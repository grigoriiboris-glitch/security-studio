import Fastify, { type FastifyInstance } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { convertToModelMessages, streamText, type UIMessage } from "ai";
import { z } from "zod";
import { config } from "./config.js";
import { buildLessonSystem, type LessonId } from "./lessons.js";
import { LabManager, labCatalog, type LabManagerContract, type LabId } from "./lab-manager.js";
import { checkSqlInjectionFix } from "./security-check.js";

const lessonIdSchema = z.enum(["sql-injection"]);
const labIdSchema = z.enum(["juice-shop", "nodegoat"]);
const checkRequestSchema = z.object({ code: z.string().max(12000) });
const chatRequestSchema = z.object({
  id: z.string().max(256).optional(),
  messages: z.array(z.unknown()).min(1).max(80),
  lessonId: lessonIdSchema.default("sql-injection"),
  code: z.string().max(12000).optional()
});
type AppDependencies = { labManager?: LabManagerContract; demoFetch?: typeof fetch };

function sessionIdFrom(value: string | undefined): string {
  if (!value) return randomUUID();
  return createHash("sha256").update(value).digest("hex").slice(0, 32);
}
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 400) : "Неизвестная ошибка.";
}

export function buildApp(dependencies: AppDependencies = {}): FastifyInstance {
  const labManager = dependencies.labManager ?? new LabManager();
  const demoFetch = dependencies.demoFetch ?? fetch;
  const app = Fastify({ logger: false, bodyLimit: 256 * 1024, trustProxy: false });
  app.register(helmet, { contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "same-site" } });
  app.register(rateLimit, { max: 60, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return;
    const origin = request.headers.origin;
    if (origin && !config.allowedOrigins.has(origin)) return reply.code(403).send({ error: "Origin не разрешён." });
  });

  app.get("/api/healthz", async () => ({
    status: "ok",
    aiConfigured: Boolean(config.openCodeApiKey),
    model: config.model
  }));
  app.get("/api/labs", async () => ({ labs: labCatalog }));
  app.get("/api/labs/status", async (_request, reply) => {
    const status = await labManager.status();
    if (!status.available) return reply.code(503).send({
      activeLab: null, available: false, message: status.message ?? "Docker недоступен."
    });
    return status;
  });

  app.post("/api/labs/:id/start", async (request, reply) => {
    const parsedId = labIdSchema.safeParse((request.params as { id?: string }).id);
    if (!parsedId.success) return reply.code(400).send({ error: "Неизвестная лаборатория." });
    try { return { activeLab: await labManager.start(parsedId.data as LabId) }; }
    catch (error) {
      request.log.error({ error: errorMessage(error) }, "Failed to start lab");
      return reply.code(503).send({ error: "Не удалось запустить учебную среду.", message: errorMessage(error) });
    }
  });

  app.post("/api/labs/stop", async (request, reply) => {
    try { await labManager.stop(); return { stopped: true }; }
    catch (error) {
      request.log.error({ error: errorMessage(error) }, "Failed to stop lab");
      return reply.code(503).send({ error: "Не удалось остановить учебную среду.", message: errorMessage(error) });
    }
  });

  app.post("/api/labs/demo-sqli", {
    config: { rateLimit: { max: 4, timeWindow: "1 minute" } }
  }, async (_request, reply) => {
    const status = await labManager.status();
    if (!status.available) {
      return reply.code(503).send({ error: status.message ?? "Docker недоступен." });
    }
    if (status.activeLab?.id !== "juice-shop") {
      return reply.code(409).send({ error: "Для демонстрации запустите OWASP Juice Shop в Security Studio." });
    }

    try {
      const upstream = await demoFetch("http://127.0.0.1:3000/rest/user/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: "' OR 1=1--", password: "security-studio-invalid-password" }),
        redirect: "error",
        signal: AbortSignal.timeout(5000)
      });
      const result = await upstream.json().catch(() => null) as { authentication?: { token?: unknown } } | null;
      const tokenIssued = typeof result?.authentication?.token === "string";
      const passed = upstream.ok && tokenIssued;
      return {
        passed,
        message: passed
          ? "SQL-инъекция сработала в локальном Juice Shop: учебное приложение выдало сессию без корректного пароля."
          : "SQL-инъекция не подтвердилась: учебное приложение не выдало сессию на тестовый запрос.",
        evidence: [
          "Запрос отправлен только на фиксированный адрес локального Juice Shop.",
          "HTTP статус: " + upstream.status + ".",
          tokenIssued ? "В ответе был токен сессии; он намеренно не возвращается в браузер." : "Токен сессии не обнаружен."
        ]
      };
    } catch {
      return reply.code(503).send({
        error: "Juice Shop недоступен на 127.0.0.1:3000. Проверьте статус лаборатории и попробуйте ещё раз."
      });
    }
  });

  app.post("/api/labs/check", async (request, reply) => {
    const parsed = checkRequestSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Передайте строку code длиной не более 12000 символов." });
    return checkSqlInjectionFix(parsed.data.code);
  });

  app.post("/api/assistant/chat", {
    config: { rateLimit: { max: 12, timeWindow: "1 minute" } }
  }, async (request, reply) => {
    const parsed = chatRequestSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({
      error: "Некорректный формат диалога.",
      details: parsed.error.issues.map((issue) => issue.message)
    });
    if (!config.openCodeApiKey) return reply.code(503).send({
      error: "AI не настроен. Добавьте OPENCODE_GO_API_KEY в .env и перезапустите API."
    });

    const payload = parsed.data;
    const provider = createOpenAICompatible({
      name: "opencode-go",
      baseURL: config.openCodeBaseUrl,
      apiKey: config.openCodeApiKey,
      headers: {
        "User-Agent": "security-studio/0.1 (local security education)",
        "x-opencode-session": sessionIdFrom(payload.id)
      }
    });

    const result = streamText({
      model: provider.chatModel(config.model),
      messages: await convertToModelMessages(payload.messages as UIMessage[]),
      system: buildLessonSystem(payload.lessonId as LessonId, payload.code),
      temperature: 0.2,
      maxOutputTokens: 1400
    });
    const response = result.toUIMessageStreamResponse();
    reply.code(response.status);
    response.headers.forEach((value, key) => reply.header(key, value));
    if (!response.body) return reply.send();
    return reply.send(Readable.fromWeb(response.body as import("node:stream/web").ReadableStream<Uint8Array>));
  });

  return app;
}
