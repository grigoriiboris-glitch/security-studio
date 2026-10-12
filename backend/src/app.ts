import Fastify, { type FastifyInstance } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { convertToModelMessages, streamText, type UIMessage } from "ai";
import { z } from "zod";
import { config } from "./config.js";
import { buildLessonSystem, lessonIds, type LessonId } from "./lessons.js";
import { LabManager, labCatalog, type LabManagerContract, type LabId } from "./lab-manager.js";
import { checkLessonFix } from "./security-check.js";
import { labScenarios } from "./lab-scenarios.js";
import { createLabRun, fixLabRun, getLabRun, probeLabRun, resetLabRun, retestLabRun } from "./lab-runtime.js";
import { registerHttpLabTargets } from "./http-lab-targets.js";
import { getChatMessages, getProgress, saveChatMessages, saveProgress } from "./database.js";
import { createExerciseWorkspace, type ExerciseWorkspace } from "./workspace.js";

const lessonIdSchema = z.enum(lessonIds);
const labIdSchema = z.enum(["juice-shop", "nodegoat"]);
const checkRequestSchema = z.object({ lessonId: lessonIdSchema.default("sql-injection"), code: z.string().max(12000) });
const workspaceRequestSchema = z.object({ code: z.string().max(12000) });
const progressRequestSchema = z.object({
  editorCode: z.string().max(12000),
  selectedLabId: labIdSchema.default("juice-shop"),
  checkResult: z.object({ passed: z.boolean(), message: z.string().max(1000), evidence: z.array(z.string().max(500)).max(30) }).nullable().optional()
});
const chatRequestSchema = z.object({
  id: z.string().max(256).optional(),
  messages: z.array(z.unknown()).min(1).max(80),
  lessonId: lessonIdSchema.default("sql-injection"),
  code: z.string().max(12000).optional()
});
type AppDependencies = { labManager?: LabManagerContract; demoFetch?: typeof fetch; workspace?: ExerciseWorkspace };
const httpTargetLessons = new Set<LessonId>(["xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf"]);
async function probeHttpTarget(app: FastifyInstance, lessonId: LessonId, runId: string): Promise<{ vulnerable: boolean; evidence: string[] }> {
  const base = "/api/labs/http-targets/" + lessonId + "/" + runId + "/fixture";
  const request = async (url: string, method: "GET" | "POST" = "GET", payload?: { comment?: string }) =>
    app.inject({ method, url, ...(payload === undefined ? {} : { payload }) });
  let response;
  switch (lessonId) {
    case "xss-reflected":
      response = await request(base + "?value=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E");
      return { vulnerable: response.body.includes("<img src=x onerror=alert(1)>"), evidence: ["HTTP GET reflected payload; response was checked for raw versus escaped HTML."] };
    case "xss-stored":
      await request(base, "POST", { comment: "<img src=x onerror=alert(1)>" });
      response = await request(base);
      return { vulnerable: response.body.includes("<img src=x onerror=alert(1)>"), evidence: ["HTTP POST stored a harmless marker; HTTP GET checked the rendered response."] };
    case "xss-dom":
      response = await request(base);
      return { vulnerable: response.body.includes(".innerHTML=value"), evidence: ["HTTP-served DOM fixture checked for innerHTML versus textContent sink. Browser JavaScript was not executed."] };
    case "idor":
      response = await request(base + "?id=bob-note");
      return { vulnerable: response.statusCode === 200 && response.body.includes("BOB-PRIVATE-FIXTURE"), evidence: ["HTTP GET requested Bob's synthetic private object as the unprivileged lab user."] };
    case "csrf":
      response = await request(base, "POST", {});
      return { vulnerable: response.statusCode === 200 && response.body.includes('"changed":true'), evidence: ["HTTP POST attempted a state change without a CSRF token."] };
    case "path-traversal":
      response = await request(base + "?path=..%2Fsecret.txt");
      return { vulnerable: response.statusCode === 200 && response.body.includes("LAB-ONLY-SECRET-FIXTURE"), evidence: ["HTTP GET attempted traversal outside the synthetic fixture root."] };
    case "ssrf":
      response = await request(base + "?url=http%3A%2F%2Fmetadata.lab%2Fidentity");
      return { vulnerable: response.statusCode === 200 && response.body.includes("LAB-METADATA-FIXTURE"), evidence: ["HTTP GET requested a synthetic metadata destination; no outbound network request is made."] };
    default:
      return { vulnerable: true, evidence: ["No HTTP probe is registered for this lesson."] };
  }
}


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
  const workspace = dependencies.workspace ?? createExerciseWorkspace();
  const app = Fastify({ logger: false, bodyLimit: 256 * 1024, trustProxy: false });
  app.register(helmet, { contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: "same-site" } });
  app.register(rateLimit, { max: 60, timeWindow: "1 minute" });
  registerHttpLabTargets(app);

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
  app.get("/api/progress/:lessonId", async (request, reply) => {
    const lessonId = lessonIdSchema.safeParse((request.params as { lessonId?: string }).lessonId);
    if (!lessonId.success) return reply.code(400).send({ error: "Неизвестный урок." });
    return { progress: getProgress(lessonId.data) };
  });

  app.put("/api/progress/:lessonId", async (request, reply) => {
    const lessonId = lessonIdSchema.safeParse((request.params as { lessonId?: string }).lessonId);
    const parsed = progressRequestSchema.safeParse(request.body);
    if (!lessonId.success || !parsed.success) return reply.code(400).send({ error: "Некорректный прогресс урока." });
    return { progress: saveProgress({
      lessonId: lessonId.data,
      editorCode: parsed.data.editorCode,
      selectedLabId: parsed.data.selectedLabId,
      checkResult: parsed.data.checkResult ?? null
    }) };
  });

  app.get("/api/assistant/history", async (request, reply) => {
    const query = z.object({ id: z.string().min(1).max(256) }).safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: "Укажите id диалога." });
    return { messages: getChatMessages(sessionIdFrom(query.data.id)) };
  });

  app.get("/api/lessons", async () => ({ lessonIds }));

  app.get("/api/labs/scenarios", async () => ({ scenarios: labScenarios }));

  // Fixed, deterministic synthetic targets for every lesson. User editor code is never executed.
  app.post("/api/labs/scenarios/:lessonId/reset", async (request, reply) => {
    const parsed = lessonIdSchema.safeParse((request.params as { lessonId?: string }).lessonId);
    if (!parsed.success) return reply.code(400).send({ error: "Неизвестный урок." });
    const run = createLabRun(parsed.data);
    const mode = httpTargetLessons.has(parsed.data) ? "controlled-http" : "synthetic";
    if (mode === "controlled-http") await app.inject({ method: "POST", url: "/api/labs/http-targets/" + parsed.data + "/" + run.runId + "/prepare" });
    return { run, mode, codeExecution: false };
  });

  app.get("/api/labs/scenarios/:lessonId/:runId", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    if (!lesson.success || !params.runId) return reply.code(400).send({ error: "Некорректная лаборатория." });
    const run = getLabRun(lesson.data, params.runId);
    if (!run) return reply.code(404).send({ error: "Сессия лаборатории не найдена. Создайте новую через reset." });
    return { run };
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/exploit", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    if (!lesson.success || !params.runId) return reply.code(400).send({ error: "Некорректная лаборатория." });
    const result = probeLabRun(lesson.data, params.runId);
    if (!result) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (!httpTargetLessons.has(lesson.data)) return result;
    const probe = await probeHttpTarget(app, lesson.data, params.runId);
    return { ...result, vulnerable: probe.vulnerable, passed: probe.vulnerable, message: probe.vulnerable ? "HTTP exploit probe подтвердил уязвимое поведение контролируемой мишени." : "HTTP exploit probe не воспроизвёл уязвимость; проверьте исходное состояние.", evidence: ["Контролируемая HTTP-мишень Security Studio.", ...probe.evidence, "Код из редактора не исполнялся; внешние хосты не вызываются."] };
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/fix", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    const body = z.object({ code: z.string().max(12000) }).safeParse(request.body);
    if (!lesson.success || !params.runId || !body.success) return reply.code(400).send({ error: "Передайте lessonId, runId и code длиной не более 12000 символов." });
    const result = fixLabRun(lesson.data, params.runId, body.data.code);
    if (!result) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (result.passed && httpTargetLessons.has(lesson.data)) await app.inject({ method: "POST", url: "/api/labs/http-targets/" + lesson.data + "/" + params.runId + "/fix" });
    return result;
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/retest", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    if (!lesson.success || !params.runId) return reply.code(400).send({ error: "Некорректная лаборатория." });
    const result = retestLabRun(lesson.data, params.runId);
    if (!result) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (!httpTargetLessons.has(lesson.data) || result.phase !== "passed") return result;
    const probe = await probeHttpTarget(app, lesson.data, params.runId);
    const passed = !probe.vulnerable;
    return { ...result, vulnerable: probe.vulnerable, passed, message: passed ? "HTTP retest пройден: контрольный запрос больше не воспроизводит уязвимость." : "HTTP retest провален: контрольный запрос всё ещё воспроизводит уязвимость.", evidence: ["Повторён тот же контрольный HTTP probe после применения защиты.", ...probe.evidence, "Это локальная fixture-мишень, а не проверка произвольного приложения."] };
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/reset", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    if (!lesson.success || !params.runId) return reply.code(400).send({ error: "Некорректная лаборатория." });
    const run = resetLabRun(lesson.data, params.runId);
    if (!run) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (httpTargetLessons.has(lesson.data)) await app.inject({ method: "POST", url: "/api/labs/http-targets/" + lesson.data + "/" + params.runId + "/reset" });
    return { run };
  });

  app.get("/api/workspace/:lessonId", async (request, reply) => {
    const parsedId = lessonIdSchema.safeParse((request.params as { lessonId?: string }).lessonId);
    if (!parsedId.success) return reply.code(400).send({ error: "Неизвестный урок." });
    return { code: await workspace.read(parsedId.data), file: "solution.js" };
  });

  app.put("/api/workspace/:lessonId", async (request, reply) => {
    const parsedId = lessonIdSchema.safeParse((request.params as { lessonId?: string }).lessonId);
    const parsed = workspaceRequestSchema.safeParse(request.body);
    if (!parsedId.success) return reply.code(400).send({ error: "Неизвестный урок." });
    if (!parsed.success) return reply.code(400).send({ error: "Код должен быть строкой длиной не более 12000 символов." });
    await workspace.write(parsedId.data, parsed.data.code);
    return { saved: true, file: "solution.js" };
  });

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

  app.post("/api/labs/reset", async (request, reply) => {
    const status = await labManager.status();
    if (!status.available) return reply.code(503).send({ error: status.message ?? "Docker недоступен." });
    if (!status.activeLab) return reply.code(409).send({ error: "Сначала запустите лабораторию." });
    try {
      return { activeLab: await labManager.start(status.activeLab.id), reset: true };
    } catch (error) {
      request.log.error({ error: errorMessage(error) }, "Failed to reset lab");
      return reply.code(503).send({ error: "Не удалось сбросить учебную среду.", message: errorMessage(error) });
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
    return checkLessonFix(parsed.data.lessonId, parsed.data.code);
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
    saveChatMessages(sessionIdFrom(payload.id), payload.lessonId, payload.messages);

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
    const response = result.toUIMessageStreamResponse({
      onFinish: ({ messages }) => saveChatMessages(sessionIdFrom(payload.id), payload.lessonId, messages)
    });
    reply.code(response.status);
    response.headers.forEach((value, key) => reply.header(key, value));
    if (!response.body) return reply.send();
    return reply.send(Readable.fromWeb(response.body as import("node:stream/web").ReadableStream<Uint8Array>));
  });

  return app;
}
