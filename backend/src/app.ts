import Fastify, { type FastifyInstance } from "fastify";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { convertToModelMessages, streamText, type UIMessage } from "ai";
import { z } from "zod";
import { config } from "./config.js";
import { buildLessonSystem, lessonIds, type LessonId } from "./lessons.js";
import { LabManager, labCatalog, type LabManagerContract, type LabId } from "./lab-manager.js";
import { checkLessonFix } from "./security-check.js";
import { labScenarios } from "./lab-scenarios.js";
import { createLabRun, fixLabRun, getLabRun, probeLabRun, recordLabProbeResult, recordLabRetestResult, resetLabRun, retestLabRun } from "./lab-runtime.js";
import { internalLabControlHeaders, registerHttpLabTargets } from "./http-lab-targets.js";
import { registerAISecurityLabRoutes } from "./ai-security-lab-runtime.js";
import { registerAILiveEvaluationRoutes } from "./ai-live-evaluation.js";
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
const httpTargetLessons = new Set<LessonId>(["xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf", "broken-access-control", "broken-authentication", "session-fixation", "password-reset", "file-upload", "command-injection", "xxe", "ssti", "open-redirect", "cors", "clickjacking", "security-headers", "secrets-exposure", "sensitive-data", "jwt-validation", "mass-assignment", "rate-limiting", "business-logic", "prototype-pollution", "nosql-injection", "ldap-injection", "insecure-deserialization"]);
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

    case "broken-access-control":
      response = await request(base + "?action=admin");
      return { vulnerable: response.statusCode === 200 && response.body.includes("LAB-ADMIN-FIXTURE"), evidence: ["HTTP request called the synthetic admin action as a basic user; no real privileged system is accessed."] };
    case "broken-authentication":
      response = await request(base + "?password=wrong-lab-password");
      return { vulnerable: response.statusCode === 200 && response.body.includes('"authenticated":true'), evidence: ["HTTP login fixture submitted an invalid synthetic password; no real account is used."] };
    case "session-fixation":
      response = await request(base + "?sessionId=attacker-known-session");
      return { vulnerable: response.body.includes('"before":"attacker-known-session","after":"attacker-known-session"'), evidence: ["HTTP response compared the pre-authentication fixture session ID with the post-login ID."] };
    case "password-reset":
      response = await request(base + "?token=known-reset-token");
      return { vulnerable: response.statusCode === 200 && response.body.includes('"resetAllowed":true'), evidence: ["HTTP reset endpoint tested a fixed synthetic token; no email or account reset is triggered."] };
    case "file-upload":
      response = await request(base + "?filename=..%2Fpublic%2Flab.svg");
      return { vulnerable: response.statusCode === 200 && response.body.includes('"accepted":true') && response.body.includes("LAB-UPLOAD-FIXTURE"), evidence: ["HTTP upload-policy fixture checked traversal-like filename and active-content extension; no file is written."] };
    case "command-injection":
      response = await request(base + "?input=hello%3Bmarker");
      return { vulnerable: response.body.includes('"simulatedSecondCommand":true'), evidence: ["HTTP fixture recognized a shell metacharacter as a simulated second command; no OS command was executed."] };
    case "xxe":
      response = await request(base + "?entity=lab-file");
      return { vulnerable: response.body.includes('"resolvedExternalEntity":true'), evidence: ["HTTP XML-policy fixture reports only a synthetic entity marker; no XML parser or filesystem is invoked."] };
    case "ssti":
      response = await request(base + "?template=%7B%7B7%2A7%7D%7D");
      return { vulnerable: response.body.includes('"evaluated":true') && response.body.includes('"rendered":"49"'), evidence: ["HTTP template fixture simulates a harmless arithmetic expression; no template engine evaluates user code."] };
    case "open-redirect":
      response = await request(base + "?next=https%3A%2F%2Fattacker.lab.example");
      return { vulnerable: response.statusCode === 302 && response.headers.location === "https://attacker.lab.example", evidence: ["HTTP redirect response checked a synthetic external destination without following it."] };
    case "cors":
      response = await request(base + "?origin=https%3A%2F%2Fattacker.lab.example");
      return { vulnerable: response.headers["access-control-allow-origin"] === "https://attacker.lab.example" && response.headers["access-control-allow-credentials"] === "true", evidence: ["HTTP CORS fixture sent an untrusted synthetic Origin; no browser credentials are used."] };
    case "clickjacking":
      response = await request(base);
      return { vulnerable: response.body.includes('"framed":true'), evidence: ["HTTP fixture reports whether its framing policy permits embedding; no hostile page is loaded."] };
    case "security-headers":
      response = await request(base);
      return { vulnerable: response.body.includes('"headersConfigured":false'), evidence: ["HTTP fixture checks the lesson-specific baseline policy state; framework defaults are not counted as the lesson fix."] };
    case "secrets-exposure":
      response = await request(base + "?field=apiKey");
      return { vulnerable: response.body.includes("LAB-SYNTHETIC-SECRET-DO-NOT-USE"), evidence: ["HTTP response queried a synthetic secret field; no real secret is present."] };
    case "sensitive-data":
      response = await request(base);
      return { vulnerable: response.body.includes("passwordHash") || response.body.includes("mfaRecovery"), evidence: ["HTTP user response checked for synthetic private fields that should not be serialized."] };
    case "jwt-validation":
      response = await request(base + "?token=invalid-lab-token");
      return { vulnerable: response.statusCode === 200 && response.body.includes('"accepted":true'), evidence: ["HTTP auth fixture submitted a fixed invalid token; no JWT grants access to any real resource."] };
    case "mass-assignment":
      response = await request(base + "?role=admin");
      return { vulnerable: response.body.includes('"role":"admin"'), evidence: ["HTTP fixture attempted to set a protected role field through query input."] };
    case "rate-limiting": {
      const attempts = await Promise.all(Array.from({ length: 5 }, () => request(base)));
      return { vulnerable: attempts.every((item) => item.statusCode === 200), evidence: ["Five HTTP requests were sent to the isolated login-rate fixture; no credentials are attempted."] };
    }
    case "business-logic":
      response = await request(base + "?total=1");
      return { vulnerable: response.json().acceptedTotal === 1, evidence: ["HTTP order fixture submitted a manipulated synthetic total instead of the server catalog total."] };
    case "prototype-pollution":
      response = await request(base + "?key=__proto__");
      return { vulnerable: response.body.includes('"polluted":true'), evidence: ["HTTP fixture checked a dangerous object key without modifying global JavaScript prototypes."] };
    case "nosql-injection":
      response = await request(base + "?username=%5Bobject%5D");
      return { vulnerable: response.body.includes('"bypassed":true'), evidence: ["HTTP fixture simulated an object/operator-shaped username; no database query is executed."] };
    case "ldap-injection":
      response = await request(base + "?username=%2A%29%28uid%3D%2A%29");
      return { vulnerable: response.body.includes('"broadenedSearch":true'), evidence: ["HTTP fixture modeled LDAP filter broadening using synthetic match counts; no LDAP server is contacted."] };
    case "insecure-deserialization":
      response = await request(base + "?type=admin");
      return { vulnerable: response.statusCode === 200 && response.body.includes("LAB-DESERIALIZATION-FIXTURE"), evidence: ["HTTP fixture simulated acceptance of an unexpected type; no object deserialization occurs."] };
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
  app.register(helmet, { contentSecurityPolicy: process.env.NODE_ENV === "production" ? {
      directives: {
        workerSrc: ["'self'", "blob:"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: null
      }
    } : false, crossOriginResourcePolicy: { policy: "same-site" } });
  app.register(rateLimit, { max: 60, timeWindow: "1 minute" });
  registerHttpLabTargets(app);
  registerAISecurityLabRoutes(app);
  registerAILiveEvaluationRoutes(app);

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
    if (mode === "controlled-http") await app.inject({ method: "POST", url: "/api/labs/http-targets/" + parsed.data + "/" + run.runId + "/prepare", headers: internalLabControlHeaders() });
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
    const existingRun = getLabRun(lesson.data, params.runId);
    if (!existingRun) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (existingRun.phase !== "ready") {
      return reply.code(409).send({ error: "Сначала сбросьте лабораторию: exploit probe разрешён только в исходном состоянии." });
    }
    const result = probeLabRun(lesson.data, params.runId);
    if (!result) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (!httpTargetLessons.has(lesson.data)) return result;
    const probe = await probeHttpTarget(app, lesson.data, params.runId);
    const run = recordLabProbeResult(lesson.data, params.runId, probe.vulnerable);
    if (!run) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    return { ...result, phase: run.phase, vulnerable: probe.vulnerable, passed: probe.vulnerable, message: probe.vulnerable ? "HTTP exploit probe подтвердил уязвимое поведение контролируемой мишени." : "HTTP exploit probe не воспроизвёл уязвимость; мишень осталась в исходном состоянии.", evidence: ["Контролируемая HTTP-мишень Security Studio.", ...probe.evidence, "Код из редактора не исполнялся; внешние хосты не вызываются."] };
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/fix", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    const body = z.object({ code: z.string().max(12000) }).safeParse(request.body);
    if (!lesson.success || !params.runId || !body.success) return reply.code(400).send({ error: "Передайте lessonId, runId и code длиной не более 12000 символов." });
    const result = fixLabRun(lesson.data, params.runId, body.data.code);
    if (!result) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (result.passed && httpTargetLessons.has(lesson.data)) await app.inject({ method: "POST", url: "/api/labs/http-targets/" + lesson.data + "/" + params.runId + "/fix", headers: internalLabControlHeaders() });
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
    const run = recordLabRetestResult(lesson.data, params.runId, passed);
    if (!run) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    return { ...result, phase: run.phase, vulnerable: probe.vulnerable, passed, message: passed ? "HTTP retest пройден: контрольный запрос больше не воспроизводит уязвимость." : "HTTP retest провален: контрольный запрос всё ещё воспроизводит уязвимость.", evidence: ["Повторён тот же контрольный HTTP probe после применения защиты.", ...probe.evidence, "Это локальная fixture-мишень, а не проверка произвольного приложения."] };
  });

  app.post("/api/labs/scenarios/:lessonId/:runId/reset", async (request, reply) => {
    const params = request.params as { lessonId?: string; runId?: string };
    const lesson = lessonIdSchema.safeParse(params.lessonId);
    if (!lesson.success || !params.runId) return reply.code(400).send({ error: "Некорректная лаборатория." });
    const run = resetLabRun(lesson.data, params.runId);
    if (!run) return reply.code(404).send({ error: "Сессия лаборатории не найдена." });
    if (httpTargetLessons.has(lesson.data)) await app.inject({ method: "POST", url: "/api/labs/http-targets/" + lesson.data + "/" + params.runId + "/reset", headers: internalLabControlHeaders() });
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

  // Serve the built SPA when running the production server without Vite.
  const frontendDist = resolve(fileURLToPath(new URL("../../frontend/dist/", import.meta.url)));
  const contentTypes: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".map": "application/json; charset=utf-8"
  };
  app.get("/*", async (request, reply) => {
    const pathname = new URL(request.url, "http://localhost").pathname;
    if (pathname === "/api" || pathname.startsWith("/api/")) {
      return reply.code(404).send({ error: "Not found." });
    }
    let relativePath: string;
    try {
      relativePath = decodeURIComponent(pathname.slice(1)) || "index.html";
    } catch {
      return reply.code(400).send({ error: "Invalid path." });
    }
    const candidate = resolve(frontendDist, relativePath);
    if (candidate !== frontendDist && !candidate.startsWith(frontendDist + sep)) {
      return reply.code(404).send({ error: "Not found." });
    }
    let file: Buffer;
    let filePath = candidate;
    try {
      file = await readFile(filePath);
    } catch {
      if (extname(relativePath)) return reply.code(404).send({ error: "Not found." });
      filePath = resolve(frontendDist, "index.html");
      try {
        file = await readFile(filePath);
      } catch {
        return reply.code(404).send({ error: "Production frontend build not found. Run npm run build first." });
      }
    }
    reply.type(contentTypes[extname(filePath).toLowerCase()] ?? "application/octet-stream");
    reply.header("Cache-Control", extname(filePath) === ".html" ? "no-cache" : "public, max-age=31536000, immutable");
    return reply.send(file);
  });

  return app;
}
