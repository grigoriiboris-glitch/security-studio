import type { FastifyInstance } from "fastify";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { LessonId } from "./lessons.js";

const supported = new Set<LessonId>([
  "xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf", "broken-access-control", "broken-authentication", "session-fixation", "password-reset", "file-upload", "command-injection", "xxe", "ssti", "open-redirect", "cors", "clickjacking", "security-headers", "secrets-exposure", "sensitive-data", "jwt-validation", "mass-assignment", "rate-limiting", "business-logic", "prototype-pollution", "nosql-injection", "ldap-injection", "insecure-deserialization"
]);

type TargetState = { fixed: boolean; storedComment: string; attempts: number; createdAt: number };
const states = new Map<string, TargetState>();
const MAX_HTTP_TARGET_STATES = 500;
const HTTP_TARGET_TTL_MS = 2 * 60 * 60 * 1000;
const controlToken = randomBytes(32).toString("hex");
const controlHeader = "x-security-studio-internal";
export function internalLabControlHeaders(): Record<string, string> { return { [controlHeader]: controlToken }; }
function isInternalControlRequest(request: { headers: Record<string, string | string[] | undefined> }): boolean {
  const value = request.headers[controlHeader];
  const supplied = Array.isArray(value) ? value[0] : value;
  if (typeof supplied !== "string" || supplied.length !== controlToken.length) return false;
  return timingSafeEqual(Buffer.from(supplied), Buffer.from(controlToken));
}
const key = (lessonId: LessonId, runId: string) => lessonId + ":" + runId;
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[char]!);
function pruneTargetStates(now = Date.now()): void {
  for (const [stateKey, state] of states) {
    if (now - state.createdAt > HTTP_TARGET_TTL_MS) states.delete(stateKey);
  }
  while (states.size >= MAX_HTTP_TARGET_STATES) {
    const oldestKey = states.keys().next().value as string | undefined;
    if (oldestKey === undefined) break;
    states.delete(oldestKey);
  }
}
function stateFor(lessonId: LessonId, runId: string): TargetState | undefined {
  const stateKey = key(lessonId, runId);
  const state = states.get(stateKey);
  if (state && Date.now() - state.createdAt > HTTP_TARGET_TTL_MS) {
    states.delete(stateKey);
    return undefined;
  }
  return state;
}

/**
 * Controlled HTTP fixtures for the first practical lesson group. These handlers are the
 * target application: probes reach them over Fastify's HTTP router via inject(), never
 * arbitrary learner code or external hosts. State is scoped to one lab run.
 */
export function registerHttpLabTargets(app: FastifyInstance): void {
  app.post("/api/labs/http-targets/:lessonId/:runId/prepare", async (request, reply) => {
    if (!isInternalControlRequest(request)) return reply.code(404).send({ error: "Target session not found." });
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    if (!supported.has(lessonId) || !runId || runId.length > 128) return reply.code(400).send({ error: "HTTP target is not available for this lesson." });
    pruneTargetStates();
    states.set(key(lessonId, runId), { fixed: false, storedComment: "", attempts: 0, createdAt: Date.now() });
    return { lessonId, runId, target: "controlled-http-fixture", fixed: false };
  });

  app.route({ method: ["GET", "POST"], url: "/api/labs/http-targets/:lessonId/:runId/fixture", handler: async (request, reply) => {
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!state) return reply.code(404).send({ error: "Prepare the target first." });
    const query = request.query as { value?: string; id?: string; token?: string; path?: string; url?: string; sessionId?: string; filename?: string; input?: string; entity?: string; template?: string; next?: string; origin?: string; field?: string; role?: string; total?: string; key?: string; username?: string; type?: string; action?: string; password?: string };
    const value = String(query.value ?? "<img src=x onerror=alert(1)>");
    switch (lessonId) {
      case "xss-reflected":
        reply.type("text/html; charset=utf-8");
        return "<!doctype html><title>Reflected XSS fixture</title><main>" + (state.fixed ? escapeHtml(value) : value) + "</main>";
      case "xss-stored":
        if (request.method === "POST") {
          const body = request.body as { comment?: string } | undefined;
          state.storedComment = String(body?.comment ?? value);
          return { saved: true };
        }
        reply.type("text/html; charset=utf-8");
        return "<!doctype html><title>Stored XSS fixture</title><main>" + (state.fixed ? escapeHtml(state.storedComment) : state.storedComment) + "</main>";
      case "xss-dom":
        reply.type("text/html; charset=utf-8");
        return "<!doctype html><title>DOM XSS fixture</title><div id=\"out\"></div><script>const value=location.hash.slice(1);document.querySelector('#out')." +
          (state.fixed ? "textContent" : "innerHTML") + "=value;</script>";
      case "idor":
        if (query.id !== "alice-note" && query.id !== "bob-note") return reply.code(404).send({ error: "Not found" });
        if (query.id === "bob-note" && state.fixed) return reply.code(403).send({ error: "Forbidden" });
        return { id: query.id, owner: query.id.startsWith("bob") ? "bob" : "alice", secret: query.id.startsWith("bob") ? "BOB-PRIVATE-FIXTURE" : "ALICE-PUBLIC-FIXTURE" };
      case "csrf":
        if (request.method !== "POST") return { balance: 100 };
        if (state.fixed && query.token !== "lab-csrf-token") return reply.code(403).send({ error: "CSRF token required" });
        return { changed: true, balance: 0 };
      case "path-traversal":
        if (query.path === "../secret.txt" && !state.fixed) return { file: "LAB-ONLY-SECRET-FIXTURE" };
        if (query.path !== "readme.txt") return reply.code(403).send({ error: "Path outside fixture root" });
        return { file: "This is a harmless lab fixture." };
      case "ssrf":
        // No outbound request is made. The "metadata" destination is a fixed local fixture.
        if (query.url === "http://metadata.lab/identity" && !state.fixed) return { status: 200, body: "LAB-METADATA-FIXTURE" };
        if (query.url === "https://docs.lab.example/status") return { status: 200, body: "LAB-PUBLIC-FIXTURE" };
        return reply.code(403).send({ error: "Destination blocked by lab allowlist" });

      case "broken-access-control":
        return query.action === "admin" && !state.fixed ? { status: 200, adminPanel: "LAB-ADMIN-FIXTURE" } : query.action === "admin" ? reply.code(403).send({ error: "Role required" }) : { status: 200, profile: "LAB-USER" };
      case "broken-authentication":
        if (query.password === "correct-lab-password") return { status: 200, authenticated: true };
        return state.fixed ? reply.code(401).send({ error: "Invalid credentials" }) : { status: 200, authenticated: true, note: "LAB-ONLY weak verifier accepts invalid password" };
      case "session-fixation":
        return { before: String(query.sessionId ?? "known-session"), after: state.fixed ? "rotated-lab-session" : String(query.sessionId ?? "known-session"), rotated: state.fixed };
      case "password-reset":
        if (query.token === "known-reset-token" && !state.fixed) return { status: 200, resetAllowed: true, token: "LAB-RESET-FIXTURE" };
        return query.token === "random-lab-token" ? { status: 200, resetAllowed: true } : reply.code(403).send({ resetAllowed: false });
      case "file-upload":
        if (String(query.filename ?? "").includes("..") || String(query.filename ?? "").endsWith(".svg")) {
          return state.fixed ? reply.code(400).send({ error: "Upload rejected by fixture policy" }) : { status: 200, accepted: true, publicPath: "/public/" + String(query.filename), marker: "LAB-UPLOAD-FIXTURE" };
        }
        return { status: 200, accepted: true, storedAs: "random-lab-file.bin" };
      case "command-injection":
        return !state.fixed && String(query.input ?? "").includes(";")
          ? { status: 200, simulatedSecondCommand: true, marker: "LAB-COMMAND-FIXTURE", executed: false }
          : { status: 200, simulatedSecondCommand: false, executed: false };
      case "xxe":
        return query.entity === "lab-file" && !state.fixed
          ? { status: 200, resolvedExternalEntity: true, marker: "LAB-XXE-FIXTURE" }
          : { status: 200, resolvedExternalEntity: false, parserPolicy: "DTD_DISABLED" };
      case "ssti":
        return query.template === "{{7*7}}" && !state.fixed
          ? { status: 200, rendered: "49", evaluated: true }
          : { status: 200, rendered: String(query.template ?? "profile"), evaluated: false };
      case "open-redirect":
        if (String(query.next ?? "").startsWith("https://") && !state.fixed) return reply.header("location", String(query.next)).code(302).send();
        if (String(query.next ?? "").startsWith("/")) return reply.header("location", String(query.next)).code(302).send();
        return reply.code(400).send({ error: "Redirect destination blocked" });
      case "cors":
        if (query.origin === "https://attacker.lab.example" && !state.fixed) reply.header("access-control-allow-origin", String(query.origin)).header("access-control-allow-credentials", "true");
        else if (query.origin === "https://app.lab.example") reply.header("access-control-allow-origin", String(query.origin));
        return { ok: true, corsAllowed: reply.getHeader("access-control-allow-origin") === query.origin };
      case "clickjacking":
        if (state.fixed) reply.header("x-frame-options", "DENY").header("content-security-policy", "frame-ancestors 'none'");
        return { framed: !state.fixed, policy: state.fixed ? "DENY" : "NONE" };
      case "security-headers":
        if (state.fixed) reply.header("content-security-policy", "default-src 'self'").header("x-content-type-options", "nosniff").header("referrer-policy", "no-referrer");
        return { headersConfigured: state.fixed };
      case "secrets-exposure":
        return query.field === "apiKey" && !state.fixed
          ? { apiKey: "LAB-SYNTHETIC-SECRET-DO-NOT-USE" }
          : { configAvailable: true, secretExposed: false };
      case "sensitive-data":
        return state.fixed ? { id: "user-1", name: "Lab User" } : { id: "user-1", name: "Lab User", email: "user@lab.example", passwordHash: "LAB-HASH-FIXTURE", mfaRecovery: "LAB-RECOVERY-FIXTURE" };
      case "jwt-validation":
        return query.token === "invalid-lab-token" && !state.fixed
          ? { status: 200, accepted: true, subject: "lab-admin" }
          : reply.code(401).send({ accepted: false, error: "JWT signature or claims invalid" });
      case "mass-assignment":
        return { status: 200, role: query.role === "admin" && !state.fixed ? "admin" : "user", writableFields: state.fixed ? ["displayName"] : ["displayName", "role"] };
      case "rate-limiting":
        state.attempts += 1;
        if (state.fixed && state.attempts > 3) return reply.code(429).send({ throttled: true, attempts: state.attempts });
        return { throttled: false, attempts: state.attempts };
      case "business-logic":
        return { status: 200, acceptedTotal: state.fixed ? 100 : Number(query.total ?? 1), expectedServerTotal: 100 };
      case "prototype-pollution":
        return { status: 200, polluted: query.key === "__proto__" && !state.fixed, marker: query.key === "__proto__" && !state.fixed ? "LAB-POLLUTION-FIXTURE" : null };
      case "nosql-injection":
        return { status: 200, bypassed: query.username === "[object]" && !state.fixed, matches: query.username === "[object]" && !state.fixed ? 3 : 1 };
      case "ldap-injection":
        return { status: 200, broadenedSearch: String(query.username ?? "").includes("*") && !state.fixed, matches: String(query.username ?? "").includes("*") && !state.fixed ? 20 : 1 };
      case "insecure-deserialization":
        return query.type === "admin" && !state.fixed
          ? { status: 200, acceptedType: "admin", marker: "LAB-DESERIALIZATION-FIXTURE" }
          : reply.code(400).send({ error: "Input rejected by schema" });
      default:
        return reply.code(404).send({ error: "Unsupported target" });
    }
  } });

  app.post("/api/labs/http-targets/:lessonId/:runId/fix", async (request, reply) => {
    if (!isInternalControlRequest(request)) return reply.code(404).send({ error: "Target session not found." });
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!supported.has(lessonId) || !state) return reply.code(404).send({ error: "Target session not found." });
    state.fixed = true;
    return { fixed: true, target: "controlled-http-fixture" };
  });

  app.post("/api/labs/http-targets/:lessonId/:runId/reset", async (request, reply) => {
    if (!isInternalControlRequest(request)) return reply.code(404).send({ error: "Target session not found." });
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!supported.has(lessonId) || !state) return reply.code(404).send({ error: "Target session not found." });
    state.fixed = false;
    state.storedComment = "";
    state.attempts = 0;
    return { fixed: false, reset: true };
  });
}

export const httpTargetLessonIds = [...supported];
