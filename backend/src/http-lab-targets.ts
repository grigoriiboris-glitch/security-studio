import type { FastifyInstance } from "fastify";
import type { LessonId } from "./lessons.js";

const supported = new Set<LessonId>([
  "xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf"
]);

type TargetState = { fixed: boolean; storedComment: string };
const states = new Map<string, TargetState>();
const key = (lessonId: LessonId, runId: string) => lessonId + ":" + runId;
const escapeHtml = (value: string) => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[char]!);
const stateFor = (lessonId: LessonId, runId: string) => states.get(key(lessonId, runId));

/**
 * Controlled HTTP fixtures for the first practical lesson group. These handlers are the
 * target application: probes reach them over Fastify's HTTP router via inject(), never
 * arbitrary learner code or external hosts. State is scoped to one lab run.
 */
export function registerHttpLabTargets(app: FastifyInstance): void {
  app.post("/api/labs/http-targets/:lessonId/:runId/prepare", async (request, reply) => {
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    if (!supported.has(lessonId) || !runId || runId.length > 128) return reply.code(400).send({ error: "HTTP target is not available for this lesson." });
    states.set(key(lessonId, runId), { fixed: false, storedComment: "" });
    return { lessonId, runId, target: "controlled-http-fixture", fixed: false };
  });

  app.get("/api/labs/http-targets/:lessonId/:runId/fixture", async (request, reply) => {
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!state) return reply.code(404).send({ error: "Prepare the target first." });
    const query = request.query as { value?: string; id?: string; token?: string; path?: string; url?: string };
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
      default:
        return reply.code(404).send({ error: "Unsupported target" });
    }
  });

  app.post("/api/labs/http-targets/:lessonId/:runId/fix", async (request, reply) => {
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!supported.has(lessonId) || !state) return reply.code(404).send({ error: "Target session not found." });
    state.fixed = true;
    return { fixed: true, target: "controlled-http-fixture" };
  });

  app.post("/api/labs/http-targets/:lessonId/:runId/reset", async (request, reply) => {
    const { lessonId, runId } = request.params as { lessonId: LessonId; runId: string };
    const state = stateFor(lessonId, runId);
    if (!supported.has(lessonId) || !state) return reply.code(404).send({ error: "Target session not found." });
    state.fixed = false;
    state.storedComment = "";
    return { fixed: false, reset: true };
  });
}

export const httpTargetLessonIds = [...supported];
