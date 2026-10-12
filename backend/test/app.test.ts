import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { saveChatMessages } from "../src/database.js";
import { buildApp } from "../src/app.js";
import type { LabManagerContract, LabId } from "../src/lab-manager.js";
import { createExerciseWorkspace, type ExerciseWorkspace } from "../src/workspace.js";

function fakeLabs(): LabManagerContract {
  let active: LabId | null = null;
  return {
    async status() {
      return {
        activeLab: active ? {
          id: active,
          name: active === "nodegoat" ? "OWASP NodeGoat" : "OWASP Juice Shop",
          url: active === "nodegoat" ? "http://127.0.0.1:4000" : "http://127.0.0.1:3000",
          status: "running" as const
        } : null,
        available: true
      };
    },
    async start(id) {
      active = id;
      return {
        id,
        name: id === "nodegoat" ? "OWASP NodeGoat" : "OWASP Juice Shop",
        url: id === "nodegoat" ? "http://127.0.0.1:4000" : "http://127.0.0.1:3000",
        status: "running"
      };
    },
    async stop() { active = null; }
  };
}

describe("Security Studio API", () => {
  const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

  async function makeApp(demoFetch?: typeof fetch, workspace?: ExerciseWorkspace) {
    const app = buildApp({ labManager: fakeLabs(), demoFetch, workspace });
    await app.ready();
    apps.push(app);
    return app;
  }

  it("reports health without exposing an API key", async () => {
    const response = await (await makeApp()).inject({ method: "GET", url: "/api/healthz" });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toHaveProperty("status", "ok");
    expect(JSON.stringify(response.json())).not.toMatch(/sk-[A-Za-z0-9]/);
  });
  it("lists allowlisted labs", async () => {
    const response = await (await makeApp()).inject({ method: "GET", url: "/api/labs" });
    expect(response.statusCode).toBe(200);
    expect(response.json().labs.map((lab: { id: string }) => lab.id)).toEqual(["juice-shop", "nodegoat"]);
  });
  it("starts a lab and reports status", async () => {
    const app = await makeApp();
    const start = await app.inject({ method: "POST", url: "/api/labs/nodegoat/start" });
    expect(start.statusCode).toBe(200);
    expect(start.json().activeLab.url).toBe("http://127.0.0.1:4000");
    expect((await app.inject({ method: "GET", url: "/api/labs/status" })).json().activeLab.id).toBe("nodegoat");
  });
  it("rejects arbitrary lab ids", async () => {
    const response = await (await makeApp()).inject({ method: "POST", url: "/api/labs/anything/start" });
    expect(response.statusCode).toBe(400);
  });
  it("stops the active lab", async () => {
    const app = await makeApp();
    await app.inject({ method: "POST", url: "/api/labs/juice-shop/start" });
    expect((await app.inject({ method: "POST", url: "/api/labs/stop" })).statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: "/api/labs/status" })).json().activeLab).toBeNull();
  });
  it("returns independent code-check results", async () => {
    const app = await makeApp();
    const safe = await app.inject({
      method: "POST", url: "/api/labs/check",
      payload: { code: 'db.query("SELECT * FROM users WHERE name = ?", [username]);' }
    });
    const unsafe = await app.inject({
      method: "POST", url: "/api/labs/check",
      payload: { code: 'db.query("SELECT * FROM users WHERE name = " + username);' }
    });
    expect(safe.json().passed).toBe(true);
    expect(unsafe.json().passed).toBe(false);
  });
  it("rejects a non-local Origin on mutating routes", async () => {
    const response = await (await makeApp()).inject({
      method: "POST", url: "/api/labs/stop", headers: { origin: "https://attacker.example" }
    });
    expect(response.statusCode).toBe(403);
  });
  it("only runs SQLi demo against active Juice Shop and never returns the session token", async () => {
    let requestedUrl = "";
    let requestBody = "";
    const demoFetch: typeof fetch = async (input, init) => {
      requestedUrl = String(input);
      requestBody = String(init?.body);
      return new Response(JSON.stringify({ authentication: { token: "token-that-must-not-leak" } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    };
    const app = await makeApp(demoFetch);
    expect((await app.inject({ method: "POST", url: "/api/labs/demo-sqli" })).statusCode).toBe(409);
    await app.inject({ method: "POST", url: "/api/labs/juice-shop/start" });
    const response = await app.inject({ method: "POST", url: "/api/labs/demo-sqli" });
    expect(response.statusCode).toBe(200);
    expect(response.json().passed).toBe(true);
    expect(requestedUrl).toBe("http://127.0.0.1:3000/rest/user/login");
    expect(JSON.parse(requestBody)).toEqual({
      email: "' OR 1=1--",
      password: "security-studio-invalid-password"
    });
    expect(response.body).not.toContain("token-that-must-not-leak");
  });

  it("persists and restores local lesson progress through SQLite", async () => {
    const app = await makeApp();
    const payload = {
      editorCode: 'db.query("SELECT * FROM users WHERE name = ?", [username]);',
      selectedLabId: "nodegoat",
      checkResult: { passed: true, message: "Проверка пройдена", evidence: ["Параметризованный запрос"] }
    };
    const saved = await app.inject({ method: "PUT", url: "/api/progress/sql-injection", payload });
    expect(saved.statusCode).toBe(200);
    expect(saved.json().progress.editorCode).toBe(payload.editorCode);
    expect(saved.json().progress.selectedLabId).toBe("nodegoat");
    const loaded = await app.inject({ method: "GET", url: "/api/progress/sql-injection" });
    expect(loaded.statusCode).toBe(200);
    expect(loaded.json().progress.checkResult).toEqual(payload.checkResult);
    expect((await app.inject({ method: "PUT", url: "/api/progress/unknown", payload })).statusCode).toBe(400);
  });

  it("restores persisted chat history for the same conversation id", async () => {
    const app = await makeApp();
    const conversationId = "history-test-" + crypto.randomUUID();
    const sessionId = createHash("sha256").update(conversationId).digest("hex").slice(0, 32);
    const messages = [
      { id: "user-1", role: "user", parts: [{ type: "text", text: "Что такое SQL-инъекция?" }] },
      { id: "assistant-1", role: "assistant", parts: [{ type: "text", text: "Это небезопасная обработка SQL-ввода." }] }
    ];
    saveChatMessages(sessionId, "sql-injection", messages);
    const response = await app.inject({
      method: "GET",
      url: "/api/assistant/history?id=" + encodeURIComponent(conversationId)
    });
    expect(response.statusCode).toBe(200);
    expect(response.json().messages).toEqual(messages);
    expect((await app.inject({ method: "GET", url: "/api/assistant/history" })).statusCode).toBe(400);
  });

  it("saves and restores code in the fixed exercise workspace", async () => {
    const root = await mkdtemp(join(tmpdir(), "security-studio-workspace-"));
    try {
      const app = await makeApp(undefined, createExerciseWorkspace(root));
      const initial = await app.inject({ method: "GET", url: "/api/workspace/sql-injection" });
      expect(initial.statusCode).toBe(200);
      expect(initial.json()).toMatchObject({ code: null, file: "solution.js" });

      const code = 'db.query("SELECT * FROM users WHERE name = ?", [username]);';
      const saved = await app.inject({
        method: "PUT", url: "/api/workspace/sql-injection", payload: { code }
      });
      expect(saved.statusCode).toBe(200);
      expect(saved.json()).toEqual({ saved: true, file: "solution.js" });

      const loaded = await app.inject({ method: "GET", url: "/api/workspace/sql-injection" });
      expect(loaded.json().code).toBe(code);
      expect((await app.inject({
        method: "PUT", url: "/api/workspace/sql-injection", payload: { code: "x".repeat(12001) }
      })).statusCode).toBe(400);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("publishes the 30 lesson IDs and rejects unknown lesson IDs", async () => {
    const app = await makeApp();
    const catalog = await app.inject({ method: "GET", url: "/api/lessons" });
    expect(catalog.statusCode).toBe(200);
    expect(catalog.json().lessonIds).toHaveLength(30);
    expect(new Set(catalog.json().lessonIds).size).toBe(30);
    expect((await app.inject({
      method: "POST", url: "/api/labs/check", payload: { lessonId: "not-a-lesson", code: "anything" }
    })).statusCode).toBe(400);
  });

  it("checks the selected lesson and stores workspace code separately per lesson", async () => {
    const root = await mkdtemp(join(tmpdir(), "security-studio-multi-workspace-"));
    try {
      const app = await makeApp(undefined, createExerciseWorkspace(root));
      const checked = await app.inject({
        method: "POST", url: "/api/labs/check",
        payload: { lessonId: "xss-dom", code: "result.textContent = location.hash.slice(1);" }
      });
      expect(checked.statusCode).toBe(200);
      expect(checked.json().passed).toBe(true);
      const codeA = "element.textContent = comment.body;";
      const codeB = "result.textContent = location.hash;";
      expect((await app.inject({ method: "PUT", url: "/api/workspace/xss-stored", payload: { code: codeA } })).statusCode).toBe(200);
      expect((await app.inject({ method: "PUT", url: "/api/workspace/xss-dom", payload: { code: codeB } })).statusCode).toBe(200);
      expect((await app.inject({ method: "GET", url: "/api/workspace/xss-stored" })).json().code).toBe(codeA);
      expect((await app.inject({ method: "GET", url: "/api/workspace/xss-dom" })).json().code).toBe(codeB);
      expect((await app.inject({ method: "GET", url: "/api/workspace/not-a-lesson" })).statusCode).toBe(400);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("validates chat payload before contacting upstream", async () => {
    const response = await (await makeApp()).inject({
      method: "POST", url: "/api/assistant/chat", payload: { messages: [], lessonId: "invalid" }
    });
    expect(response.statusCode).toBe(400);
  });
});
