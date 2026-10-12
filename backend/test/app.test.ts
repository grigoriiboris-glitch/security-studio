import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { LabManagerContract, LabId } from "../src/lab-manager.js";

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

  async function makeApp() {
    const app = buildApp({ labManager: fakeLabs() });
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
  it("validates chat payload before contacting upstream", async () => {
    const response = await (await makeApp()).inject({
      method: "POST", url: "/api/assistant/chat", payload: { messages: [], lessonId: "invalid" }
    });
    expect(response.statusCode).toBe(400);
  });
});
