import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { LabManagerContract, LabId } from "../src/lab-manager.js";

function fakeLabs(): LabManagerContract {
  let active: LabId | null = null;
  return {
    async status() {
      return { activeLab: active ? { id: active, name: active === "nodegoat" ? "OWASP NodeGoat" : "OWASP Juice Shop", url: active === "nodegoat" ? "http://127.0.0.1:4000" : "http://127.0.0.1:3000", status: "running" as const } : null, available: true };
    },
    async start(id) {
      active = id;
      return { id, name: id === "nodegoat" ? "OWASP NodeGoat" : "OWASP Juice Shop", url: id === "nodegoat" ? "http://127.0.0.1:4000" : "http://127.0.0.1:3000", status: "running" };
    },
    async stop() { active = null; }
  };
}

describe("server-side AI Security fixture API", () => {
  const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });
  async function makeApp() {
    const app = buildApp({ labManager: fakeLabs() });
    await app.ready();
    apps.push(app);
    return app;
  }

  it("publishes nine allowlisted fixture labs and discloses no live model testing", async () => {
    const response = await (await makeApp()).inject({ method: "GET", url: "/api/ai-security/labs" });
    expect(response.statusCode).toBe(200);
    expect(response.json().labs).toHaveLength(9);
    expect(new Set(response.json().labs.map((lab: { id: string }) => lab.id)).size).toBe(9);
    expect(response.json()).toMatchObject({ mode: "server-fixtures", liveModelTesting: false });
  });

  it("rejects unknown lab IDs and unknown session IDs", async () => {
    const app = await makeApp();
    expect((await app.inject({ method: "POST", url: "/api/ai-security/labs/not-a-lab/reset" })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: "/api/ai-security/labs/foundations/no-session/attack" })).statusCode).toBe(404);
  });

  it("enforces attack → fix → independent server-side retest", async () => {
    const app = await makeApp();
    const reset = await app.inject({ method: "POST", url: "/api/ai-security/labs/prompt-injection/reset" });
    expect(reset.statusCode).toBe(200);
    const runId = reset.json().run.runId as string;
    expect(reset.json().run.phase).toBe("ready");

    expect((await app.inject({ method: "POST", url: `/api/ai-security/labs/prompt-injection/${runId}/retest` })).statusCode).toBe(409);
    const attack = await app.inject({ method: "POST", url: `/api/ai-security/labs/prompt-injection/${runId}/attack` });
    expect(attack.statusCode).toBe(200);
    expect(attack.json()).toMatchObject({ vulnerable: true, liveModelTesting: false, run: { phase: "exploited" } });

    const fix = await app.inject({ method: "POST", url: `/api/ai-security/labs/prompt-injection/${runId}/fix` });
    expect(fix.statusCode).toBe(200);
    expect(fix.json().run.controls.promptIsolated).toBe(true);

    const retest = await app.inject({ method: "POST", url: `/api/ai-security/labs/prompt-injection/${runId}/retest` });
    expect(retest.statusCode).toBe(200);
    expect(retest.json()).toMatchObject({ passed: true, vulnerable: false, run: { phase: "passed" } });
    expect(retest.json().run.evidence.map((item: { step: string }) => item.step)).toEqual(["Attack probe", "Remediation", "Independent retest"]);
  });

  it("keeps sessions isolated and requires reset before a second attack", async () => {
    const app = await makeApp();
    const first = (await app.inject({ method: "POST", url: "/api/ai-security/labs/foundations/reset" })).json().run;
    const second = (await app.inject({ method: "POST", url: "/api/ai-security/labs/foundations/reset" })).json().run;
    expect(first.runId).not.toBe(second.runId);
    expect((await app.inject({ method: "POST", url: `/api/ai-security/labs/foundations/${first.runId}/attack` })).statusCode).toBe(200);
    expect((await app.inject({ method: "POST", url: `/api/ai-security/labs/foundations/${first.runId}/attack` })).statusCode).toBe(409);
    expect((await app.inject({ method: "GET", url: `/api/ai-security/labs/foundations/${second.runId}` })).json().run.phase).toBe("ready");
  });
});
