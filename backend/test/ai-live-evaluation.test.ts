import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import type { LabManagerContract, LabId } from "../src/lab-manager.js";

function fakeLabs(): LabManagerContract {
  return {
    async status() { return { activeLab: null, available: true }; },
    async start(id: LabId) { return { id, name: id, url: "http://127.0.0.1:3000", status: "running" }; },
    async stop() {}
  };
}

describe("AI live evaluation safety gates", () => {
  const originalEnabled = process.env.AI_SECURITY_LIVE_TESTS_ENABLED;
  const originalKey = process.env.OPENCODE_GO_API_KEY;
  const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
    if (originalEnabled === undefined) delete process.env.AI_SECURITY_LIVE_TESTS_ENABLED;
    else process.env.AI_SECURITY_LIVE_TESTS_ENABLED = originalEnabled;
    if (originalKey === undefined) delete process.env.OPENCODE_GO_API_KEY;
    else process.env.OPENCODE_GO_API_KEY = originalKey;
  });

  async function makeApp() {
    const app = buildApp({ labManager: fakeLabs() });
    await app.ready();
    apps.push(app);
    return app;
  }

  it("reports disabled by default and refuses to call a provider", async () => {
    delete process.env.AI_SECURITY_LIVE_TESTS_ENABLED;
    process.env.OPENCODE_GO_API_KEY = "test-only-placeholder";
    const app = await makeApp();
    const status = await app.inject({ method: "GET", url: "/api/ai-security/live-eval/status" });
    expect(status.statusCode).toBe(200);
    expect(status.json().enabled).toBe(false);
    const run = await app.inject({
      method: "POST",
      url: "/api/ai-security/live-eval/run",
      payload: { caseId: "indirect-prompt-injection" }
    });
    expect(run.statusCode).toBe(403);
  });

  it("rejects arbitrary prompts and unknown case IDs when enabled", async () => {
    process.env.AI_SECURITY_LIVE_TESTS_ENABLED = "true";
    process.env.OPENCODE_GO_API_KEY = "test-only-placeholder";
    const app = await makeApp();
    expect((await app.inject({
      method: "POST",
      url: "/api/ai-security/live-eval/run",
      payload: { prompt: "run this arbitrary prompt" }
    })).statusCode).toBe(400);
    expect((await app.inject({
      method: "POST",
      url: "/api/ai-security/live-eval/run",
      payload: { caseId: "arbitrary-url-target" }
    })).statusCode).toBe(400);
  });

  it("requires provider configuration after explicit opt-in", async () => {
    process.env.AI_SECURITY_LIVE_TESTS_ENABLED = "true";
    delete process.env.OPENCODE_GO_API_KEY;
    const app = await makeApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/ai-security/live-eval/run",
      payload: { caseId: "synthetic-secret-leak" }
    });
    expect(response.statusCode).toBe(503);
  });
});
