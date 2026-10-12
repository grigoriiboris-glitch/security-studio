import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";

describe("controlled HTTP vulnerability targets", () => {
  const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

  async function fixture(lessonId: string, method: "GET" | "POST" = "GET", query = "") {
    const app = buildApp();
    await app.ready();
    apps.push(app);
    const runId = "test-" + lessonId;
    const base = "/api/labs/http-targets/" + lessonId + "/" + runId;
    const prepared = await app.inject({ method: "POST", url: base + "/prepare" });
    expect(prepared.statusCode).toBe(200);
    const url = base + "/fixture" + query;
    const vulnerable = await app.inject({ method, url, ...(method === "POST" && lessonId === "xss-stored" ? { payload: { comment: "<img src=x onerror=alert(1)>" } } : {}) });
    const fixed = await app.inject({ method: "POST", url: base + "/fix" });
    expect(fixed.statusCode).toBe(200);
    const protectedResponse = await app.inject({ method, url, ...(method === "POST" && lessonId === "xss-stored" ? { payload: { comment: "<img src=x onerror=alert(1)>" } } : {}) });
    return { app, base, vulnerable, protectedResponse };
  }

  it("reflected and stored XSS change from raw HTML to escaped text", async () => {
    const reflected = await fixture("xss-reflected", "GET", "?value=%3Csvg%20onload%3Dalert(1)%3E");
    expect(reflected.vulnerable.body).toContain("<svg onload=alert(1)>");
    expect(reflected.protectedResponse.body).toContain("&lt;svg onload=alert(1)&gt;");

    const app = buildApp();
    await app.ready();
    apps.push(app);
    const base = "/api/labs/http-targets/xss-stored/stored-run";
    await app.inject({ method: "POST", url: base + "/prepare" });
    const saved = await app.inject({ method: "POST", url: base + "/fixture", payload: { comment: "<img src=x onerror=alert(1)>" } });
    expect(saved.statusCode).toBe(200);
    expect((await app.inject({ method: "GET", url: base + "/fixture" })).body).toContain("<img src=x onerror=alert(1)>");
    await app.inject({ method: "POST", url: base + "/fix" });
    expect((await app.inject({ method: "GET", url: base + "/fixture" })).body).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });

  it("DOM XSS fixture exposes unsafe and fixed sinks as actual HTTP-served HTML", async () => {
    const { vulnerable, protectedResponse } = await fixture("xss-dom");
    expect(vulnerable.body).toContain(".innerHTML=value");
    expect(protectedResponse.body).toContain(".textContent=value");
  });

  it("IDOR blocks cross-user records after the fix", async () => {
    const { vulnerable, protectedResponse } = await fixture("idor", "GET", "?id=bob-note");
    expect(vulnerable.statusCode).toBe(200);
    expect(vulnerable.body).toContain("BOB-PRIVATE-FIXTURE");
    expect(protectedResponse.statusCode).toBe(403);
  });

  it("CSRF fixture accepts a state change before protection and requires a token after", async () => {
    const { vulnerable, protectedResponse } = await fixture("csrf", "POST");
    expect(vulnerable.statusCode).toBe(200);
    expect(protectedResponse.statusCode).toBe(403);
  });

  it("path traversal reads only the synthetic secret before remediation", async () => {
    const { vulnerable, protectedResponse } = await fixture("path-traversal", "GET", "?path=..%2Fsecret.txt");
    expect(vulnerable.body).toContain("LAB-ONLY-SECRET-FIXTURE");
    expect(protectedResponse.statusCode).toBe(403);
  });

  it("SSRF fixture simulates a metadata destination without making outbound requests", async () => {
    const { vulnerable, protectedResponse } = await fixture("ssrf", "GET", "?url=http%3A%2F%2Fmetadata.lab%2Fidentity");
    expect(vulnerable.body).toContain("LAB-METADATA-FIXTURE");
    expect(protectedResponse.statusCode).toBe(403);
  });

  it("rejects unknown lesson and unprepared sessions", async () => {
    const app = buildApp();
    await app.ready();
    apps.push(app);
    expect((await app.inject({ method: "POST", url: "/api/labs/http-targets/unknown/run/prepare" })).statusCode).toBe(400);
    expect((await app.inject({ method: "GET", url: "/api/labs/http-targets/idor/missing/fixture?id=bob-note" })).statusCode).toBe(404);
  });
});
