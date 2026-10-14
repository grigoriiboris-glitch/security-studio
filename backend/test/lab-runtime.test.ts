import { afterEach, describe, expect, it } from "vitest";
import { buildApp } from "../src/app.js";
import { lessonIds, type LessonId } from "../src/lessons.js";

const safeFixes: Record<LessonId, string> = {
  "sql-injection": 'db.query("SELECT * FROM users WHERE name = ?", [username]);',
  "xss-reflected": "res.send(textContent);",
  "xss-stored": "element.textContent = comment;",
  "xss-dom": "element.textContent = location.hash;",
  csrf: "verifyCsrfToken(req);",
  idor: "findUnique({ id: req.params.id, ownerId: req.user.id });",
  "broken-access-control": "requireRole(req, \"admin\");",
  "broken-authentication": "await argon2.verify(user.passwordHash, password);",
  "session-fixation": "await session.regenerate(); session.userId = user.id;",
  "password-reset": "const token = randomBytes(32).toString('hex');",
  ssrf: "validateAllowlistedHttpsUrl(inputUrl);",
  "path-traversal": "safeResolveWithin(root, userPath);",
  "file-upload": "saveValidatedFileOutsideWebRoot(file);",
  "command-injection": "execFile(command, args, { shell: false });",
  xxe: "parseXml(xml, { disableDoctype: true, externalEntities: false });",
  ssti: 'renderTemplate("profile", viewModel);',
  "open-redirect": "if (allowedLocalPath(next)) redirect(next);",
  cors: "if (allowedOrigins.has(origin)) setCorsOrigin(origin);",
  clickjacking: "Content-Security-Policy: frame-ancestors 'none';",
  "security-headers": "app.use(helmet());",
  "secrets-exposure": "const apiKey = process.env.API_KEY;",
  "sensitive-data": "return res.json({ id: user.id, name: user.name, email: user.email });",
  "jwt-validation": "jwt.verify(token, secret);",
  "mass-assignment": "const data = pickAllowedKeys(req.body);",
  "rate-limiting": "app.post('/login', rateLimit(), loginHandler);",
  "business-logic": "const total = calculateServerTotal(cart, catalog);",
  "prototype-pollution": "const clean = rejectDangerousKeys(input);",
  "nosql-injection": "const username = String(req.body.username);",
  "ldap-injection": "const filter = escapeLdapFilter(username);",
  "insecure-deserialization": "const data = validateSchema(JSON.parse(input));"
};

describe("all 30 runtime labs", () => {
  const apps: Array<Awaited<ReturnType<typeof buildApp>>> = [];
  afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });
  async function makeApp() {
    const app = buildApp();
    await app.ready();
    apps.push(app);
    return app;
  }

  it("advertises all 30 lessons and distinguishes controlled HTTP targets from SQLi integration", async () => {
    const app = await makeApp();
    const response = await app.inject({ method: "GET", url: "/api/labs/scenarios" });
    expect(response.statusCode).toBe(200);
    const scenarios = response.json().scenarios;
    expect(scenarios).toHaveLength(30);
    expect(new Set(scenarios.map((s: { lessonId: string }) => s.lessonId)).size).toBe(30);
    expect(scenarios.every((s: { workflow: { exploitProbe: boolean; remediationCheck: boolean; runtimeRetest: boolean; reset: boolean } }) =>
      s.workflow.exploitProbe && s.workflow.remediationCheck && s.workflow.runtimeRetest && s.workflow.reset)).toBe(true);
    expect(scenarios.filter((s: { runtimeStatus: string }) => s.runtimeStatus === "runtime-ready")).toHaveLength(30);
    expect(scenarios.filter((s: { target: string }) => s.target === "controlled-http-fixture")).toHaveLength(29);
    expect(scenarios.find((s: { lessonId: string }) => s.lessonId === "sql-injection").target).toBe("juice-shop + synthetic-cycle");
    expect(scenarios.filter((s: { runtimeStatus: string }) => s.runtimeStatus === "synthetic-runtime-ready")).toHaveLength(0);
  });

  it.each(lessonIds)("runs exploit → fix → retest → reset for %s", async (lessonId) => {
    const app = await makeApp();
    const base = "/api/labs/scenarios/" + lessonId;
    const created = await app.inject({ method: "POST", url: base + "/reset" });
    expect(created.statusCode).toBe(200);
    expect(created.json().mode).toBe(["xss-reflected", "xss-stored", "xss-dom", "idor", "csrf", "path-traversal", "ssrf", "broken-access-control", "broken-authentication", "session-fixation", "password-reset", "file-upload", "command-injection", "xxe", "ssti", "open-redirect", "cors", "clickjacking", "security-headers", "secrets-exposure", "sensitive-data", "jwt-validation", "mass-assignment", "rate-limiting", "business-logic", "prototype-pollution", "nosql-injection", "ldap-injection", "insecure-deserialization"].includes(lessonId) ? "controlled-http" : "synthetic");
    expect(created.json().codeExecution).toBe(false);
    const runId = created.json().run.runId;

    const exploit = await app.inject({ method: "POST", url: base + "/" + runId + "/exploit" });
    expect(exploit.statusCode).toBe(200);
    expect(exploit.json()).toMatchObject({ vulnerable: true, passed: true, phase: "exploited" });
    const repeated = await app.inject({ method: "POST", url: base + "/" + runId + "/exploit" });
    expect(repeated.statusCode).toBe(409);

    const blockedRetest = await app.inject({ method: "POST", url: base + "/" + runId + "/retest" });
    expect(blockedRetest.json()).toMatchObject({ vulnerable: true, passed: false });

    const fixed = await app.inject({
      method: "POST", url: base + "/" + runId + "/fix",
      payload: { code: safeFixes[lessonId] }
    });
    expect(fixed.statusCode).toBe(200);
    expect(fixed.json().remediation?.passed, JSON.stringify(fixed.json().remediation)).toBe(true);
    expect(fixed.json().phase).toBe("fixed");

    const retest = await app.inject({ method: "POST", url: base + "/" + runId + "/retest" });
    expect(retest.statusCode).toBe(200);
    expect(retest.json()).toMatchObject({ vulnerable: false, passed: true, phase: "passed" });

    const reset = await app.inject({ method: "POST", url: base + "/" + runId + "/reset" });
    expect(reset.statusCode).toBe(200);
    expect(reset.json().run).toMatchObject({ phase: "ready", fixed: false });
  });


  it("bounds retained lesson sessions so abandoned runs cannot grow memory indefinitely", async () => {
    const { createLabRun, getLabRun } = await import("../src/lab-runtime.js");
    const first = createLabRun("sql-injection");
    for (let index = 0; index < 500; index++) createLabRun("xss-reflected");
    expect(getLabRun("sql-injection", first.runId)).toBeNull();
  });

  it("rejects missing sessions and unknown lesson IDs", async () => {
    const app = await makeApp();
    expect((await app.inject({ method: "POST", url: "/api/labs/scenarios/not-a-lesson/reset" })).statusCode).toBe(400);
    expect((await app.inject({ method: "POST", url: "/api/labs/scenarios/sql-injection/missing/exploit" })).statusCode).toBe(404);
  });
});
