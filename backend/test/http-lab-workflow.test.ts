import { afterEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/app.js";
import { httpTargetLessonIds } from "../src/http-lab-targets.js";
import type { LessonId } from "../src/lessons.js";

const safeFixes: Partial<Record<LessonId, string>> = {
  "xss-reflected": "res.send(textContent);",
  "xss-stored": "element.textContent = comment;",
  "xss-dom": "element.textContent = location.hash;",
  idor: "findUnique({ id: req.params.id, ownerId: req.user.id });",
  csrf: "verifyCsrfToken(req);",
  "path-traversal": "safeResolveWithin(root, userPath);",
  ssrf: "validateAllowlistedHttpsUrl(inputUrl);",
  "broken-access-control": 'requireRole(req, "admin");',
  "broken-authentication": "await argon2.verify(user.passwordHash, password);",
  "session-fixation": "await session.regenerate(); session.userId = user.id;",
  "password-reset": "const token = randomBytes(32).toString('hex');",
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
  "rate-limiting": 'app.post("/login", rateLimit(), loginHandler);',
  "business-logic": "const total = calculateServerTotal(cart, catalog);",
  "prototype-pollution": "const clean = rejectDangerousKeys(input);",
  "nosql-injection": "const username = String(req.body.username);",
  "ldap-injection": "const filter = escapeLdapFilter(username);",
  "insecure-deserialization": "const data = validateSchema(JSON.parse(input));"
};

const apps: FastifyInstance[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((app) => app.close())); });

describe("public runtime workflow for every controlled HTTP lesson", () => {
  it("has one valid fix example for every controlled HTTP target", () => {
    expect(Object.keys(safeFixes).sort()).toEqual([...httpTargetLessonIds].sort());
  });

  it.each(httpTargetLessonIds)("%s requires a vulnerable HTTP probe, a verified fix, and a passing independent retest", async (lessonId) => {
    const app = buildApp();
    await app.ready();
    apps.push(app);

    const base = "/api/labs/scenarios/" + lessonId;
    const created = await app.inject({ method: "POST", url: base + "/reset" });
    expect(created.statusCode).toBe(200);
    expect(created.json()).toMatchObject({ mode: "controlled-http", codeExecution: false });
    const runId = created.json().run.runId as string;

    const exploit = await app.inject({ method: "POST", url: base + "/" + runId + "/exploit" });
    expect(exploit.statusCode).toBe(200);
    expect(exploit.json()).toMatchObject({ vulnerable: true, passed: true, phase: "exploited" });
    expect(exploit.json().evidence.join(" ")).toContain("HTTP");

    const fixed = await app.inject({
      method: "POST", url: base + "/" + runId + "/fix",
      payload: { code: safeFixes[lessonId] }
    });
    expect(fixed.statusCode).toBe(200);
    expect(fixed.json()).toMatchObject({ phase: "fixed", passed: true });
    expect(fixed.json().remediation?.passed).toBe(true);

    const retest = await app.inject({ method: "POST", url: base + "/" + runId + "/retest" });
    expect(retest.statusCode).toBe(200);
    expect(retest.json()).toMatchObject({ vulnerable: false, passed: true, phase: "passed" });
    expect(retest.json().message).toContain("HTTP retest пройден");

    const reset = await app.inject({ method: "POST", url: base + "/" + runId + "/reset" });
    expect(reset.statusCode).toBe(200);
    expect(reset.json().run).toMatchObject({ phase: "ready", fixed: false });

    const repeatedExploit = await app.inject({ method: "POST", url: base + "/" + runId + "/exploit" });
    expect(repeatedExploit.statusCode).toBe(200);
    expect(repeatedExploit.json()).toMatchObject({ vulnerable: true, passed: true, phase: "exploited" });
  });
});
