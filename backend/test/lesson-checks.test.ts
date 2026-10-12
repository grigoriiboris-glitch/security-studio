import { describe, expect, it } from "vitest";
import { checkLessonFix } from "../src/security-check.js";
import { lessonIds, type LessonId } from "../src/lessons.js";

const cases: Array<{ id: LessonId; vulnerable: string; fixed: string }> = [
  { id: "xss-reflected", vulnerable: 'res.send("<p>" + req.query.q + "</p>");', fixed: 'res.send("<p>" + escapeHtml(String(req.query.q ?? "")) + "</p>");' },
  { id: "xss-stored", vulnerable: "element.innerHTML = comment.body;", fixed: "element.textContent = comment.body;" },
  { id: "xss-dom", vulnerable: "result.innerHTML = location.hash.slice(1);", fixed: "result.textContent = location.hash.slice(1);" },
  { id: "csrf", vulnerable: 'app.post("/email", requireLogin, updateEmail);', fixed: 'app.post("/email", requireLogin, verifyCsrfToken, updateEmail);' },
  { id: "idor", vulnerable: "db.document.findUnique({ where: { id: req.params.id } });", fixed: "db.document.findFirst({ where: { id: req.params.id, ownerId: req.user.id } });" },
  { id: "broken-access-control", vulnerable: 'app.delete("/admin/users/:id", deleteUser);', fixed: 'app.delete("/admin/users/:id", requireRole("admin"), deleteUser);' },
  { id: "broken-authentication", vulnerable: "if (password === user.password) return createSession(user);", fixed: "if (await argon2.verify(user.passwordHash, password)) return createSession(user);" },
  { id: "session-fixation", vulnerable: "req.session.userId = user.id;", fixed: "await req.session.regenerate(); req.session.userId = user.id;" },
  { id: "password-reset", vulnerable: "const token = user.resetToken;", fixed: "const token = await createRandomExpiringSingleUseToken(user.id);" },
  { id: "ssrf", vulnerable: "return fetch(req.body.url);", fixed: "const url = validateAllowlistedHttpsUrl(req.body.url); return fetch(url);" },
  { id: "path-traversal", vulnerable: "return readFile(join(uploadDir, req.query.file));", fixed: "const path = safeResolveWithin(uploadDir, basename(String(req.query.file))); return readFile(path);" },
  { id: "file-upload", vulnerable: "await file.toFile(join(publicDir, file.filename));", fixed: "const name = randomUUID(); await saveValidatedFileOutsideWebRoot(file, name);" },
  { id: "command-injection", vulnerable: 'exec("convert " + req.body.filename);', fixed: 'execFile("convert", [validatedPath], { shell: false });' },
  { id: "xxe", vulnerable: "parseXml(xml, { processEntities: true });", fixed: "parseXml(xml, { disableDoctype: true, externalEntities: false });" },
  { id: "ssti", vulnerable: "renderTemplate(req.body.template, data);", fixed: 'renderTemplate("welcome", { name: String(req.body.name) });' },
  { id: "open-redirect", vulnerable: "res.redirect(req.query.next);", fixed: "res.redirect(allowedLocalPath(req.query.next) ?? \"/\");" },
  { id: "cors", vulnerable: 'res.header("Access-Control-Allow-Origin", req.headers.origin);', fixed: "if (allowedOrigins.has(origin)) res.header(\"Access-Control-Allow-Origin\", origin);" },
  { id: "clickjacking", vulnerable: 'res.sendFile("account.html");', fixed: 'res.setHeader("Content-Security-Policy", "frame-ancestors \'none\'"); res.sendFile("account.html");' },
  { id: "security-headers", vulnerable: "app.use((req, res, next) => next());", fixed: "app.use(helmet());" },
  { id: "secrets-exposure", vulnerable: 'const apiKey = "prod-secret-123";', fixed: "const apiKey = process.env.API_KEY;" },
  { id: "sensitive-data", vulnerable: "return res.json(user);", fixed: "return res.json({ id: user.id, name: user.name, email: user.email });" },
  { id: "jwt-validation", vulnerable: "const claims = jwt.decode(token);", fixed: "const claims = jwt.verify(token, publicKey, { algorithms: [\"RS256\"], issuer, audience });" },
  { id: "mass-assignment", vulnerable: "await db.user.update({ where: { id }, data: req.body });", fixed: "const { displayName } = schema.parse(req.body); await db.user.update({ where: { id }, data: { displayName } });" },
  { id: "rate-limiting", vulnerable: 'app.post("/login", loginHandler);', fixed: 'app.post("/login", rateLimit({ max: 5, timeWindow: "1 minute" }), loginHandler);' },
  { id: "business-logic", vulnerable: "const total = Number(req.body.total);", fixed: "const total = await calculateCartTotalFromCatalog(req.user.id, req.body.items);" },
  { id: "prototype-pollution", vulnerable: "const config = Object.assign({}, defaults, JSON.parse(input));", fixed: 'const config = pickAllowedKeys(JSON.parse(input), ["theme", "locale"]);' },
  { id: "nosql-injection", vulnerable: "users.findOne({ email: req.body.email });", fixed: "users.findOne({ email: String(req.body.email), passwordHash: storedHash });" },
  { id: "ldap-injection", vulnerable: 'const filter = "(uid=" + username + ")";', fixed: 'const filter = "(uid=" + escapeLdapFilter(username) + ")";' },
  { id: "insecure-deserialization", vulnerable: "const value = deserialize(req.body.payload);", fixed: "const value = JSON.parse(req.body.payload); validateSchema(value);" }
];

describe("lesson-specific verifiers", () => {
  it("has a test case for every non-SQLi lesson", () => {
    expect(cases.map((item) => item.id).sort()).toEqual(lessonIds.filter((id) => id !== "sql-injection").slice().sort());
  });
  it.each(cases)("$id rejects vulnerable code and accepts the documented mitigation", ({ id, vulnerable, fixed }) => {
    const bad = checkLessonFix(id, vulnerable);
    expect(bad.passed, bad.message + " " + bad.evidence.join(" ")).toBe(false);
    const good = checkLessonFix(id, fixed);
    expect(good.passed, good.message + " " + good.evidence.join(" ")).toBe(true);
  });
});
