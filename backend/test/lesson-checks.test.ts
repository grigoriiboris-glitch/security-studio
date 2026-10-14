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
  { id: "clickjacking", vulnerable: 'res.setHeader("X-Frame-Options", "ALLOWALL"); res.sendFile("account.html");', fixed: 'res.setHeader("Content-Security-Policy", "frame-ancestors \'none\'"); res.sendFile("account.html");' },
  { id: "security-headers", vulnerable: "app.use(helmet({ contentSecurityPolicy: false, frameguard: false }));", fixed: "app.use(helmet());" },
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


describe("verifier rejects unrelated safe-looking code", () => {
  it("does not accept a reflected-XSS fix when the response still sends request input directly", () => {
    const code = "const title = element.textContent; res.send(req.query.value);";
    expect(checkLessonFix("xss-reflected", code).passed).toBe(false);
  });

  it("does not let one rotated session hide an unrotated login route", () => {
    const code = [
      "await session.regenerate(); req.session.userId = user.id;",
      'app.post("/login", (req, res) => { req.session.userId = user.id; });'
    ].join("\n");
    expect(checkLessonFix("session-fixation", code).passed).toBe(false);
  });
});


describe("verifier rejects mixed safe and vulnerable code", () => {
  it.each(cases)("$id does not pass merely because a mitigation token coexists with vulnerable code", ({ id, vulnerable, fixed }) => {
    const result = checkLessonFix(id, fixed + "\n" + vulnerable);
    expect(result.passed, id + ": " + result.message + " " + result.evidence.join(" ")).toBe(false);
  });
});


describe("additional verifier bypass regressions", () => {
  it("rejects an untrusted Origin alias when the allowlist check is unrelated", () => {
    const code = [
      "const origin = req.headers.origin;",
      "if (allowedOrigins.has(safeOrigin)) audit(safeOrigin);",
      'reply.header("Access-Control-Allow-Origin", origin);'
    ].join("\n");
    expect(checkLessonFix("cors", code).passed).toBe(false);
  });

  it("accepts reflected Origin only when the header assignment is inside the allowlist guard", () => {
    const code = [
      "const origin = req.headers.origin;",
      'if (allowedOrigins.has(origin)) { reply.header("Access-Control-Allow-Origin", origin); }'
    ].join("\n");
    expect(checkLessonFix("cors", code).passed).toBe(true);
  });

  it("rejects a predictable password-reset token even when randomBytes is used elsewhere", () => {
    const code = [
      "const unused = randomBytes(32);",
      "const token = Date.now().toString();"
    ].join("\n");
    expect(checkLessonFix("password-reset", code).passed).toBe(false);
  });
});


describe("verifier adversarial alias-flow regressions", () => {
  it("rejects reflected XSS when request input is assigned to an alias before response output", () => {
    const code = [
      "const safeTitle = escapeHtml('fixed');",
      "const value = req.query.value;",
      "reply.send('<h1>' + value + '</h1>');"
    ].join("\n");
    expect(checkLessonFix("xss-reflected", code).passed).toBe(false);
  });

  it("rejects stored and DOM XSS through aliased sources", () => {
    expect(checkLessonFix("xss-stored", "const comment = req.body.comment; panel.innerHTML = comment;").passed).toBe(false);
    expect(checkLessonFix("xss-dom", "const fragment = location.hash; panel.innerHTML = fragment;").passed).toBe(false);
  });

  it("rejects IDOR through an alias when owner scope is absent", () => {
    const code = [
      "const requestedId = req.params.id;",
      "const harmless = { ownerId: req.user.id };",
      "db.document.findUnique({ where: { id: requestedId } });"
    ].join("\n");
    expect(checkLessonFix("idor", code).passed).toBe(false);
  });

  it("rejects SSRF and open redirect when untrusted URL is first assigned to a variable", () => {
    expect(checkLessonFix("ssrf", "const allowed = validateAllowlistedHttpsUrl('https://example.test'); const target = req.body.url; return fetch(target);").passed).toBe(false);
    expect(checkLessonFix("open-redirect", 'const allowed = allowedLocalPath("/home"); const destination = req.query.next; return res.redirect(destination);').passed).toBe(false);
  });

  it("rejects aliased mass assignment and NoSQL selectors", () => {
    expect(checkLessonFix("mass-assignment", "const patch = req.body; const safe = schema.parse({ name: 'fixed' }); await db.user.update({ data: patch });").passed).toBe(false);
    expect(checkLessonFix("nosql-injection", "const safeEmail = String(req.body.email); const lookup = req.body.filter; users.findOne({ email: lookup });").passed).toBe(false);
  });

  it("rejects aliased upload filenames in public paths", () => {
    expect(checkLessonFix("file-upload", "const randomName = randomUUID(); const uploadedName = file.originalname; await file.toFile(join(publicDir, uploadedName));").passed).toBe(false);
  });

  it("rejects multiline mutating routes without route-local CSRF protection", () => {
    const code = [
      "const verifyCsrfToken = makeCsrfMiddleware();",
      "app.post(",
      '  "/profile/email",',
      "  requireLogin,",
      "  updateEmail",
      ");"
    ].join("\n");
    expect(checkLessonFix("csrf", code).passed).toBe(false);
  });

  it("rejects administration routes registered on router instead of app", () => {
    const code = 'const canDelete = authorize("admin"); router.delete("/admin/users/:id", deleteUser);';
    expect(checkLessonFix("broken-access-control", code).passed).toBe(false);
  });

  it("rejects time-derived password reset tokens despite an unrelated random generator", () => {
    const code = ["const unused = randomBytes(32);", "const token = new Date().getTime().toString();"].join("\n");
    expect(checkLessonFix("password-reset", code).passed).toBe(false);
  });
});
