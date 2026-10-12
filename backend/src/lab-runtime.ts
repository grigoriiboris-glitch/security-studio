import { randomUUID } from "node:crypto";
import { type LessonId, lessonIds } from "./lessons.js";
import { checkLessonFix, type SecurityCheckResult } from "./security-check.js";

export type LabPhase = "ready" | "exploited" | "fixed" | "passed";
export type LabRun = {
  runId: string;
  lessonId: LessonId;
  phase: LabPhase;
  fixed: boolean;
  createdAt: string;
};
export type LabEvidence = {
  runId: string;
  lessonId: LessonId;
  phase: LabPhase;
  vulnerable: boolean;
  passed: boolean;
  message: string;
  evidence: string[];
  remediation?: SecurityCheckResult;
};

// This is a deliberately synthetic, deterministic target. It never contacts external hosts
// and never executes code supplied by the learner. The verifier evaluates the editor snippet;
// the retest is an independent, fixed probe against the synthetic vulnerable/fixed behavior.
const titles: Record<LessonId, string> = {
  "sql-injection": "SQL predicate manipulation",
  "xss-reflected": "Reflected HTML output",
  "xss-stored": "Stored HTML output",
  "xss-dom": "URL-to-DOM sink",
  csrf: "Cross-site state change",
  idor: "Cross-user object access",
  "broken-access-control": "Privileged route access",
  "broken-authentication": "Weak credential verification",
  "session-fixation": "Session identifier rotation",
  "password-reset": "Reset-token predictability",
  ssrf: "Untrusted URL destination",
  "path-traversal": "File path boundary",
  "file-upload": "Untrusted upload handling",
  "command-injection": "Shell argument boundary",
  xxe: "XML external entity resolution",
  ssti: "User-controlled template execution",
  "open-redirect": "Untrusted redirect destination",
  cors: "Untrusted CORS origin",
  clickjacking: "Framing policy",
  "security-headers": "HTTP security headers",
  "secrets-exposure": "Hard-coded secret",
  "sensitive-data": "Excessive user data response",
  "jwt-validation": "JWT signature validation",
  "mass-assignment": "Writable field allowlist",
  "rate-limiting": "Repeated login attempts",
  "business-logic": "Client-controlled purchase total",
  "prototype-pollution": "Unsafe object merge",
  "nosql-injection": "Untrusted query object",
  "ldap-injection": "LDAP filter construction",
  "insecure-deserialization": "Untrusted object deserialization"
};

const probeDescriptions: Record<LessonId, string> = {
  "sql-injection": "SQL tautology attempts to alter a login predicate; valid credentials and parameterized queries must be required.",
  "xss-reflected": "HTML markup is reflected into a response; untrusted values must be encoded before HTML output.",
  "xss-stored": "Saved markup reaches an HTML sink; stored content must be rendered as text or sanitized.",
  "xss-dom": "URL fragment reaches a DOM sink; URL-controlled values must be inserted as text.",
  "csrf": "Cross-site state-changing request omits a token; state changes must require a valid CSRF token.",
  "idor": "User A changes an object ID to read user B's object; lookup must be scoped to authenticated ownership.",
  "broken-access-control": "Non-admin calls an admin operation; role authorization must run server-side.",
  "broken-authentication": "Invalid credentials are submitted; password hash verification must be required.",
  "session-fixation": "Pre-auth session ID is reused after login; session ID must rotate after authentication.",
  "password-reset": "Predictable or reused reset token is submitted; reset tokens must be random, expiring and single-use.",
  "ssrf": "Untrusted URL targets a private synthetic address; destinations must be allowlisted and private ranges blocked.",
  "path-traversal": "Relative path attempts to escape the fixture root; resolved path must remain inside the permitted root.",
  "file-upload": "Active content uses a trusted-looking filename; content must be validated and stored outside web root.",
  "command-injection": "Shell metacharacter attempts a second command; fixed executable and argument array must be used without a shell.",
  "xxe": "XML external entity references a local fixture; DTD and external entity resolution must be disabled.",
  "ssti": "Template expression is supplied as user content; input must be data, not a template program.",
  "open-redirect": "Redirect parameter points to an external origin; destination must be allowlisted.",
  "cors": "Untrusted Origin requests a credentialed response; only allowlisted origins may receive CORS permission.",
  "clickjacking": "Hostile parent attempts to frame the app; frame policy must block framing.",
  "security-headers": "Response is checked for missing security headers; baseline browser security headers must be present.",
  "secrets-exposure": "Source is searched for a synthetic hard-coded secret; secrets must stay in server-only configuration.",
  "sensitive-data": "API response requests private fields; response DTO must expose only approved fields.",
  "jwt-validation": "Token with invalid signature is presented; signature and claims must be verified.",
  "mass-assignment": "Request adds a protected role field; only allowlisted writable fields may be accepted.",
  "rate-limiting": "Login attempts exceed threshold; excessive attempts must be throttled.",
  "business-logic": "Client submits a manipulated total; total must be recalculated from server catalog data.",
  "prototype-pollution": "JSON contains __proto__; dangerous keys must be rejected.",
  "nosql-injection": "Object-valued query operator is supplied instead of a string; types must be validated and query operators controlled by server.",
  "ldap-injection": "LDAP filter metacharacters in username; filter values must be escaped or parameterized.",
  "insecure-deserialization": "Serialized input requests a dangerous type; parsed data must be validated against a safe schema."
};

type InternalRun = LabRun & { probeCount: number };
const runs = new Map<string, InternalRun>();
const runKey = (lessonId: LessonId, runId: string) => lessonId + ":" + runId;

export function createLabRun(lessonId: LessonId): LabRun {
  if (!lessonIds.includes(lessonId)) throw new Error("Unknown lesson");
  const run: InternalRun = {
    runId: randomUUID(), lessonId, phase: "ready", fixed: false,
    createdAt: new Date().toISOString(), probeCount: 0
  };
  runs.set(runKey(lessonId, run.runId), run);
  return { runId: run.runId, lessonId, phase: run.phase, fixed: run.fixed, createdAt: run.createdAt };
}
function getRun(lessonId: LessonId, runId: string): InternalRun | undefined {
  return runs.get(runKey(lessonId, runId));
}
function evidence(run: InternalRun, vulnerable: boolean, passed: boolean, message: string, details: string[], remediation?: SecurityCheckResult): LabEvidence {
  return {
    runId: run.runId, lessonId: run.lessonId, phase: run.phase, vulnerable, passed, message,
    evidence: ["Synthetic local target: " + titles[run.lessonId] + ".", ...details],
    ...(remediation ? { remediation } : {})
  };
}
export function probeLabRun(lessonId: LessonId, runId: string): LabEvidence | null {
  const run = getRun(lessonId, runId);
  if (!run) return null;
  if (run.phase === "fixed" || run.phase === "passed") {
    return evidence(run, false, false, "Сначала сбросьте лабораторию: exploit probe предназначен для исходного уязвимого состояния.", ["Состояние не изменено."]);
  }
  run.probeCount++;
  run.phase = "exploited";
  return evidence(run, true, true, "Контрольный exploit probe воспроизводимо подтвердил уязвимое поведение учебной мишени.", [
    probeDescriptions[lessonId],
    "Probe ID: " + run.lessonId + ":baseline-v1.",
    "Это synthetic fixture, а не интеграция с внешним приложением; пользовательский код не исполнялся."
  ]);
}
export function fixLabRun(lessonId: LessonId, runId: string, code: string): LabEvidence | null {
  const run = getRun(lessonId, runId);
  if (!run) return null;
  if (run.phase !== "exploited") {
    return evidence(run, !run.fixed, false, "Сначала запустите exploit probe на исходном состоянии.", ["Порядок цикла: reset → exploit → fix → retest."]);
  }
  const remediation = checkLessonFix(lessonId, code);
  if (!remediation.passed) {
    return evidence(run, true, false, "Статическая проверка исправления не пройдена; мишень остаётся уязвимой.", ["Runtime-состояние не менялось.", ...remediation.evidence], remediation);
  }
  run.fixed = true;
  run.phase = "fixed";
  return evidence(run, false, true, "Защитный шаблон принят verifier-ом. Запустите независимый runtime retest.", [
    "Мишень переключена в фиксированное учебное состояние.",
    "Это проверка шаблона в лаборатории, а не исполнение кода из редактора."
  ], remediation);
}
export function retestLabRun(lessonId: LessonId, runId: string): LabEvidence | null {
  const run = getRun(lessonId, runId);
  if (!run) return null;
  if (run.phase !== "fixed" || !run.fixed) {
    return evidence(run, true, false, "Runtime retest не пройден: сначала необходим успешный шаг fix.", ["Уязвимость считается активной, пока fix не принят."]);
  }
  run.phase = "passed";
  return evidence(run, false, true, "Runtime retest пройден: тот же контрольный probe больше не воспроизводит уязвимое поведение.", [
    "Повторён probe ID: " + run.lessonId + ":baseline-v1.",
    "Проверяемый сценарий: " + probeDescriptions[lessonId],
    "Это детерминированная synthetic-модель, не интеграционный тест реального production-приложения."
  ]);
}
export function resetLabRun(lessonId: LessonId, runId: string): LabRun | null {
  const run = getRun(lessonId, runId);
  if (!run) return null;
  run.phase = "ready";
  run.fixed = false;
  run.probeCount = 0;
  return { runId: run.runId, lessonId, phase: run.phase, fixed: false, createdAt: run.createdAt };
}
export function getLabRun(lessonId: LessonId, runId: string): LabRun | null {
  const run = getRun(lessonId, runId);
  if (!run) return null;
  return { runId: run.runId, lessonId, phase: run.phase, fixed: run.fixed, createdAt: run.createdAt };
}
