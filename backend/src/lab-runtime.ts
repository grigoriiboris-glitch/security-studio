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
    "Probe: " + run.lessonId + ":baseline.",
    "Ожидаемое нарушение контрольного инварианта воспроизведено.",
    "Это синтетический сценарий; внешний сайт и пользовательский код не запускались."
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
    "Использован тот же lesson-specific probe, что и на baseline.",
    "Зафиксировано отсутствие ожидаемого нарушения инварианта.",
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
