import { lessonIds, type LessonId } from "./lessons.js";

export type RuntimeScenarioStatus = "runtime-ready" | "static-only";

export type LabScenario = {
  lessonId: LessonId;
  runtimeStatus: RuntimeScenarioStatus;
  target: string | null;
  workflow: {
    prepare: boolean;
    exploitProbe: boolean;
    remediationCheck: boolean;
    runtimeRetest: boolean;
    reset: boolean;
  };
  note: string;
};

const runtimeReady = new Set<LessonId>(["sql-injection"]);

const notes: Partial<Record<LessonId, string>> = {
  "sql-injection": "Runtime probe is available against the local OWASP Juice Shop; the editor verifier remains a separate heuristic.",
};

export const labScenarios: LabScenario[] = lessonIds.map((lessonId) => {
  const ready = runtimeReady.has(lessonId);
  return {
    lessonId,
    runtimeStatus: ready ? "runtime-ready" : "static-only",
    target: ready ? "juice-shop" : null,
    workflow: {
      prepare: ready,
      exploitProbe: ready,
      remediationCheck: true,
      runtimeRetest: false,
      reset: ready,
    },
    note: notes[lessonId] ?? "Runtime exploit/fix/retest is not implemented yet; only the lesson-specific static verifier is available.",
  };
});

export function getLabScenario(lessonId: LessonId): LabScenario | undefined {
  return labScenarios.find((scenario) => scenario.lessonId === lessonId);
}
