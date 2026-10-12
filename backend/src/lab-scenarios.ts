import { lessonIds, type LessonId } from "./lessons.js";

export type RuntimeScenarioStatus = "runtime-ready" | "synthetic-runtime-ready" | "static-only";
export type LabScenario = {
  lessonId: LessonId;
  runtimeStatus: RuntimeScenarioStatus;
  target: string | null;
  workflow: { prepare: boolean; exploitProbe: boolean; remediationCheck: boolean; runtimeRetest: boolean; reset: boolean };
  note: string;
};

const realRuntime = new Set<LessonId>(["sql-injection"]);
export const labScenarios: LabScenario[] = lessonIds.map((lessonId) => {
  const real = realRuntime.has(lessonId);
  return {
    lessonId,
    runtimeStatus: real ? "runtime-ready" : "synthetic-runtime-ready",
    target: real ? "juice-shop + synthetic-cycle" : "synthetic-target",
    workflow: { prepare: true, exploitProbe: true, remediationCheck: true, runtimeRetest: true, reset: true },
    note: real
      ? "Includes a real local Juice Shop SQLi probe plus a deterministic synthetic exploit → fix → retest cycle. The editor code is never executed."
      : "Deterministic synthetic exploit → fix → retest cycle. The target models this lesson's security invariant; editor code is checked by the lesson verifier and is never executed. Not a real third-party application integration."
  };
});

export function getLabScenario(lessonId: LessonId): LabScenario | undefined {
  return labScenarios.find((scenario) => scenario.lessonId === lessonId);
}
