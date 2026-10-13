import axios from "axios";
import type { UIMessage } from "ai";

export type LabId = "juice-shop" | "nodegoat";
export type LessonId = string;
export type ActiveLab = { id: LabId; name: string; url: string; status: "running" };
export type CheckResult = { passed: boolean; message: string; evidence: string[] };
export type DemoResult = CheckResult;

const http = axios.create({ baseURL: "/api", timeout: 20_000 });

export async function fetchHealth(): Promise<{ status: string; aiConfigured: boolean }> {
  return (await http.get("/healthz")).data;
}
export async function fetchLabStatus(): Promise<{ activeLab: ActiveLab | null; available: boolean; message?: string }> {
  return (await http.get("/labs/status")).data;
}
export async function startLab(id: LabId): Promise<ActiveLab> {
  return (await http.post("/labs/" + id + "/start")).data.activeLab;
}
export async function stopLab(): Promise<void> {
  await http.post("/labs/stop");
}
export async function resetLab(): Promise<ActiveLab> {
  return (await http.post("/labs/reset")).data.activeLab;
}
export async function runSqlInjectionDemo(): Promise<DemoResult> {
  return (await http.post("/labs/demo-sqli")).data;
}
export async function checkCode(code: string, lessonId: LessonId = "sql-injection"): Promise<CheckResult> {
  return (await http.post("/labs/check", { lessonId, code })).data;
}

export async function fetchExerciseCode(lessonId: LessonId): Promise<string | null> {
  return (await http.get<{ code: string | null }>("/workspace/" + encodeURIComponent(lessonId))).data.code;
}

export async function saveExerciseCode(code: string, lessonId: LessonId = "sql-injection"): Promise<void> {
  await http.put("/workspace/" + encodeURIComponent(lessonId), { code });
}

export async function fetchChatHistory(conversationId: string): Promise<UIMessage[]> {
  return (await http.get<{ messages: UIMessage[] }>("/assistant/history", { params: { id: conversationId } })).data.messages;
}

export type SavedProgress = {
  lessonId: string;
  editorCode: string;
  selectedLabId: LabId;
  checkResult: CheckResult | null;
  updatedAt: string;
};
export async function fetchProgress(lessonId: string): Promise<SavedProgress | null> {
  return (await http.get<{ progress: SavedProgress | null }>("/progress/" + encodeURIComponent(lessonId))).data.progress;
}
export async function saveProgress(lessonId: string, progress: {
  editorCode: string; selectedLabId: LabId; checkResult: CheckResult | null;
}): Promise<void> {
  await http.put("/progress/" + encodeURIComponent(lessonId), progress);
}

export type SyntheticPhase = "ready" | "exploited" | "fixed" | "passed";
export type SyntheticRun = { runId: string; lessonId: LessonId; phase: SyntheticPhase; fixed: boolean; createdAt: string };
export type SyntheticEvidence = {
  runId: string; lessonId: LessonId; phase: SyntheticPhase; vulnerable: boolean; passed: boolean;
  message: string; evidence: string[]; remediation?: CheckResult;
};
export async function createSyntheticRun(lessonId: LessonId): Promise<SyntheticRun> {
  return (await http.post<{ run: SyntheticRun }>("/labs/scenarios/" + encodeURIComponent(lessonId) + "/reset")).data.run;
}
export async function exploitSyntheticRun(lessonId: LessonId, runId: string): Promise<SyntheticEvidence> {
  return (await http.post("/labs/scenarios/" + encodeURIComponent(lessonId) + "/" + encodeURIComponent(runId) + "/exploit")).data;
}
export async function fixSyntheticRun(lessonId: LessonId, runId: string, code: string): Promise<SyntheticEvidence> {
  return (await http.post("/labs/scenarios/" + encodeURIComponent(lessonId) + "/" + encodeURIComponent(runId) + "/fix", { code })).data;
}
export async function retestSyntheticRun(lessonId: LessonId, runId: string): Promise<SyntheticEvidence> {
  return (await http.post("/labs/scenarios/" + encodeURIComponent(lessonId) + "/" + encodeURIComponent(runId) + "/retest")).data;
}
export async function resetSyntheticRun(lessonId: LessonId, runId: string): Promise<SyntheticRun> {
  return (await http.post<{ run: SyntheticRun }>("/labs/scenarios/" + encodeURIComponent(lessonId) + "/" + encodeURIComponent(runId) + "/reset")).data.run;
}


export type AISecurityLabId = "foundations" | "prompt-injection" | "rag-isolation" | "agent-tools" | "privacy" | "model-security" | "red-team" | "infrastructure" | "interview";
export type AISecurityPhase = "ready" | "exploited" | "fixed" | "passed";
export type AISecurityRun = {
  runId: string;
  labId: AISecurityLabId;
  phase: AISecurityPhase;
  controls: Record<string, boolean>;
  evidence: Array<{ step: string; message: string; passed: boolean }>;
  createdAt: string;
};
export async function resetAISecurityLab(labId: AISecurityLabId): Promise<AISecurityRun> {
  return (await http.post<{ run: AISecurityRun }>("/ai-security/labs/" + encodeURIComponent(labId) + "/reset")).data.run;
}
export async function fetchAISecurityLab(labId: AISecurityLabId, runId: string): Promise<AISecurityRun> {
  return (await http.get<{ run: AISecurityRun }>("/ai-security/labs/" + encodeURIComponent(labId) + "/" + encodeURIComponent(runId))).data.run;
}
export async function attackAISecurityLab(labId: AISecurityLabId, runId: string): Promise<AISecurityRun> {
  return (await http.post<{ run: AISecurityRun }>("/ai-security/labs/" + encodeURIComponent(labId) + "/" + encodeURIComponent(runId) + "/attack")).data.run;
}
export async function fixAISecurityLab(labId: AISecurityLabId, runId: string): Promise<AISecurityRun> {
  return (await http.post<{ run: AISecurityRun }>("/ai-security/labs/" + encodeURIComponent(labId) + "/" + encodeURIComponent(runId) + "/fix")).data.run;
}
export async function retestAISecurityLab(labId: AISecurityLabId, runId: string): Promise<AISecurityRun> {
  return (await http.post<{ run: AISecurityRun }>("/ai-security/labs/" + encodeURIComponent(labId) + "/" + encodeURIComponent(runId) + "/retest")).data.run;
}
