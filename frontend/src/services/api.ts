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
