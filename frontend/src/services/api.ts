import axios from "axios";

export type LabId = "juice-shop" | "nodegoat";
export type ActiveLab = { id: LabId; name: string; url: string; status: "running" };
export type CheckResult = { passed: boolean; message: string; evidence: string[] };

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
export async function checkCode(code: string): Promise<CheckResult> {
  return (await http.post("/labs/check", { code })).data;
}
