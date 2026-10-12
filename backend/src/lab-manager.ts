import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { config } from "./config.js";

const execFileAsync = promisify(execFile);
const containerName = "security-studio-labs";
const networkName = "security-studio-labs";
const allowedLabs = {
  "juice-shop": { name: "OWASP Juice Shop", url: "http://127.0.0.1:3000" },
  nodegoat: { name: "OWASP NodeGoat", url: "http://127.0.0.1:4000" }
} as const;

export type LabId = keyof typeof allowedLabs;
export type ActiveLab = { id: LabId; name: string; url: string; status: "running" };
export type LabManagerStatus = { activeLab: ActiveLab | null; available: boolean; message?: string };
export type LabManagerContract = {
  status(): Promise<LabManagerStatus>;
  start(id: LabId): Promise<ActiveLab>;
  stop(): Promise<void>;
};

async function docker(args: string[]): Promise<string> {
  try {
    const result = await execFileAsync("docker", args, {
      timeout: 25000, maxBuffer: 1024 * 1024, windowsHide: true
    });
    return String(result.stdout).trim();
  } catch (error) {
    const message = error instanceof Error ? error.message : "Неизвестная ошибка Docker.";
    throw new Error("Команда Docker не выполнена: " + message.slice(0, 400));
  }
}
function isMissingContainer(error: unknown): boolean {
  const message = error instanceof Error ? error.message : "";
  return message.includes("No such object") || message.includes("No such container");
}
function activeLab(id: LabId): ActiveLab {
  return { id, name: allowedLabs[id].name, url: allowedLabs[id].url, status: "running" };
}

export class LabManager implements LabManagerContract {
  async status(): Promise<LabManagerStatus> {
    try {
      const id = await docker(["inspect", "--format={{index .Config.Labels \"security-studio.lab\"}}", containerName]);
      if (id === "juice-shop" || id === "nodegoat") return { activeLab: activeLab(id), available: true };
      return { activeLab: null, available: true };
    } catch (error) {
      if (isMissingContainer(error)) return { activeLab: null, available: true };
      return { activeLab: null, available: false, message: "Docker недоступен. Установите Docker и запустите демон." };
    }
  }

  async start(id: LabId): Promise<ActiveLab> {
    if (!(id in allowedLabs)) throw new Error("Неизвестная лаборатория.");
    await this.stop();
    try { await docker(["network", "inspect", networkName]); }
    catch { await docker(["network", "create", "--internal", networkName]); }

    await docker([
      "run", "-d", "--rm", "--init",
      "--name", containerName,
      "--label", "security-studio.managed=true",
      "--label", "security-studio.lab=" + id,
      "--network", networkName,
      "--publish", "127.0.0.1:3000:3000",
      "--publish", "127.0.0.1:4000:4000",
      "--memory=1g", "--cpus=1", "--pids-limit=256",
      "--security-opt=no-new-privileges:true", "--cap-drop=ALL", "--read-only",
      "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,uid=999,gid=999",
      "--tmpfs", "/data/db:rw,nosuid,nodev,size=256m,uid=999,gid=999",
      "--tmpfs", "/opt/juice-shop/data:rw,nosuid,nodev,size=128m,uid=999,gid=999",
      "--env", "NODE_ENV=production",
      "--env", "MONGODB_URI=mongodb://127.0.0.1:27017/nodegoat",
      config.labsImage, id
    ]);
    return activeLab(id);
  }

  async stop(): Promise<void> {
    try {
      const managed = await docker(["inspect", "--format={{index .Config.Labels \"security-studio.managed\"}}", containerName]);
      if (managed !== "true") {
        throw new Error("Контейнер с зарезервированным именем найден, но не принадлежит Security Studio. Остановка отменена.");
      }
      await docker(["rm", "-f", containerName]);
    } catch (error) {
      if (!isMissingContainer(error)) throw error;
    }
  }
}

export const labCatalog = [
  { id: "juice-shop", name: "OWASP Juice Shop", description: "Уязвимое веб-приложение для практики веб-безопасности.", port: 3000 },
  { id: "nodegoat", name: "OWASP NodeGoat", description: "Учебное Node.js-приложение с MongoDB для изучения типовых уязвимостей.", port: 4000 }
] satisfies Array<{ id: LabId; name: string; description: string; port: number }>;
