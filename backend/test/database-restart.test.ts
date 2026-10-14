import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const children: ChildProcess[] = [];
const stop = async (child: ChildProcess) => {
  if (child.exitCode !== null || child.killed) return;
  await new Promise<void>((resolve) => {
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
    setTimeout(() => {
      if (child.exitCode === null) child.kill("SIGKILL");
      resolve();
    }, 2000).unref();
  });
};

async function freePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Could not reserve a local port");
  const port = address.port;
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

function startBackend(port: number, databasePath: string): ChildProcess {
  const child = spawn(process.execPath, ["--import", "tsx", "src/server.ts"], {
    cwd: process.cwd(),
    env: { ...process.env, NODE_ENV: "test", API_HOST: "127.0.0.1", API_PORT: String(port), SECURITY_STUDIO_DB_PATH: databasePath },
    stdio: "ignore"
  });
  children.push(child);
  return child;
}

async function waitForHealth(port: number, child: ChildProcess): Promise<void> {
  const deadline = Date.now() + 12000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("Backend exited before becoming healthy (code " + child.exitCode + ")");
    try {
      const response = await fetch("http://127.0.0.1:" + port + "/api/healthz");
      if (response.ok) return;
    } catch {
      // The server may still be starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Backend did not become healthy within 12 seconds");
}

describe("SQLite persistence across backend restarts", () => {
  afterAll(async () => {
    await Promise.all(children.map(stop));
  });

  it("restores lesson progress and an AI Security lab run after the process exits", async () => {
    const directory = await mkdtemp(join(tmpdir(), "security-studio-restart-"));
    const databasePath = join(directory, "restart.sqlite");
    const port = await freePort();
    const base = "http://127.0.0.1:" + port;
    try {
      let child = startBackend(port, databasePath);
      await waitForHealth(port, child);

      const progress = {
        editorCode: "const safe = true;",
        selectedLabId: "nodegoat",
        checkResult: { passed: true, message: "restart persistence", evidence: ["sqlite"] }
      };
      const savedProgress = await fetch(base + "/api/progress/sql-injection", {
        method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify(progress)
      });
      expect(savedProgress.status).toBe(200);

      const createdRunResponse = await fetch(base + "/api/ai-security/labs/prompt-injection/reset", { method: "POST" });
      expect(createdRunResponse.status).toBe(200);
      const createdRun = await createdRunResponse.json() as { run: { runId: string; phase: string } };
      expect(createdRun.run.phase).toBe("ready");
      const attacked = await fetch(base + "/api/ai-security/labs/prompt-injection/" + createdRun.run.runId + "/attack", { method: "POST" });
      expect(attacked.status).toBe(200);
      await stop(child);

      child = startBackend(port, databasePath);
      await waitForHealth(port, child);

      const restoredProgress = await fetch(base + "/api/progress/sql-injection");
      expect(restoredProgress.status).toBe(200);
      expect((await restoredProgress.json() as { progress: typeof progress }).progress).toMatchObject(progress);

      const restoredRunResponse = await fetch(base + "/api/ai-security/labs/prompt-injection/" + createdRun.run.runId);
      expect(restoredRunResponse.status).toBe(200);
      const restoredRun = await restoredRunResponse.json() as { run: { phase: string; evidence: Array<{ step: string }> } };
      expect(restoredRun.run.phase).toBe("exploited");
      expect(restoredRun.run.evidence.map((item) => item.step)).toContain("Attack probe");
    } finally {
      await Promise.all(children.map(stop));
      await rm(directory, { recursive: true, force: true });
    }
  }, 30000);
});
