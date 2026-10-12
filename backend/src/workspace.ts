import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const workspaceRoot = resolve(process.env.SECURITY_STUDIO_WORKSPACE_DIR ?? "data/workspaces");
const exerciseFiles = {
  "sql-injection": "sql-injection/user-repository.js"
} as const;

export type ExerciseId = keyof typeof exerciseFiles;

function exercisePath(exerciseId: ExerciseId): string {
  const path = resolve(workspaceRoot, exerciseFiles[exerciseId]);
  if (!path.startsWith(workspaceRoot + "/")) {
    throw new Error("Путь учебного файла выходит за пределы рабочей области.");
  }
  return path;
}

export async function readExerciseCode(exerciseId: ExerciseId): Promise<string | null> {
  try {
    return await readFile(exercisePath(exerciseId), "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return null;
    throw error;
  }
}

export async function writeExerciseCode(exerciseId: ExerciseId, code: string): Promise<void> {
  const path = exercisePath(exerciseId);
  await mkdir(dirname(path), { recursive: true });
  const temporaryPath = path + ".tmp";
  try {
    await writeFile(temporaryPath, code, { encoding: "utf8", mode: 0o600 });
    await rename(temporaryPath, path);
  } catch (error) {
    const { unlink } = await import("node:fs/promises");
    await unlink(temporaryPath).catch(() => undefined);
    throw error;
  }
}
