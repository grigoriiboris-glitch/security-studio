import { mkdir, readFile, rename, unlink, writeFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { lessonIds, type LessonId } from "./lessons.js";

export type ExerciseId = LessonId;
export type ExerciseWorkspace = {
  read(exerciseId: ExerciseId): Promise<string | null>;
  write(exerciseId: ExerciseId, code: string): Promise<void>;
};

export function createExerciseWorkspace(root = process.env.SECURITY_STUDIO_WORKSPACE_DIR ?? "data/workspaces"): ExerciseWorkspace {
  const workspaceRoot = resolve(root);

  function exercisePath(exerciseId: ExerciseId): string {
    if (!(lessonIds as readonly string[]).includes(exerciseId)) throw new Error("Неизвестный урок.");
    const path = resolve(workspaceRoot, exerciseId, "solution.js");
    const relativePath = relative(workspaceRoot, path);
    if (!relativePath || relativePath.startsWith("..") || isAbsolute(relativePath)) {
      throw new Error("Путь учебного файла выходит за пределы рабочей области.");
    }
    return path;
  }

  async function read(exerciseId: ExerciseId): Promise<string | null> {
    try {
      return await readFile(exercisePath(exerciseId), "utf8");
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return null;
      throw error;
    }
  }

  async function write(exerciseId: ExerciseId, code: string): Promise<void> {
    const path = exercisePath(exerciseId);
    await mkdir(dirname(path), { recursive: true });
    const temporaryPath = path + "." + randomUUID() + ".tmp";
    try {
      await writeFile(temporaryPath, code, { encoding: "utf8", mode: 0o600 });
      await rename(temporaryPath, path);
    } catch (error) {
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }

  return { read, write };
}

const defaultWorkspace = createExerciseWorkspace();
export const readExerciseCode = defaultWorkspace.read;
export const writeExerciseCode = defaultWorkspace.write;
