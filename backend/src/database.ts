import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

const databasePath = resolve(process.env.SECURITY_STUDIO_DB_PATH ?? "data/security-studio.sqlite");
mkdirSync(dirname(databasePath), { recursive: true });

export const database = new DatabaseSync(databasePath);
database.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;
  CREATE TABLE IF NOT EXISTS lesson_progress (
    lesson_id TEXT PRIMARY KEY,
    editor_code TEXT NOT NULL,
    selected_lab_id TEXT NOT NULL DEFAULT 'juice-shop',
    check_result_json TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS chat_messages (
    conversation_id TEXT NOT NULL,
    message_id TEXT NOT NULL,
    lesson_id TEXT NOT NULL,
    role TEXT NOT NULL,
    message_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (conversation_id, message_id)
  );
  CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
`);

export type SavedProgress = {
  lessonId: string;
  editorCode: string;
  selectedLabId: "juice-shop" | "nodegoat";
  checkResult: { passed: boolean; message: string; evidence: string[] } | null;
  updatedAt: string;
};

export function getProgress(lessonId: string): SavedProgress | null {
  const row = database.prepare(
    "SELECT lesson_id, editor_code, selected_lab_id, check_result_json, updated_at FROM lesson_progress WHERE lesson_id = ?"
  ).get(lessonId) as {
    lesson_id: string; editor_code: string; selected_lab_id: "juice-shop" | "nodegoat";
    check_result_json: string | null; updated_at: string;
  } | undefined;
  if (!row) return null;
  return {
    lessonId: row.lesson_id,
    editorCode: row.editor_code,
    selectedLabId: row.selected_lab_id,
    checkResult: row.check_result_json ? JSON.parse(row.check_result_json) as SavedProgress["checkResult"] : null,
    updatedAt: row.updated_at
  };
}

export function saveProgress(progress: Omit<SavedProgress, "updatedAt">): SavedProgress {
  database.prepare(`
    INSERT INTO lesson_progress (lesson_id, editor_code, selected_lab_id, check_result_json, updated_at)
    VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(lesson_id) DO UPDATE SET
      editor_code = excluded.editor_code,
      selected_lab_id = excluded.selected_lab_id,
      check_result_json = excluded.check_result_json,
      updated_at = datetime('now')
  `).run(progress.lessonId, progress.editorCode, progress.selectedLabId, progress.checkResult ? JSON.stringify(progress.checkResult) : null);
  return getProgress(progress.lessonId)!;
}

export function saveChatMessages(conversationId: string, lessonId: string, messages: unknown[]): void {
  const insert = database.prepare(`
    INSERT INTO chat_messages (conversation_id, message_id, lesson_id, role, message_json)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(conversation_id, message_id) DO UPDATE SET
      role = excluded.role, message_json = excluded.message_json
  `);
  const transaction = database.transaction((items: unknown[]) => {
    for (const item of items) {
      if (!item || typeof item !== "object") continue;
      const message = item as { id?: unknown; role?: unknown };
      const messageId = typeof message.id === "string" && message.id.length <= 256 ? message.id : null;
      const role = typeof message.role === "string" && ["user", "assistant", "system"].includes(message.role)
        ? message.role : null;
      if (!messageId || !role) continue;
      insert.run(conversationId, messageId, lessonId, role, JSON.stringify(item));
    }
  });
  transaction(messages);
  database.prepare(`
    DELETE FROM chat_messages WHERE conversation_id = ? AND message_id NOT IN (
      SELECT message_id FROM chat_messages WHERE conversation_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 200
    )
  `).run(conversationId, conversationId);
}

export function getChatMessages(conversationId: string): unknown[] {
  const rows = database.prepare(
    "SELECT message_json FROM chat_messages WHERE conversation_id = ? ORDER BY created_at ASC, rowid ASC LIMIT 200"
  ).all(conversationId) as Array<{ message_json: string }>;
  return rows.map((row) => JSON.parse(row.message_json) as unknown);
}
