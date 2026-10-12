import { describe, expect, it } from "vitest";
import { checkSqlInjectionFix } from "../src/security-check.js";

describe("SQL injection static verifier: known vulnerable and fixed examples", () => {
  const vulnerableExamples = [
    'const query = "SELECT * FROM users WHERE name = " + username; db.query(query);',
    'db.query(`SELECT * FROM users WHERE name = ${username}`);',
    'const query = "UPDATE users SET name = " + name + " WHERE id = " + id; db.execute(query);'
  ];
  const fixedExamples = [
    'db.query("SELECT * FROM users WHERE name = ?", [username]);',
    'db.execute("SELECT * FROM users WHERE id = $1", [id]);',
    'const stmt = db.prepare("SELECT * FROM users WHERE name = ?"); stmt.get(username);'
  ];

  it.each(vulnerableExamples)("rejects vulnerable SQL: %s", (code) => {
    expect(checkSqlInjectionFix(code).passed).toBe(false);
  });

  it.each(fixedExamples)("accepts parameterized SQL: %s", (code) => {
    const result = checkSqlInjectionFix(code);
    expect(result.passed).toBe(true);
    expect(result.evidence.join(" ")).toContain("параметризованного");
  });

  it("does not treat a commented-out vulnerable example as active code", () => {
    const code = [
      '// const query = "SELECT * FROM users WHERE name = " + username;',
      'db.query("SELECT * FROM users WHERE name = ?", [username]);'
    ].join("\n");
    expect(checkSqlInjectionFix(code).passed).toBe(true);
  });

  it("does not claim that an empty editor is safe", () => {
    expect(checkSqlInjectionFix("  ").passed).toBe(false);
  });

  it("does not pass when a vulnerable query is present alongside a safe query", () => {
    const code = [
      'db.query("SELECT * FROM users WHERE name = ?", [username]);',
      'const unsafe = "SELECT * FROM users WHERE id = " + id;'
    ].join("\n");
    expect(checkSqlInjectionFix(code).passed).toBe(false);
  });
});
