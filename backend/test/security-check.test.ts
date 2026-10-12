import { describe, expect, it } from "vitest";
import { checkSqlInjectionFix } from "../src/security-check.js";

describe("SQL injection static verifier", () => {
  it("rejects SQL constructed with string concatenation", () => {
    const code = 'const query = "SELECT * FROM users WHERE name = \\'" + username + "\\'";\ndb.query(query);';
    const result = checkSqlInjectionFix(code);
    expect(result.passed).toBe(false);
    expect(result.evidence.join(" ")).toContain("конкатенация");
  });
  it("accepts a parameterized query with a separate values array", () => {
    const result = checkSqlInjectionFix('db.query("SELECT * FROM users WHERE name = ?", [username]);');
    expect(result.passed).toBe(true);
    expect(result.evidence.join(" ")).toContain("параметризованного");
  });
  it("rejects template interpolation into SQL", () => {
    const tick = String.fromCharCode(96);
    const code = "db.query(" + tick + "SELECT * FROM users WHERE name = " + "$" + "{username}" + tick + ");";
    expect(checkSqlInjectionFix(code).passed).toBe(false);
  });
  it("does not claim that an empty editor is safe", () => {
    expect(checkSqlInjectionFix("  ").passed).toBe(false);
  });
});
