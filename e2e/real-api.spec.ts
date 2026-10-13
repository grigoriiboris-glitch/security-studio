import { expect, test } from "@playwright/test";

const apiBase = "http://127.0.0.1:3001";

test.describe("real backend integration (no API route mocks)", () => {
  test("health and lesson catalog are served by the running API", async ({ request }) => {
    await expect.poll(async () => {
      try {
        const response = await request.get(apiBase + "/api/healthz", { timeout: 1500 });
        return response.status();
      } catch {
        return 0;
      }
    }, { timeout: 20_000, message: "Backend API should become ready" }).toBe(200);

    const health = await request.get(apiBase + "/api/healthz");
    expect(await health.json()).toMatchObject({ status: "ok" });

    const lessons = await request.get(apiBase + "/api/lessons");
    expect(lessons.status()).toBe(200);
    expect((await lessons.json()).lessonIds).toHaveLength(30);

    const scenarios = await request.get(apiBase + "/api/labs/scenarios");
    expect(scenarios.status()).toBe(200);
    expect((await scenarios.json()).scenarios).toHaveLength(30);
  });

  test("real API enforces exploit → fix → independent retest and rejects invalid order", async ({ request }) => {
    const base = apiBase + "/api/labs/scenarios/sql-injection";
    const created = await request.post(base + "/reset");
    expect(created.status()).toBe(200);
    const { run } = await created.json();
    expect(run).toMatchObject({ lessonId: "sql-injection", phase: "ready", fixed: false });

    const blockedRetest = await request.post(base + "/" + run.runId + "/retest");
    expect(blockedRetest.status()).toBe(200);
    expect((await blockedRetest.json())).toMatchObject({ phase: "ready", passed: false });

    const exploit = await request.post(base + "/" + run.runId + "/exploit");
    expect(exploit.status()).toBe(200);
    expect(await exploit.json()).toMatchObject({ phase: "exploited", vulnerable: true, passed: true });

    const rejectedSecondExploit = await request.post(base + "/" + run.runId + "/exploit");
    expect(rejectedSecondExploit.status()).toBe(409);
    expect(await rejectedSecondExploit.json()).toMatchObject({ error: "Сначала сбросьте лабораторию: exploit probe разрешён только в исходном состоянии." });

    const fix = await request.post(base + "/" + run.runId + "/fix", {
      data: { code: 'db.query("SELECT * FROM users WHERE name = ?", [username]);' }
    });
    expect(fix.status()).toBe(200);
    expect(await fix.json()).toMatchObject({ phase: "fixed", passed: true, remediation: { passed: true } });

    const retest = await request.post(base + "/" + run.runId + "/retest");
    expect(retest.status()).toBe(200);
    expect(await retest.json()).toMatchObject({ phase: "passed", vulnerable: false, passed: true });

    const saved = await request.get(base + "/" + run.runId);
    expect(saved.status()).toBe(200);
    expect(await saved.json()).toMatchObject({ run: { phase: "passed", fixed: true } });
  });

  test("real API validates request sizes and unknown lesson IDs", async ({ request }) => {
    const unknown = await request.post(apiBase + "/api/labs/scenarios/not-a-lesson/reset");
    expect(unknown.status()).toBe(400);

    const invalidFix = await request.post(apiBase + "/api/labs/scenarios/sql-injection/not-a-run/fix", {
      data: { code: "x".repeat(12_001) }
    });
    expect(invalidFix.status()).toBe(400);
  });
  test("browser loads the real lesson UI without stubbing API responses", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "SQL Injection", exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Выбор урока" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Проверить исправление" })).toBeVisible();
  });

});
