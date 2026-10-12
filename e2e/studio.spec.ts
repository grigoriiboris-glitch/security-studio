import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  let savedProgress: { editorCode: string; selectedLabId: string; checkResult: unknown } | null = null;
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.pathname.endsWith("/healthz")) {
      await route.fulfill({ json: { status: "ok", aiConfigured: false, model: "test-model" } });
      return;
    }
    if (url.pathname.endsWith("/assistant/history")) {
      await route.fulfill({ json: { messages: [] } });
      return;
    }
    if (url.pathname.endsWith("/labs/status")) {
      await route.fulfill({ json: { activeLab: null, available: true } });
      return;
    }
    if (url.pathname.endsWith("/progress/sql-injection") && request.method() === "GET") {
      await route.fulfill({ json: { progress: savedProgress } });
      return;
    }
    if (url.pathname.endsWith("/progress/sql-injection") && request.method() === "PUT") {
      savedProgress = request.postDataJSON() as typeof savedProgress;
      await route.fulfill({ json: { progress: savedProgress } });
      return;
    }
    if (url.pathname.endsWith("/workspace/sql-injection") && request.method() === "GET") {
      await route.fulfill({ json: { code: null, file: "user-repository.js" } });
      return;
    }
    if (url.pathname.endsWith("/workspace/sql-injection") && request.method() === "PUT") {
      await route.fulfill({ json: { saved: true, file: "user-repository.js" } });
      return;
    }
    await route.fulfill({ json: { labs: [] } });
  });
});

test("editor submits changed code to backend checker and displays its result", async ({ page }) => {
  let submittedCode = "";
  await page.route("**/api/labs/check", async (route) => {
    submittedCode = (route.request().postDataJSON() as { code: string }).code;
    await route.fulfill({
      json: { passed: true, message: "Проверка пройдена: параметры передаются отдельно.", evidence: ["Проверка получена backend."] }
    });
  });

  await page.goto("/");
  await expect(page.getByRole("heading", { name: "SQL Injection" })).toBeVisible();

  const editor = page.locator(".monaco-editor").first();
  await expect(editor).toBeVisible();
  await editor.click();
  await page.keyboard.press("Control+A");
  await page.keyboard.type('db.query("SELECT * FROM users WHERE name = ?", [username]);');

  await page.getByRole("button", { name: "Проверить исправление" }).click();
  await expect.poll(() => submittedCode).toContain("[username]");
  await expect(page.getByText("Проверка пройдена: параметры передаются отдельно.").first()).toBeVisible();
});

test("lab selector opens a visible option list", async ({ page }) => {
  await page.goto("/");
  const selector = page.getByRole("combobox", { name: "Выбор учебного приложения" });
  await selector.focus();
  await page.keyboard.press("ArrowDown");
  const option = page.getByRole("option", { name: "OWASP NodeGoat" });
  await expect(option).toBeVisible();
  const box = await option.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThan(0);
});

test("saves code, checks it, and restores the lesson after reload", async ({ page }) => {
  let workspaceCode = "";
  let savedProgress: { editorCode: string; selectedLabId: string; checkResult: unknown } | null = null;
  await page.route("**/api/progress/sql-injection", async (route) => {
    if (route.request().method() === "PUT") {
      savedProgress = route.request().postDataJSON() as typeof savedProgress;
      await route.fulfill({ json: { progress: savedProgress } });
      return;
    }
    await route.fulfill({ json: { progress: savedProgress } });
  });
  await page.route("**/api/workspace/sql-injection", async (route) => {
    const request = route.request();
    if (request.method() === "PUT") {
      workspaceCode = (request.postDataJSON() as { code: string }).code;
      await route.fulfill({ json: { saved: true, file: "user-repository.js" } });
      return;
    }
    await route.fulfill({ json: { code: workspaceCode || null, file: "user-repository.js" } });
  });
  await page.route("**/api/labs/check", async (route) => {
    await route.fulfill({
      json: { passed: true, message: "Проверка пройдена.", evidence: ["Код проверен backend."] }
    });
  });

  await page.goto("/");
  const editor = page.locator(".monaco-editor").first();
  await expect(editor).toBeVisible();
  await editor.click();
  await page.keyboard.press("Control+A");
  const code = 'db.query("SELECT * FROM users WHERE name = ?", [username]);';
  await page.keyboard.type(code);
  await page.getByRole("button", { name: "Сохранить код" }).click();
  await expect.poll(() => workspaceCode).toContain("[username]");
  await page.getByRole("button", { name: "Проверить исправление" }).click();
  await expect(page.getByText("Проверка пройдена.", { exact: true }).first()).toBeVisible();

  await expect.poll(() => savedProgress?.editorCode ?? "").toContain("[username]");
  await page.reload();
  await expect(page.locator(".monaco-editor").first()).toBeVisible();
  await expect(page.locator(".monaco-editor .view-lines").first()).toContainText("[username]");
});


test("switching lesson changes the example and verifier receives that lesson ID", async ({ page }) => {
  let checkedLesson = "";
  await page.route("**/api/progress/xss-dom", async (route) => {
    await route.fulfill({ json: { progress: null } });
  });
  await page.route("**/api/workspace/xss-dom", async (route) => {
    await route.fulfill({ json: { code: null, file: "solution.js" } });
  });
  await page.route("**/api/labs/check", async (route) => {
    checkedLesson = (route.request().postDataJSON() as { lessonId: string }).lessonId;
    await route.fulfill({
      json: { passed: false, message: "Учебная проверка DOM XSS.", evidence: ["Verifier получил lessonId."] }
    });
  });

  await page.goto("/");
  const selector = page.getByRole("combobox", { name: "Выбор урока" });
  await selector.click();
  await page.getByRole("option", { name: "DOM XSS" }).click();
  await expect(page.locator(".monaco-editor .view-lines").first()).toContainText("location.hash");
  await page.getByRole("button", { name: "Проверить исправление" }).click();
  await expect.poll(() => checkedLesson).toBe("xss-dom");
});
