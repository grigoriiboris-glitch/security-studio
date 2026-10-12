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

test("reveals lesson hints progressively and can hide them again", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("Найдите решение самостоятельно")).toBeVisible();
  const hintButton = page.getByRole("button", { name: "Открыть следующую подсказку" });
  await hintButton.click();
  await expect(page.locator(".hint-card .objective-list li")).toHaveCount(1);
  await expect(page.locator(".hint-card .objective-list")).toContainText("Найти SQL-конкатенацию");
  await hintButton.click();
  await expect(page.locator(".hint-card .objective-list li")).toHaveCount(2);
  await hintButton.click();
  await expect(page.locator(".hint-card .objective-list li")).toHaveCount(3);
  await expect(page.getByRole("button", { name: "Все подсказки открыты" })).toBeDisabled();
  await page.getByRole("button", { name: "Скрыть подсказки" }).click();
  await expect(page.locator(".hint-card .objective-list")).toHaveCount(0);
});

test("isolated DOM XSS browser probe distinguishes vulnerable and fixed rendering", async ({ page }) => {
  await page.route("**/api/progress/xss-dom", async (route) => {
    await route.fulfill({ json: { progress: null } });
  });
  await page.route("**/api/workspace/xss-dom", async (route) => {
    await route.fulfill({ json: { code: null, file: "solution.js" } });
  });

  await page.goto("/");
  const selector = page.getByRole("combobox", { name: "Выбор урока" });
  await selector.fill("DOM-based XSS");
  await page.getByRole("option", { name: "DOM-based XSS" }).click();

  await expect(page.getByRole("heading", { name: "DOM XSS: проверка в браузере" })).toBeVisible();
  await page.getByRole("button", { name: "Проверить уязвимый вывод" }).click();
  await expect(page.getByText(/Атака подтверждена: HTML-ввод выполнил событие/)).toBeVisible();

  await page.getByRole("button", { name: "Проверить textContent" }).click();
  await expect(page.getByText(/Защита подтверждена: ввод отображён как текст/)).toBeVisible();
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
  await expect(page.getByRole("heading", { name: "SQL Injection", exact: true })).toBeVisible();

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
  await selector.fill("DOM-based XSS");
  await page.getByRole("option", { name: "DOM-based XSS" }).click();
  await expect(page.locator(".monaco-editor .view-lines").first()).toContainText("location.hash");
  await page.getByRole("button", { name: "Проверить исправление" }).click();
  await expect.poll(() => checkedLesson).toBe("xss-dom");
});

test("runs synthetic exploit → fix → retest from the lesson workspace", async ({ page }) => {
  const calls: string[] = [];
  await page.route("**/api/labs/scenarios/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const action = url.pathname.split("/").pop() ?? "";
    calls.push(action);
    if (request.method() === "POST" && action === "reset" && url.pathname.split("/").length === 5) {
      await route.fulfill({ json: { run: { runId: "e2e-run", lessonId: "sql-injection", phase: "ready", fixed: false, createdAt: "2026-01-01T00:00:00.000Z" }, mode: "synthetic", codeExecution: false } });
      return;
    }
    if (action === "exploit") {
      await route.fulfill({ json: { runId: "e2e-run", lessonId: "sql-injection", phase: "exploited", vulnerable: true, passed: true, message: "Контрольный exploit probe подтвердил уязвимое поведение.", evidence: ["Synthetic target"] } });
      return;
    }
    if (action === "fix") {
      await route.fulfill({ json: { runId: "e2e-run", lessonId: "sql-injection", phase: "fixed", vulnerable: false, passed: true, message: "Исправление принято.", evidence: ["Verifier passed"], remediation: { passed: true, message: "Базовая проверка SQLi пройдена.", evidence: [] } } });
      return;
    }
    if (action === "retest") {
      await route.fulfill({ json: { runId: "e2e-run", lessonId: "sql-injection", phase: "passed", vulnerable: false, passed: true, message: "Runtime retest пройден.", evidence: ["Same probe passed"] } });
      return;
    }
    await route.fulfill({ json: { run: { runId: "e2e-run", lessonId: "sql-injection", phase: "ready", fixed: false, createdAt: "2026-01-01T00:00:00.000Z" } } });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Подготовить сценарий" }).click();
  await page.getByRole("button", { name: "1. Exploit probe" }).click();
  await expect(page.getByText("Контрольный exploit probe подтвердил уязвимое поведение.").first()).toBeVisible();
  await expect(page.locator(".runtime-history")).toContainText("Exploit probe");
  await page.getByRole("button", { name: "2. Проверить fix" }).click();
  await expect(page.getByText("Исправление принято.", { exact: true })).toBeVisible();
  await expect(page.locator(".runtime-history")).toContainText("Проверка исправления");
  await page.getByRole("button", { name: "3. Retest" }).click();
  await expect(page.getByText("Runtime retest пройден.", { exact: true })).toBeVisible();
  await expect(page.locator(".runtime-history")).toContainText("Независимый retest");
  expect(calls).toEqual(["reset", "exploit", "fix", "retest"]);
});


test("lesson selector lists all 30 lessons and allows selecting the final lesson", async ({ page }) => {
  await page.goto("/");
  const selector = page.getByRole("combobox", { name: "Выбор урока" });
  await selector.click();
  await expect(page.getByRole("option")).toHaveCount(30);

  const lastOption = page.getByRole("option", { name: "Insecure Deserialization", exact: true });
  await lastOption.scrollIntoViewIfNeeded();
  const box = await lastOption.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.width).toBeGreaterThan(0);
  expect(box!.height).toBeGreaterThan(0);
  await lastOption.click();
  await expect(page.getByRole("heading", { name: "Insecure Deserialization", exact: true })).toBeVisible();
});

test("failed fix shows runtime evidence and keeps retest disabled", async ({ page }) => {
  await page.route("**/api/labs/scenarios/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const action = url.pathname.split("/").pop() ?? "";
    if (request.method() === "POST" && action === "reset" && url.pathname.startsWith("/api/labs/scenarios/")) {
      await route.fulfill({ json: { run: { runId: "failed-fix-run", lessonId: "sql-injection", phase: "ready", fixed: false, createdAt: "2026-01-01T00:00:00.000Z" }, mode: "synthetic", codeExecution: false } });
      return;
    }
    if (action === "exploit") {
      await route.fulfill({ json: { runId: "failed-fix-run", lessonId: "sql-injection", phase: "exploited", vulnerable: true, passed: true, message: "Контрольный exploit probe подтвердил уязвимое поведение.", evidence: ["Исходная мишень уязвима."] } });
      return;
    }
    if (action === "fix") {
      await route.fulfill({ json: { runId: "failed-fix-run", lessonId: "sql-injection", phase: "exploited", fixed: false, vulnerable: true, passed: false, message: "Исправление не подтверждено.", evidence: ["Уязвимый запрос всё ещё присутствует."], remediation: { passed: false, message: "Небезопасный sink найден.", evidence: ["Прямой вывод req.query.value."] } } });
      return;
    }
    await route.fulfill({ json: { error: "Unexpected runtime action" }, status: 500 });
  });

  await page.goto("/");
  await page.getByRole("button", { name: "Подготовить сценарий" }).click();
  await page.getByRole("button", { name: "1. Exploit probe" }).click();
  await page.getByRole("button", { name: "2. Проверить fix" }).click();

  const result = page.locator(".runtime-card .check-result");
  await expect(result).toBeVisible();
  await expect(result).not.toHaveClass(/passed/);
  await expect(result).toContainText("Исправление не подтверждено.");
  await expect(result).toContainText("Уязвимый запрос всё ещё присутствует.");
  await expect(result).toContainText("Прямой вывод req.query.value.");
  await expect(page.getByRole("button", { name: "3. Retest" })).toBeDisabled();
});
