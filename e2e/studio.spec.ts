import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());

    if (url.pathname.endsWith("/healthz")) {
      await route.fulfill({ json: { status: "ok", aiConfigured: false, model: "test-model" } });
      return;
    }
    if (url.pathname.endsWith("/labs/status")) {
      await route.fulfill({ json: { activeLab: null, available: true } });
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
