import { test, expect } from "@playwright/test";

const DASHBOARD_URL =
  process.env.DASHBOARD_URL ||
  "https://janani0734.github.io/mcp-guardrail/";

const ADMIN_KEY = process.env.RENDER_ADMIN_API_KEY;

test.describe("MCP-Guardrail dashboard", () => {
  test("loads landing page", async ({ page }) => {
    await page.goto(DASHBOARD_URL);

    await expect(
      page.getByRole("heading", { name: /MCP-Guardrail/i })
    ).toBeVisible();

    await expect(
      page.getByRole("button", {
        name: "Open Sandbox Test Console"
      })
    ).toBeVisible();
  });

  test("connects and verifies audit chain", async ({ page }) => {
    test.skip(
      !ADMIN_KEY,
      "RENDER_ADMIN_API_KEY is required for this test."
    );

    await page.goto(DASHBOARD_URL);

    await page
      .getByRole("button", { name: "Open Sandbox Test Console" })
      .click();

    await expect(
      page.getByRole("heading", {
        name: "Connect administrator session"
      })
    ).toBeVisible();

    await page
      .getByLabel("Backend HTTPS base URL")
      .fill("https://mcp-guardrail-backend.onrender.com");

    await page
      .getByLabel("Sandbox administrator API key")
      .fill(ADMIN_KEY);

    page.once("dialog", dialog => dialog.accept());

    await page
      .getByRole("button", { name: "Connect" })
      .click();

    await expect(
      page.getByText("Admin API connected")
    ).toBeVisible({ timeout: 30000 });

    await expect(
      page.getByText(/Audit chain verified:/)
    ).toBeVisible({ timeout: 30000 });
  });
});
