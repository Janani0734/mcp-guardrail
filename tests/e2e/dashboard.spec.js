import { test, expect } from "@playwright/test";

const DASHBOARD_URL =
  process.env.DASHBOARD_URL ||
  "https://janani0734.github.io/mcp-guardrail/";

const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://mcp-guardrail-backend.onrender.com";

const ADMIN_KEY = process.env.RENDER_ADMIN_API_KEY;

test.describe("MCP-Guardrail dashboard", () => {
  test("loads landing page", async ({ page }) => {
    await page.goto(DASHBOARD_URL);

    // .first() avoids a strict-mode failure when several headings
    // contain "MCP-Guardrail" (title, section headings, and so on).
    await expect(
      page.getByRole("heading", { name: /MCP-Guardrail/i }).first()
    ).toBeVisible();

    await expect(
      page.getByRole("button", { name: "Open Sandbox Test Console" })
    ).toBeVisible();
  });

  test("connects and verifies audit chain", async ({ page, request }) => {
    test.skip(
      !ADMIN_KEY,
      "RENDER_ADMIN_API_KEY is required for this test."
    );

    // Render's free tier sleeps. The first call can take 20 to 60 seconds,
    // and the default Playwright test timeout is only 30 seconds in total.
    test.setTimeout(180_000);

    // Wake the backend before driving the UI.
    const health = await request.get(`${BACKEND_URL}/healthz`, {
      timeout: 120_000
    });
    expect(health.ok()).toBeTruthy();

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
      .fill(BACKEND_URL);

    await page
      .getByLabel("Sandbox administrator API key")
      .fill(ADMIN_KEY);

    // Register the dialog handler before the click that triggers it.
    page.once("dialog", (dialog) => dialog.accept());

    // exact: true stops "Connect" from also matching "Disconnect".
    await page
      .getByRole("button", { name: "Connect", exact: true })
      .click();

    await expect(
      page.getByText("Admin API connected").first()
    ).toBeVisible({ timeout: 60_000 });

    await expect(
      page.getByText(/Audit chain verified:/).first()
    ).toBeVisible({ timeout: 60_000 });
  });
});
