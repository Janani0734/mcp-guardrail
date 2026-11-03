const { test, expect } = require("@playwright/test");

const DASHBOARD_URL =
  process.env.DASHBOARD_URL ||
  "https://janani0734.github.io/mcp-guardrail/";

const ADMIN_KEY = process.env.RENDER_ADMIN_API_KEY;

test.describe("MCP-Guardrail dashboard lifecycle", () => {
  test("connects, refreshes ledger, and verifies audit status", async ({
    page
  }) => {
    test.skip(
      !ADMIN_KEY,
      "RENDER_ADMIN_API_KEY secret is required for this test."
    );

    await page.goto(DASHBOARD_URL);

    await expect(
      page.getByRole("heading", { name: /MCP-Guardrail/i })
    ).toBeVisible();

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
    ).toBeVisible();

    await expect(
      page.getByText(/Last successful sync:/)
    ).toBeVisible();

    await page
      .getByRole("button", { name: "Refresh" })
      .click();

    await expect(
      page.getByText(/Audit chain verified:/)
    ).toBeVisible();

    await expect(
      page.getByText(/Backend status:/)
    ).toBeVisible();
  });

  test("rejects a pending deletion and preserves the task", async ({
    page
  }) => {
    test.skip(
      !ADMIN_KEY,
      "RENDER_ADMIN_API_KEY secret is required for this test."
    );

    await page.goto(DASHBOARD_URL);

    await page
      .getByRole("button", { name: "Open Sandbox Test Console" })
      .click();

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
    ).toBeVisible();

    const pendingCard = page
      .locator("article.card")
      .filter({
        hasText: "Backend status: PENDING"
      })
      .first();

    await expect(pendingCard).toBeVisible();

    await pendingCard
      .getByRole("button", { name: "Reject Request" })
      .click();

    await expect(
      page.getByText(/Backend reported: REJECTED/)
    ).toBeVisible();
  });
});
