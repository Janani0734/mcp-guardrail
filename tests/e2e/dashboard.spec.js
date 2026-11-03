const { test, expect } = require('@playwright/test');

test.describe('MCP-Guardrail Admin Dashboard E2E Pipeline', () => {
  test('should connect session, verify ledger state, and trigger audit check', async ({ page }) => {
    // 1. Navigate to your deployed UI
    await page.goto('https://github.io');

    // 2. Validate core UI elements are visible before connecting
    await expect(page.locator('text=Connect administrator session')).toBeVisible();
    
    // 3. Fill the Admin API Key input and click Connect
    await page.fill('input[type="password"]', process.env.PLAYWRIGHT_ADMIN_KEY || 'mock_key');
    await page.click('button:has-text("Connect")');

    // 4. Assert the state changed to Connected
    const statusBadge = page.locator('.status-badge'); // Update with your actual CSS class
    await expect(statusBadge).toContainText('Connected');

    // 5. Verify the Audit Ledger Table populates rows
    const ledgerTable = page.locator('table'); 
    await expect(ledgerTable).toBeVisible();

    // 6. Test the API Verification pipeline response UI mapping
    await page.click('button:has-text("Verify Chain")');
    await expect(page.locator('text=Audit chain verified successfully')).toBeVisible();
  });
});
