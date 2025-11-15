import { test, expect } from '@playwright/test';

test.describe('Admin Login Flow', () => {
  test('should display login page', async ({ page }) => {
    await page.goto('/');

    // Check for login form elements
    await expect(page.locator('input[name="username"]')).toBeVisible();
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/');

    await page.fill('input[name="username"]', 'invalid@example.com');
    await page.fill('input[name="password"]', 'wrongpassword');
    await page.click('button[type="submit"]');

    // Should show error message
    await expect(page.locator('text=/Invalid credentials|Login failed/i')).toBeVisible();
  });

  test('should login successfully with valid credentials', async ({ page }) => {
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    // Should redirect to dashboard after successful login
    await expect(page).toHaveURL(/\/dashboard|\/admin/);
  });

  test('should remember user session', async ({ page, context }) => {
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/dashboard|\/admin/);

    // Close and reopen browser to test session persistence
    const cookies = await context.cookies();
    const newContext = await page.context().browser()!.newContext();
    await newContext.addCookies(cookies);

    const newPage = await newContext.newPage();
    await newPage.goto('/');

    // Should still be logged in
    await expect(newPage).toHaveURL(/\/dashboard|\/admin/);

    await newContext.close();
  });

  test('should logout successfully', async ({ page }) => {
    // Login first
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/dashboard|\/admin/);

    // Logout
    await page.click('button:has-text("Logout"), a:has-text("Logout")');

    // Should redirect to login page
    await expect(page).toHaveURL('/');
  });
});
