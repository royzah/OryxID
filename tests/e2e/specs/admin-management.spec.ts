import { test, expect } from '@playwright/test';

test.describe('Admin Application Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login before each test
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/dashboard|\/admin/);
  });

  test('should navigate to applications page', async ({ page }) => {
    await page.click('a:has-text("Applications"), nav >> text=Applications');

    await expect(page).toHaveURL(/\/applications/);
    await expect(page.locator('h1, h2')).toContainText(/Applications/i);
  });

  test('should create new application', async ({ page }) => {
    await page.click('a:has-text("Applications")');
    await page.click('button:has-text("New Application"), button:has-text("Create Application")');

    // Fill in application details
    await page.fill('input[name="name"]', 'E2E Test App');
    await page.fill('input[name="redirect_uri"]', 'https://e2e-test.com/callback');
    await page.selectOption('select[name="client_type"]', 'confidential');

    await page.click('button[type="submit"]');

    // Should show success message
    await expect(page.locator('text=/created|success/i')).toBeVisible();
  });

  test('should list applications', async ({ page }) => {
    await page.click('a:has-text("Applications")');

    // Should show applications table
    await expect(page.locator('table, .application-list')).toBeVisible();
  });

  test('should view application details', async ({ page }) => {
    await page.click('a:has-text("Applications")');

    // Click on first application
    await page.click('tr:has-text("Test Application"), .application-item:first-child');

    // Should show application details
    await expect(page.locator('text=/Client ID|Application Details/i')).toBeVisible();
  });

  test('should regenerate client secret', async ({ page }) => {
    await page.click('a:has-text("Applications")');
    await page.click('tr:has-text("Test Application")');

    // Click regenerate secret button
    await page.click('button:has-text("Regenerate Secret")');

    // Confirm action
    await page.click('button:has-text("Confirm")');

    // Should show new secret
    await expect(page.locator('text=/New Secret|Secret regenerated/i')).toBeVisible();
  });
});

test.describe('Admin User Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/dashboard|\/admin/);
  });

  test('should navigate to users page', async ({ page }) => {
    await page.click('a:has-text("Users")');

    await expect(page).toHaveURL(/\/users/);
    await expect(page.locator('h1, h2')).toContainText(/Users/i);
  });

  test('should create new user', async ({ page }) => {
    await page.click('a:has-text("Users")');
    await page.click('button:has-text("New User"), button:has-text("Create User")');

    // Fill in user details
    const randomEmail = `e2e-test-${Date.now()}@example.com`;
    await page.fill('input[name="username"]', `e2e-test-${Date.now()}`);
    await page.fill('input[name="email"]', randomEmail);
    await page.fill('input[name="password"]', 'SecurePassword123!');

    await page.click('button[type="submit"]');

    // Should show success message
    await expect(page.locator('text=/created|success/i')).toBeVisible();
  });

  test('should disable user account', async ({ page }) => {
    await page.click('a:has-text("Users")');

    // Find and click on a user
    await page.click('tr:nth-child(2), .user-item:nth-child(2)');

    // Click disable button
    await page.click('button:has-text("Disable"), button:has-text("Deactivate")');

    // Confirm
    await page.click('button:has-text("Confirm")');

    // Should show success
    await expect(page.locator('text=/disabled|deactivated/i')).toBeVisible();
  });
});

test.describe('Admin Audit Logs', () => {
  test.beforeEach(async ({ page }) => {
    // Login
    await page.goto('/');

    const username = process.env.ADMIN_USERNAME || 'admin';
    const password = process.env.ADMIN_PASSWORD || 'admin123';

    await page.fill('input[name="username"]', username);
    await page.fill('input[name="password"]', password);
    await page.click('button[type="submit"]');

    await expect(page).toHaveURL(/\/dashboard|\/admin/);
  });

  test('should view audit logs', async ({ page }) => {
    await page.click('a:has-text("Audit Logs"), a:has-text("Logs")');

    await expect(page).toHaveURL(/\/audit|\/logs/);
    await expect(page.locator('table, .log-list')).toBeVisible();
  });

  test('should filter audit logs', async ({ page }) => {
    await page.click('a:has-text("Audit Logs"), a:has-text("Logs")');

    // Apply filter
    await page.selectOption('select[name="action"], select[name="filter"]', 'oauth.token');

    // Logs should be filtered
    await expect(page.locator('text=/oauth.token|token/i')).toBeVisible();
  });
});
