import { test, expect } from '@playwright/test';

test.describe('Authentication journey', () => {
  test('Sign-in page loads and form is accessible', async ({ page }) => {
    await page.goto('/sign-in');
    await expect(page).toHaveTitle(/Sign in/);
    await expect(page.getByRole('heading', { name: /Sign in to your evidence workspace/ })).toBeVisible();
    await expect(page.getByLabel('Email address')).toBeVisible();
    await expect(page.getByLabel('Password')).toBeVisible();
    await expect(page.getByRole('button', { name: /Sign in/ })).toBeVisible();
  });

  test('Register page loads and form is accessible', async ({ page }) => {
    await page.goto('/register');
    await expect(page).toHaveTitle(/Create account/);
    await expect(page.getByRole('heading', { name: /Create your organization workspace/ })).toBeVisible();
  });

  test('CSP header allows unsafe-inline in dev', async ({ request }) => {
    const response = await request.get('/');
    const csp = response.headers()['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toContain("style-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain("style-src 'self' 'nonce-");
  });

  test('No CSP inline style violations in console', async ({ page }) => {
    const violations: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error' && msg.text().includes('Applying inline style violates')) {
        violations.push(msg.text());
      }
    });
    await page.goto('/sign-in');
    await page.waitForTimeout(1000);
    expect(violations).toHaveLength(0);
  });
});
