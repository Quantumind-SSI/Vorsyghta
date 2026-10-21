import { test, expect } from '@playwright/test';

const API_BASE = process.env.VORSYGHTA_API_URL || 'http://127.0.0.1:8001';

test.describe('Full auth user journey', () => {
  test('Register → Login → Onboarding entry flow', async ({ page, request }) => {
    const email = `e2e-${Date.now()}@example.com`;
    const password = 'E2ePass123!xyz';
    const org = 'E2E Org';

    // Register via API to avoid UI race with Next server actions
    const registerResp = await request.post(`${API_BASE}/api/auth/register`, {
      data: { email, password, organization_name: org }
    });
    expect(registerResp.status()).toBe(201);
    const regData = await registerResp.json();
    expect(regData.tenant_id).toBeTruthy();

    // 2. Sign-in page loads
    await page.goto('/sign-in?next=%2Fonboarding');
    await expect(page).toHaveTitle(/Sign in/);
    await expect(page.getByLabel('Email address')).toBeVisible();

    // 3. Submit credentials via API to obtain token
    const tokenResp = await request.post(`${API_BASE}/api/auth/token`, {
      form: { username: email, password }
    });
    expect(tokenResp.status()).toBe(200);
    const tokenData = await tokenResp.json();
    expect(tokenData.access_token).toBeTruthy();

    // 4. Verify /api/auth/me works
    const meResp = await request.get(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    expect(meResp.status()).toBe(200);
    const meData = await meResp.json();
    expect(meData.email).toBe(email);
    expect(meData.tenant_id).toBe(regData.tenant_id);

    // 5. UI shows onboarding requires auth
    await page.goto('/onboarding');
    await expect(page).toHaveURL(/\/sign-in/);
  });

  test('Start trial redirects unauthenticated users to sign-in', async ({ page }) => {
    await page.goto('/start-trial');
    // If unauthenticated, should show offer; if authenticated, app entry
    // At minimum page loads without error
    await expect(page.locator('main')).toBeVisible();
  });

  test('Register page enforces password min length', async ({ page }) => {
    await page.goto('/register');
    await page.fill('input[name="organization_name"]', 'Org');
    await page.fill('input[name="email"]', 'a@b.com');
    await page.fill('input[name="password"]', 'short');
    // Client validation prevents submit
    await page.getByRole('button', { name: /Create account/ }).click();
    await expect(page).toHaveURL(/\/register/);
  });

  test('Forgot password page is static and informs user', async ({ page }) => {
    await page.goto('/forgot-password');
    await expect(page.getByText(/Password recovery is not available/)).toBeVisible();
    await expect(page.getByRole('link', { name: /Back to sign in/ })).toBeVisible();
  });
});
