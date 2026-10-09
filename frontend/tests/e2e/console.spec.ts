import { expect, test } from '@playwright/test';

test('desktop entry has no fabricated live data and supports keyboard login', async ({ page }) => {
  const apiCalls: string[] = [];
  page.on('request', (request) => {
    if (request.url().includes('/api/')) apiCalls.push(request.url());
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
  await expect(page.getByText('1,000,000원')).toHaveCount(0);
  expect(apiCalls).toEqual([]);
  await page.screenshot({ path: 'test-results/console-desktop-entry.png', fullPage: true });
  await page.getByLabel('개발용 인증 토큰').fill('browser-smoke-invalid-token');
  await page.getByLabel('개발용 인증 토큰').press('Enter');
  // This is a real server/proxy response. An invalid token never becomes a successful demo session.
  await expect(page.getByRole('alert')).toBeVisible({ timeout: 15000 });
  await expect(page.getByText('실시간 업무를 불러오지 못했어요')).toBeVisible();
  await expect(page.getByRole('link', { name: 'customer-102', exact: true })).toHaveCount(0);
  expect(apiCalls.every((url) => new URL(url).pathname.startsWith('/api/v1/'))).toBeTruthy();
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.screenshot({ path: 'test-results/console-auth-or-offline-error.png', fullPage: true });
  await page.getByRole('button', { name: '연결 해제' }).click();
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
});

test('mobile layout does not overflow and route history stays usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.getByRole('link', { name: /격리 · 영향 조사/ }).click();
  await expect(page).toHaveURL(/#\/quarantine$/);
  await page.goBack();
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
  await page.screenshot({ path: 'test-results/console-mobile-entry.png', fullPage: true });
});
