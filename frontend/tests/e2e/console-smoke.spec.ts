import { expect, test } from '@playwright/test';

test('disconnected console sends no API request', async ({ page }) => {
  let requests = 0;
  await page.route('**/api/v1/**', async (route) => {
    requests += 1;
    await route.abort();
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
  expect(requests).toBe(0);
});

test('explicit synthetic session reads only the same-origin workflow API', async ({ page }) => {
  const token = 'synthetic-not-a-real-credential';
  const requests: Array<{ path: string; authorized: boolean }> = [];
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    requests.push({ path, authorized: request.headers().authorization === `Bearer ${token}` });
    if (path !== '/api/v1/workflows' || request.method() !== 'GET') {
      await route.abort();
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], total: 0, page: 0, size: 20 }),
    });
  });
  await page.goto('/#/workflows');
  await page.getByLabel('개발용 인증 토큰').fill(token);
  await page.getByRole('button', { name: '연결하고 업무 조회' }).click();
  await expect(page.getByRole('heading', { name: '업무 모니터', exact: true })).toBeVisible();
  await expect(page.getByText('표시할 업무가 없어요', { exact: true })).toBeVisible();
  expect(requests.length).toBeGreaterThan(0);
  expect(requests.every((request) => request.path === '/api/v1/workflows' && request.authorized)).toBe(true);
  await page.getByRole('button', { name: '연결 해제', exact: true }).click();
  await expect(page.getByRole('heading', { name: '운영 콘솔 연결' })).toBeVisible();
});
