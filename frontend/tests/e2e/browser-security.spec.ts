import { expect, test } from '@playwright/test';

// Synthetic API responses exercise the real UI; they do not certify backend/DB isolation.
test('SC-T07 untrusted customer text never creates executable DOM or network work', async ({ page }) => {
  const marker = '<img src="/synthetic-xss-probe" onerror="window.syntheticExecuted=1">';
  let mutationCount = 0;
  let probeCount = 0;
  page.on('request', (request) => {
    if (request.method() === 'POST') mutationCount++;
    if (request.url().includes('synthetic-xss-probe')) probeCount++;
  });
  await page.route('**/api/v1/workflows?**', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            workflowId: '00000000-0000-4000-8000-000000000102',
            customerId: marker,
            state: 'WAIT_APPROVAL',
            reasonCodes: [],
            usedRisk: 35,
            reservedRisk: 0,
            riskLimit: 40,
          },
        ],
        total: 1,
        page: 0,
        size: 20,
      },
    }),
  );
  await page.goto('/');
  await page.getByLabel('개발용 인증 토큰').fill('synthetic-browser-session');
  await page.getByRole('button', { name: /연결하고 업무 조회/ }).click();
  await expect(page.getByRole('link', { name: marker })).toBeVisible();
  expect(
    await page.evaluate(() => (window as unknown as Record<string, unknown>).syntheticExecuted),
  ).toBeUndefined();
  expect(probeCount).toBe(0);
  expect(mutationCount).toBe(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await page.getByRole('link', { name: /비교 실험/ }).click();
  await page.getByRole('button', { name: '연결 해제' }).click();
  await page.goBack();
  await expect(page.getByRole('link', { name: marker })).toHaveCount(0);
});

test('SC-T07 deployed UI enforces CSP, no-store, frame and referrer headers', async ({ page }) => {
  test.skip(!process.env.FUSE_UI_SECURITY_HEADERS, 'Requires actual nginx deployment, not Vite dev server');
  const response = await page.goto('/');
  const headers = response!.headers();
  expect(headers['cache-control']).toContain('no-store');
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['referrer-policy']).toBe('no-referrer');
  expect(headers['x-frame-options']).toBe('DENY');
  const csp = headers['content-security-policy'];
  for (const directive of [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ])
    expect(csp).toContain(directive);
  expect(csp).not.toMatch(/unsafe-inline|unsafe-eval/);
  // Install a harmless inline script; enforced script-src must block it.
  await page.evaluate(() => {
    const script = document.createElement('script');
    script.textContent = 'window.syntheticCspExecuted = true';
    document.head.append(script);
  });
  expect(
    await page.evaluate(() => (window as unknown as Record<string, unknown>).syntheticCspExecuted),
  ).toBeUndefined();
});
