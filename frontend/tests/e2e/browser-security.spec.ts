import { expect, test, type CDPSession } from '@playwright/test';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { checkpoint } from './checkpoints';

// Synthetic API responses exercise the real UI; they do not certify backend/DB isolation.
test('SC-T07 untrusted customer text never creates executable DOM or network work', async ({ page }) => {
  checkpoint('SECURITY_ROUTE_STUB');
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
  checkpoint('SECURITY_LITERAL_LINK');
  await expect(page.getByRole('link', { name: marker, exact: true })).toBeVisible();
  checkpoint('SECURITY_NO_EXECUTION');
  expect(
    await page.evaluate(() => (window as unknown as Record<string, unknown>).syntheticExecuted),
  ).toBeUndefined();
  expect(probeCount).toBe(0);
  expect(mutationCount).toBe(0);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  checkpoint('SECURITY_LOGOUT_HISTORY');
  await page.getByRole('link', { name: /비교 실험/ }).click();
  await page.getByRole('button', { name: '연결 해제' }).click();
  await page.goBack();
  await expect(page.getByRole('link', { name: marker })).toHaveCount(0);
});

test('SC-T07 deployed UI enforces CSP, no-store, frame and referrer headers', async ({ page }) => {
  test.skip(!process.env.FUSE_UI_SECURITY_HEADERS, 'Requires actual nginx deployment, not Vite dev server');
  checkpoint('SECURITY_HEADERS');
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
  checkpoint('SECURITY_CSP');
  await page.evaluate(() => {
    const script = document.createElement('script');
    script.textContent = 'window.syntheticCspExecuted = true';
    document.head.append(script);
  });
  expect(
    await page.evaluate(() => (window as unknown as Record<string, unknown>).syntheticCspExecuted),
  ).toBeUndefined();
});

test('SC-T07 hostile loopback parent cannot frame the deployed UI', async ({ page, browserName }) => {
  test.skip(
    process.env.FUSE_UI_SECURITY_HEADERS !== '1' || !process.env.FUSE_UI_URL,
    'Requires explicit deployed UI with enforced security headers',
  );
  checkpoint('SECURITY_FRAME_TOP_LEVEL');
  expect(browserName === 'chromium').toBe(true);
  const target = new URL('/', process.env.FUSE_UI_URL!);
  expect(['http:', 'https:'].includes(target.protocol) && !target.username && !target.password).toBe(true);
  // Synthetic correlation only; the marker carries no session/customer/provider information.
  const marker = randomUUID();
  const framedUrl = new URL(target);
  framedUrl.searchParams.set('fuse-frame-probe', marker);
  const response = await page.goto(framedUrl.href);
  expect(response?.ok() === true).toBe(true);
  await expect(page.getByLabel('개발용 인증 토큰')).toBeVisible();
  await expect(page.getByRole('button', { name: /연결하고 업무 조회/ })).toBeVisible();

  // No app proxy, token, customer fixture or parent CSP: only the deployed response can deny framing.
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end(
      '<!doctype html><title>Hostile parent</title><iframe id="hostile-frame" title="Framing probe"></iframe>',
    );
  });
  let session: CDPSession | undefined;
  try {
    checkpoint('SECURITY_FRAME_PARENT');
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('FRAME_PARENT_UNAVAILABLE');
    const parentOrigin = `http://127.0.0.1:${address.port}`;
    expect(parentOrigin !== target.origin).toBe(true);
    const parentUrl = new URL(parentOrigin);
    parentUrl.searchParams.set('fuse-frame-probe', marker);
    await page.goto(parentUrl.href);
    const element = await page.locator('#hostile-frame').elementHandle();
    const frame = await element!.contentFrame();
    expect(frame !== null && page.frames().length === 2).toBe(true);

    // Immediately reduce Chromium diagnostics to booleans. Never attach/log protocol or browser text.
    const cdp = await page.context().newCDPSession(page);
    session = cdp;
    let policyDenied = false;
    let navigationDenied = false;
    cdp.on('Audits.issueAdded', ({ issue }) => {
      const details = issue.details.contentSecurityPolicyIssueDetails;
      // Accept only an exact marked endpoint of this probe, whether the issue identifies the
      // protected resource or its offending ancestor. Unknown/normalized URL forms fail closed;
      // do not infer undocumented frameAncestor semantics or accept an unrelated policy issue.
      if (
        details &&
        !details.isReportOnly &&
        /^frame-ancestors(?:\s|$)/.test(details.violatedDirective) &&
        (details.blockedURL === framedUrl.href || details.blockedURL === parentUrl.href)
      )
        policyDenied = true;
    });
    page.on('requestfailed', (request) => {
      if (
        request.url() === framedUrl.href &&
        request.isNavigationRequest() &&
        request.frame() === frame &&
        request.failure()?.errorText === 'net::ERR_BLOCKED_BY_RESPONSE'
      )
        navigationDenied = true;
    });
    await cdp.send('Audits.enable');
    checkpoint('SECURITY_FRAME_DENIAL');
    await page.locator('#hostile-frame').evaluate((element, url) => {
      (element as HTMLIFrameElement).src = url;
    }, framedUrl.href);
    await expect.poll(() => policyDenied && navigationDenied).toBe(true);

    // Playwright inspects the child directly; a cross-origin DOM exception/load event is not evidence.
    checkpoint('SECURITY_FRAME_UI_ABSENT');
    expect((await element!.contentFrame()) === frame).toBe(true);
    expect(await frame!.locator('#root').count()).toBe(0);
    expect(await frame!.getByLabel('개발용 인증 토큰').count()).toBe(0);
    expect(await frame!.getByRole('button', { name: /연결하고 업무 조회/ }).count()).toBe(0);
  } finally {
    await session?.detach().catch(() => undefined);
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
