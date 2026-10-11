import { expect, test, type Locator, type Page, type Request, type Route } from '@playwright/test';
import { checkpoint } from './checkpoints';

// Synthetic API intercepts exercise the deployed UI and native browser fetch/abort only.
// They do not certify server authority, DB effects, LIVE execution, or an abort-ignoring transport.
// The latter remains covered by the separately executed injected-transport component tests.
const ID = '00000000-0000-4000-8000-000000000102';
const NEXT_ID = '00000000-0000-4000-8000-000000000103';
const EXPERIMENT_ID = '00000000-0000-4000-8000-000000000301';
const ORIGINAL_HASH = 'a'.repeat(64);
const CHANGED_HASH = 'd'.repeat(64);
const FIRST_SESSION = 'synthetic-browser-first-session';
const SECOND_SESSION = 'synthetic-browser-second-session';
const originalComment = 'Synthetic original review';
type Decision = 'APPROVE' | 'REJECT';
type SentCommand = { path: string; body: string; key: string; authorization: string };

function sent(request: Request): SentCommand {
  const headers = request.headers();
  return {
    path: new URL(request.url()).pathname,
    body: request.postData() ?? '',
    key: headers['idempotency-key'] ?? '',
    authorization: headers.authorization ?? '',
  };
}

async function syntheticApi(page: Page, handle: (route: Route, path: string) => Promise<boolean>) {
  const unexpected: string[] = [];
  const origin = new URL(String(test.info().project.use.baseURL)).origin;
  await page.route('**/*', async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) {
      unexpected.push('EXTERNAL_REQUEST');
      await route.abort('blockedbyclient');
    } else if (url.pathname.startsWith('/api/')) {
      if (!(await handle(route, url.pathname))) {
        unexpected.push('UNEXPECTED_API_REQUEST');
        await route.abort('blockedbyclient');
      }
    } else await route.continue();
  });
  return unexpected;
}

async function connect(page: Page, session = FIRST_SESSION) {
  await page.getByLabel('개발용 인증 토큰').fill(session);
  await page.getByRole('button', { name: /연결하고 업무 조회/ }).click();
  await expect(page.getByRole('button', { name: '연결 해제', exact: true })).toBeVisible();
}

async function closeApproval(page: Page) {
  await page.getByRole('dialog').getByRole('button', { name: '닫기', exact: true }).first().click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
}

async function openApproval(page: Page) {
  await page.getByRole('button', { name: '정확한 승인 내용 확인', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '직원 승인 · 정확한 내용 확인' });
  await expect(dialog).toBeVisible();
  return dialog;
}

async function enterApproval(dialog: Locator, decision: Decision, comment: string) {
  await dialog.getByLabel('직원 판단', { exact: true }).selectOption(decision);
  await dialog.getByLabel('검토 의견', { exact: true }).fill(comment);
  await dialog.getByLabel('정확한 고객·금액·계좌·결과를 확인했으며 위 판단으로 제출합니다.').check();
  await dialog
    .getByRole('button', {
      name: decision === 'APPROVE' ? '정확한 조건으로 승인' : '직원 거절 제출',
      exact: true,
    })
    .click();
}

async function originalRecovery(dialog: Locator, command: SentCommand, decision: Decision) {
  const region = dialog.getByRole('region', { name: '원래 요청 재확인' });
  await expect(region).toBeVisible();
  await expect(region).toContainText(command.key);
  await expect(region).toContainText(command.path.replace('/api/v1', ''));
  await expect(region).toContainText(decision);
  await expect(region).toContainText(ORIGINAL_HASH);
  await expect(region).toContainText(originalComment);
  await expect(region).toContainText('처음 접수·실행될 수 있어요');
  expect(JSON.parse(await region.locator('pre').innerText())).toEqual(JSON.parse(command.body));
  await expect(dialog.getByLabel('직원 판단', { exact: true })).toHaveCount(0);
  await expect(dialog.getByLabel('검토 의견', { exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: '정확한 조건으로 승인', exact: true })).toHaveCount(0);
  await expect(dialog.getByRole('button', { name: '직원 거절 제출', exact: true })).toHaveCount(0);
  await expect(dialog.getByText(CHANGED_HASH, { exact: true })).toHaveCount(0);
  return region;
}

function workflow(id: string) {
  return {
    workflowId: id,
    generation: 1,
    customerId: id === ID ? 'synthetic-original-customer' : 'synthetic-other-customer',
    businessReference: 'SYNTHETIC-BROWSER-REVIEW',
    amountKrw: 1000000,
    payoutAccountId: id,
    state: 'WAIT_APPROVAL',
    usedRisk: 35,
    reservedRisk: 0,
    riskLimit: 40,
    reasonCodes: ['APPROVAL_REQUIRED'],
    canApprove: true,
    canResume: false,
    activeQuarantines: [],
  };
}

function approvalReceipt(command: SentCommand) {
  const body = JSON.parse(command.body);
  const id = command.path.split('/')[4];
  return {
    requestId: command.key,
    workflowId: id,
    generation: 1,
    decision: 'ALLOW',
    state: body.decision === 'REJECT' ? 'REJECTED' : 'APPROVED',
    reasonCodes: [],
    message: 'Synthetic approval receipt verified',
    replayed: false,
    approvalId: id,
    extraRiskLimit: 50,
    riskLimit: 85,
    expiresAt: '2026-10-11T10:00:00Z',
    payJobId: body.decision === 'REJECT' ? null : id,
  };
}

async function approvalApi(page: Page, post: (route: Route, command: SentCommand) => Promise<void>) {
  const commands: SentCommand[] = [];
  const previewReads: Array<{ id: string; hash: string }> = [];
  let hash = ORIGINAL_HASH;
  const unexpected = await syntheticApi(page, async (route, path) => {
    const request = route.request();
    if (request.method() === 'GET' && path === '/api/v1/workflows') {
      await route.fulfill({
        json: { items: [workflow(ID), workflow(NEXT_ID)], total: 2, page: 0, size: 20 },
      });
      return true;
    }
    const match = /^\/api\/v1\/workflows\/([^/]+)(?:\/(trace|approval-preview|approvals))?$/.exec(path);
    if (!match || ![ID, NEXT_ID].includes(match[1])) return false;
    if (request.method() === 'POST' && match[2] === 'approvals') {
      const command = sent(request);
      commands.push(command);
      await post(route, command);
      return true;
    }
    if (request.method() !== 'GET' || match[2] === 'approvals') return false;
    if (match[2] === 'approval-preview') previewReads.push({ id: match[1], hash });
    await route.fulfill({
      json:
        match[2] === 'trace'
          ? { runs: [], results: [], approvals: [], payments: [], riskEvents: [], auditEvents: [] }
          : match[2] === 'approval-preview'
            ? {
                ...workflow(match[1]),
                kycResultId: match[1],
                loanResultId: match[1],
                evidenceBundleHash: 'b'.repeat(64),
                loanResultHash: 'c'.repeat(64),
                policyVersion: 'synthetic-policy',
                riskLimitAfterApproval: 85,
                reviewSnapshotHash: hash,
              }
            : workflow(match[1]),
    });
    return true;
  });
  return {
    commands,
    previewReads,
    unexpected,
    changePreview: () => {
      hash = CHANGED_HASH;
    },
  };
}

function experiment(status: 'RUNNING' | 'COMPLETED') {
  return {
    experimentId: EXPERIMENT_ID,
    fixtureSetId: 'mvp-security-v1',
    status,
    modelMode: 'REPLAY',
    syntheticModelOutputs: true,
    liveRobustnessMeasured: false,
    progress: { completedRuns: 1, totalRuns: 2 },
    caseOutputs: [
      {
        caseId: 'T01_NORMAL_PAYMENT',
        environment: 'FUSE',
        repeat: 1,
        status: 'COMPLETED',
        state: 'PAID',
        decision: 'ALLOW',
        reasonCodes: [],
      },
    ],
    metrics: {},
  };
}

for (const status of [401, 403, 404]) {
  for (const lateStatus of ['RUNNING', 'COMPLETED'] as const) {
    test(`synthetic browser export HTTP ${status} retires delayed ${lateStatus} poll`, async ({ page }) => {
      checkpoint('REVOCATION_PREPARE');
      let reads = 0;
      let phase: 'initial' | 'await-poll' | 'poll-held' | 'fresh' = 'initial';
      let delayed: Route | undefined;
      const downloads: string[] = [];
      page.on('download', (download) => downloads.push(download.suggestedFilename()));
      const unexpected = await syntheticApi(page, async (route, path) => {
        if (route.request().method() !== 'GET' || path !== `/api/v1/experiments/${EXPERIMENT_ID}`)
          return false;
        reads += 1;
        if (phase === 'await-poll') {
          delayed = route;
          phase = 'poll-held';
        } else if (phase === 'initial' || phase === 'fresh') {
          await route.fulfill({ json: experiment('RUNNING') });
        } else await route.fulfill({ status, json: { reasonCodes: ['FORBIDDEN'] } });
        return true;
      });
      try {
        await page.clock.install({ time: new Date('2026-10-11T08:00:00Z') });
        await page.goto(`/#/experiments/${EXPERIMENT_ID}`);
        await page.clock.pauseAt(new Date('2026-10-11T09:00:00Z'));
        await connect(page);
        await expect(page.getByText('mvp-security-v1', { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: '실험 새로고침' })).toBeEnabled();
        const initialReads = reads;
        expect(initialReads).toBeGreaterThan(0);
        phase = 'await-poll';
        checkpoint('REVOCATION_POLL_HELD');
        await page.clock.runFor(5000);
        await expect.poll(() => !!delayed).toBe(true);
        expect(reads).toBe(initialReads + 1);
        const held = delayed!;
        const aborted = page.waitForEvent('requestfailed', (request) => request === held.request());
        checkpoint('REVOCATION_EXPORT_DENIED');
        await page.getByRole('button', { name: '정제 JSON 내보내기', exact: true }).click();
        await expect(page.getByRole('alert')).toContainText(`HTTP ${status}`);
        const failed = await aborted;
        expect(failed.failure()?.errorText).toBe('net::ERR_ABORTED');
        expect(reads).toBe(initialReads + 2);
        await expect(page.getByText('mvp-security-v1', { exact: true })).toHaveCount(0);
        await expect(page.getByText('T01_NORMAL_PAYMENT', { exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '정제 JSON 내보내기', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: 'CSV 내보내기', exact: true })).toHaveCount(0);
        expect(downloads).toHaveLength(0);
        checkpoint('REVOCATION_NATIVE_ABORT');
        // The response is released only after revocation and observed native abort.
        // A native aborted request cannot deliver this body; no fetch/Response monkeypatch is used.
        await held.fulfill({ json: experiment(lateStatus) });
        delayed = undefined;
        await page.clock.runFor(20000);
        await expect(page.getByRole('alert')).toContainText(`HTTP ${status}`);
        await expect(page.getByText('mvp-security-v1', { exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '정제 JSON 내보내기', exact: true })).toHaveCount(0);
        expect(reads).toBe(initialReads + 2);
        expect(downloads).toHaveLength(0);
        checkpoint('REVOCATION_FRESH_EXPORT');
        phase = 'fresh';
        await page.getByRole('button', { name: '실험 새로고침' }).click();
        await expect(page.getByText('mvp-security-v1', { exact: true })).toBeVisible();
        expect(reads).toBe(initialReads + 3);
        const pendingDownload = page.waitForEvent('download');
        await page.getByRole('button', { name: '정제 JSON 내보내기', exact: true }).click();
        const download = await pendingDownload;
        expect(download.suggestedFilename()).toBe(`finsec-${EXPERIMENT_ID}-sanitized.json`);
        const stream = await download.createReadStream();
        expect(stream).not.toBeNull();
        const chunks: Buffer[] = [];
        for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
        const exported = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        expect(exported.experimentId).toBe(EXPERIMENT_ID);
        expect(exported.exportVersion).toBe('FUSE-UI-EVIDENCE-1');
        expect(exported.sanitized).toBe(true);
        expect(exported.caseOutputs).toHaveLength(1);
        expect(reads).toBe(initialReads + 4);
        expect(downloads).toHaveLength(1);
        expect(unexpected).toEqual([]);
      } finally {
        if (delayed) await delayed.abort().catch(() => undefined);
        await page.unrouteAll({ behavior: 'ignoreErrors' });
      }
    });
  }
}

for (const decision of ['APPROVE', 'REJECT'] as const) {
  test(`synthetic browser UNKNOWN ${decision} preserves intent through dismissal and navigation`, async ({
    page,
  }) => {
    checkpoint('UNKNOWN_ORIGINAL_SEND');
    let heldRetry: Route | undefined;
    let attempts = 0;
    const api = await approvalApi(page, async (route, command) => {
      attempts += 1;
      if (attempts === 1) await route.abort('failed');
      else if (attempts === 2) heldRetry = route;
      else await route.fulfill({ status: 201, json: approvalReceipt(command) });
    });
    try {
      await page.goto(`/#/workflows/${ID}`);
      await connect(page);
      let dialog = await openApproval(page);
      await enterApproval(dialog, decision, originalComment);
      await expect(dialog.getByRole('region', { name: '원래 요청 재확인' })).toBeVisible();
      expect(api.commands).toHaveLength(1);
      const original = { ...api.commands[0] };
      expect(JSON.parse(original.body)).toEqual({
        decision,
        reviewSnapshotHash: ORIGINAL_HASH,
        comment: originalComment,
      });
      expect(original.key).toMatch(/^[0-9a-f-]{36}$/);
      await originalRecovery(dialog, original, decision);
      expect(api.commands).toHaveLength(1);
      checkpoint('UNKNOWN_REOPEN');
      await closeApproval(page);
      expect(api.commands).toHaveLength(1);
      api.changePreview();
      dialog = await openApproval(page);
      await expect
        .poll(() => api.previewReads.filter((row) => row.id === ID && row.hash === CHANGED_HASH).length)
        .toBeGreaterThan(0);
      await originalRecovery(dialog, original, decision);
      expect(api.commands).toHaveLength(1);
      await page.keyboard.press('Escape');
      await expect(page.getByRole('dialog')).toHaveCount(0);
      expect(api.commands).toHaveLength(1);
      checkpoint('UNKNOWN_NAVIGATE_BACK');
      await page.getByRole('link', { name: '← 업무 목록', exact: true }).click();
      await page.getByRole('link', { name: 'synthetic-other-customer', exact: true }).click();
      dialog = await openApproval(page);
      await expect(dialog.getByLabel('직원 판단', { exact: true })).toHaveValue('APPROVE');
      await expect(dialog.getByRole('region', { name: '원래 요청 재확인' })).toHaveCount(0);
      await expect(dialog).not.toContainText(original.key);
      expect(api.commands).toHaveLength(1);
      await closeApproval(page);
      await page.goBack();
      await expect(page.getByRole('heading', { name: '업무 모니터', exact: true })).toBeVisible();
      await page.goBack();
      await expect(page).toHaveURL(new RegExp(`#/workflows/${ID}$`));
      dialog = await openApproval(page);
      const region = await originalRecovery(dialog, original, decision);
      expect(api.commands).toHaveLength(1);
      checkpoint('UNKNOWN_EXACT_RETRY');
      await region.getByRole('button', { name: '같은 요청 다시 확인', exact: true }).click();
      await expect.poll(() => !!heldRetry).toBe(true);
      expect(api.commands).toHaveLength(2);
      expect(api.commands[1]).toEqual(original);
      await originalRecovery(dialog, original, decision);
      await expect(region.getByRole('button')).toBeDisabled();
      await expect(dialog.getByRole('button', { name: '닫기', exact: true })).toBeDisabled();
      await page.keyboard.press('Escape');
      await expect(dialog).toBeVisible();
      expect(api.commands).toHaveLength(2);
      checkpoint('UNKNOWN_RECEIPT');
      await heldRetry!.fulfill({ status: 201, json: approvalReceipt(api.commands[1]) });
      heldRetry = undefined;
      await expect(dialog.getByRole('status')).toContainText('Synthetic approval receipt verified');
      await expect(dialog.getByRole('region', { name: '원래 요청 재확인' })).toHaveCount(0);
      await expect(dialog.getByLabel('직원 판단', { exact: true })).toHaveCount(0);
      expect(api.commands).toHaveLength(2);
      await dialog.getByRole('button', { name: '업무 상태 확인', exact: true }).click();
      checkpoint('UNKNOWN_FRESH_COMMAND');
      dialog = await openApproval(page);
      await expect(dialog.getByText(CHANGED_HASH, { exact: true })).toBeVisible();
      expect(api.commands).toHaveLength(2);
      const opposite: Decision = decision === 'APPROVE' ? 'REJECT' : 'APPROVE';
      await enterApproval(dialog, opposite, 'Synthetic fresh different review');
      await expect(dialog.getByRole('status')).toContainText('Synthetic approval receipt verified');
      expect(api.commands).toHaveLength(3);
      const fresh = api.commands[2];
      expect(fresh.key).not.toBe(original.key);
      expect(fresh.path).toBe(original.path);
      expect(JSON.parse(fresh.body)).toEqual({
        decision: opposite,
        reviewSnapshotHash: CHANGED_HASH,
        comment: 'Synthetic fresh different review',
      });
      expect(fresh.authorization).toBe(original.authorization);
      expect(api.commands[0]).toEqual(original);
      expect(api.commands[1]).toEqual(original);
      expect(unexpectedCount(api.unexpected)).toBe(0);
    } finally {
      if (heldRetry) await heldRetry.abort().catch(() => undefined);
      await page.unrouteAll({ behavior: 'ignoreErrors' });
    }
  });
}

// Return only a bounded count if this assertion fails; never expose an unexpected URL.
function unexpectedCount(unexpected: string[]) {
  return unexpected.length;
}

test('synthetic browser logout prevents old UNKNOWN command in replacement session', async ({ page }) => {
  checkpoint('UNKNOWN_ORIGINAL_SEND');
  let attempts = 0;
  const api = await approvalApi(page, async (route, command) => {
    attempts += 1;
    if (attempts === 1) await route.abort('failed');
    else await route.fulfill({ status: 201, json: approvalReceipt(command) });
  });
  try {
    await page.goto(`/#/workflows/${ID}`);
    await connect(page);
    let dialog = await openApproval(page);
    await enterApproval(dialog, 'APPROVE', originalComment);
    await expect(dialog.getByRole('region', { name: '원래 요청 재확인' })).toBeVisible();
    expect(api.commands).toHaveLength(1);
    const original = { ...api.commands[0] };
    await originalRecovery(dialog, original, 'APPROVE');
    await closeApproval(page);
    expect(api.commands).toHaveLength(1);
    checkpoint('UNKNOWN_SESSION_REPLACED');
    await page.getByRole('button', { name: '연결 해제', exact: true }).click();
    await expect(page.getByLabel('개발용 인증 토큰')).toBeVisible();
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`#/workflows/${ID}$`));
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('button', { name: '같은 요청 다시 확인', exact: true })).toHaveCount(0);
    expect(api.commands).toHaveLength(1);
    api.changePreview();
    await connect(page, SECOND_SESSION);
    dialog = await openApproval(page);
    await expect(dialog.getByLabel('직원 판단', { exact: true })).toHaveValue('APPROVE');
    await expect(dialog.getByRole('region', { name: '원래 요청 재확인' })).toHaveCount(0);
    await expect(dialog).not.toContainText(original.key);
    await expect(dialog.getByText(CHANGED_HASH, { exact: true })).toBeVisible();
    expect(api.commands).toHaveLength(1);
    checkpoint('UNKNOWN_FRESH_COMMAND');
    await enterApproval(dialog, 'REJECT', 'Synthetic replacement session review');
    await expect(dialog.getByRole('status')).toContainText('Synthetic approval receipt verified');
    expect(api.commands).toHaveLength(2);
    const fresh = api.commands[1];
    expect(fresh.key).not.toBe(original.key);
    expect(fresh.path).toBe(original.path);
    expect(JSON.parse(fresh.body)).toEqual({
      decision: 'REJECT',
      reviewSnapshotHash: CHANGED_HASH,
      comment: 'Synthetic replacement session review',
    });
    expect(original.authorization === `Bearer ${FIRST_SESSION}`).toBe(true);
    expect(fresh.authorization === `Bearer ${SECOND_SESSION}`).toBe(true);
    expect(api.commands.filter((item) => item.key === original.key)).toHaveLength(1);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    expect(unexpectedCount(api.unexpected)).toBe(0);
  } finally {
    await page.unrouteAll({ behavior: 'ignoreErrors' });
  }
});
