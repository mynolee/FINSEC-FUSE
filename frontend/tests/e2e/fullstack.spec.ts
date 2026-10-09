import { expect, test, type APIRequestContext, type Download, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { checkpoint } from './checkpoints';

// No route mocking or direct DB writes. All commands go through the real Java API.
// Run against a newly bootstrapped, isolated Compose project only.
test.skip(process.env.FUSE_E2E_INTEGRATION !== '1', 'NOT_RUN: opt into a fresh real Compose/API/DB stack.');

type Json = Record<string, any>;
const fixture = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, '../../..', 'backend/src/main/resources/fixtures/demo_seed.json'),
    'utf8',
  ),
) as Json;

function token(role: string): string {
  // Deliberately do not accept tokens in command arguments, URLs, storage, or reports.
  const envFile = resolve(process.env.FUSE_E2E_ENV_FILE || '../.env');
  const line = readFileSync(envFile, 'utf8')
    .split(/\r?\n/)
    .find((item) => item.startsWith(`FUSE_${role}_TOKEN=`));
  const value = line?.slice(line.indexOf('=') + 1);
  if (!value || !/^[a-f0-9]{64}$/.test(value)) {
    throw new Error('Missing random bootstrap credential; generate a fresh CI mock configuration.');
  }
  return value;
}
async function login(page: Page, role: string) {
  checkpoint('SESSION_NAVIGATE');
  await page.goto('/');
  checkpoint('SESSION_TOKEN_INPUT');
  await page.getByLabel('개발용 인증 토큰').fill(token(role));
  checkpoint('SESSION_CONNECT');
  await page.getByLabel('개발용 인증 토큰').press('Enter');
  await expect(page.getByRole('button', { name: '연결 해제' })).toBeVisible();
  checkpoint('SESSION_CONNECTED');
}
async function navigate(page: Page, route: string) {
  await page.evaluate((hash) => {
    window.location.hash = hash;
  }, route);
}
async function get(request: APIRequestContext, role: string, path: string): Promise<Json> {
  const response = await request.get(`/api/v1${path}`, {
    headers: { Authorization: `Bearer ${token(role)}` },
  });
  expect(response.status(), 'Real API status').toBe(200);
  return response.json();
}
async function state(request: APIRequestContext, id: string, expected: string): Promise<Json> {
  checkpoint('WORKFLOW_WAIT_STATE');
  await expect
    .poll(async () => (await get(request, 'REVIEWER', `/workflows/${id}`)).state, {
      timeout: 60000,
      intervals: [300, 500, 1000],
    })
    .toBe(expected);
  checkpoint('WORKFLOW_STATE_VERIFIED');
  return get(request, 'REVIEWER', `/workflows/${id}`);
}
async function create(page: Page, customer: string): Promise<string> {
  checkpoint('WORKFLOW_OPEN_CREATE');
  await page.getByRole('button', { name: '+ 등록 신청 시작' }).click();
  checkpoint('WORKFLOW_SELECT_FIXTURE');
  await page.getByLabel('기본 데모 입력 선택').selectOption(customer);
  const accepted = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' && new URL(response.url()).pathname === '/api/v1/workflows',
  );
  checkpoint('WORKFLOW_SUBMIT');
  await page.getByRole('button', { name: '신청 접수', exact: true }).click();
  checkpoint('WORKFLOW_RESPONSE');
  const response = await accepted;
  expect(response.status()).toBe(202);
  const body = await response.json();
  expect(body.workflowId).toMatch(/^[a-f0-9-]{36}$/);
  checkpoint('WORKFLOW_DETAIL_ROUTE');
  await expect(page).toHaveURL(new RegExp(`#/workflows/${body.workflowId}$`));
  return body.workflowId;
}
async function command(page: Page, suffix: string, button: string): Promise<Json> {
  const pending = page.waitForResponse(
    (response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith(suffix),
  );
  checkpoint('COMMAND_CLICK');
  await page.getByRole('button', { name: button, exact: true }).click();
  checkpoint('COMMAND_RESPONSE');
  const response = await pending;
  expect(response.ok(), 'Real API command accepted').toBe(true);
  const body = await response.json();
  expect(['DENY', 'ERROR'].includes(body.decision), 'Server permitted requested command').toBe(false);
  checkpoint('COMMAND_ACCEPTED');
  return body;
}
async function downloaded(download: Download): Promise<string> {
  const stream = await download.createReadStream();
  if (!stream) throw new Error('Browser export download unavailable');
  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks)
    .toString('utf8')
    .replace(/^\uFEFF/, '');
}
function csvRows(csv: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [],
    cell = '',
    quoted = false;
  for (let i = 0; i < csv.length; i += 1) {
    const ch = csv[i];
    if (ch === '"') {
      if (quoted && csv[i + 1] === '"') {
        cell += '"';
        i += 1;
      } else quoted = !quoted;
    } else if (ch === ',' && !quoted) {
      row.push(cell);
      cell = '';
    } else if (ch === '\n' && !quoted) {
      row.push(cell.replace(/\r$/, ''));
      rows.push(row);
      row = [];
      cell = '';
    } else cell += ch;
  }
  if (cell || row.length) {
    row.push(cell.replace(/\r$/, ''));
    rows.push(row);
  }
  if (quoted) throw new Error('Malformed browser CSV export');
  return rows;
}

test('real browser approval pays exactly once while missing evidence stays blocked', async ({
  page,
  request,
}) => {
  test.setTimeout(150000);
  await login(page, 'CUSTOMER_102');
  const normalId = await create(page, '102');
  const waiting = await state(request, normalId, 'WAIT_APPROVAL');
  expect([waiting.usedRisk, waiting.reservedRisk, waiting.generation]).toEqual([35, 0, 1]);
  expect((await get(request, 'REVIEWER', `/workflows/${normalId}/trace`)).payments).toHaveLength(0);

  await login(page, 'REVIEWER');
  await navigate(page, `/workflows/${normalId}`);
  checkpoint('APPROVAL_OPEN');
  await page.getByRole('button', { name: '정확한 승인 내용 확인' }).click();
  checkpoint('APPROVAL_VERIFY_PREVIEW');
  const modal = page.getByRole('dialog');
  await expect(modal.getByText('00000000-0000-4000-8000-000000000102', { exact: true })).toBeVisible();
  await expect(modal.getByText('1,000,000원', { exact: true })).toBeVisible();
  await expect(modal.getByRole('button', { name: '정확한 조건으로 승인', exact: true })).toBeDisabled();
  checkpoint('APPROVAL_CONFIRM');
  await modal
    .getByLabel('검토 의견')
    .fill('CI reviewer checked the exact synthetic customer, amount and account.');
  await modal.getByLabel('정확한 고객·금액·계좌·결과를 확인했으며 위 판단으로 제출합니다.').check();
  await command(page, `/workflows/${normalId}/approvals`, '정확한 조건으로 승인');
  await page.getByRole('button', { name: '업무 상태 확인', exact: true }).click();
  const paid = await state(request, normalId, 'PAID');
  expect([paid.usedRisk, paid.reservedRisk]).toEqual([85, 0]);
  checkpoint('APPROVAL_LEDGER');
  const trace = await get(request, 'REVIEWER', `/workflows/${normalId}/trace`);
  expect(trace.payments).toHaveLength(1);
  expect(trace.approvals.filter((row: Json) => row.status === 'CONSUMED')).toHaveLength(1);
  expect(
    trace.riskEvents.filter((row: Json) => row.eventType === 'CONSUME' && row.points === 50),
  ).toHaveLength(1);
  await expect(page.getByText('Mock 지급 완료. 사후 격리는 지급을 되돌리지 않습니다.')).toBeVisible();

  checkpoint('MISSING_EVIDENCE_CHECK');
  await login(page, 'CUSTOMER_101');
  const attackId = await create(page, '101');
  const blocked = await state(request, attackId, 'BLOCKED');
  expect([blocked.usedRisk, blocked.reservedRisk]).toEqual([10, 0]);
  expect(blocked.reasonCodes).toContain('EVIDENCE_MISSING');
  expect(blocked.activeQuarantines).toHaveLength(1);
  expect((await get(request, 'REVIEWER', `/workflows/${attackId}/trace`)).payments).toHaveLength(0);
  expect((await get(request, 'REVIEWER', `/workflows/${normalId}`)).state).toBe('PAID');
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test('real browser quarantine impact, safe release and explicit recovery preserve history', async ({
  page,
  request,
}) => {
  test.setTimeout(180000);
  await login(page, 'CUSTOMER_103');
  const id = await create(page, '103');
  const original = await state(request, id, 'REJECTED');
  expect([original.usedRisk, original.reservedRisk, original.generation]).toEqual([35, 0, 1]);

  await login(page, 'SECURITY');
  checkpoint('QUARANTINE_OPEN');
  await page.getByRole('link', { name: /격리 · 영향 조사/ }).click();
  await page.getByRole('button', { name: '격리 범위 지정' }).click();
  checkpoint('QUARANTINE_FILL');
  await page.getByLabel('격리 범위', { exact: true }).selectOption('WORKFLOW');
  await page.locator('#quarantine-target').fill(id);
  await page.getByLabel('정책 사유').selectOption('SECURITY_INVESTIGATION');
  await page.getByLabel('조사 내용').fill('CI recovery check of this synthetic workflow only.');
  await page.getByLabel('위 범위와 대상 ID를 확인했습니다.').check();
  const quarantine = await command(page, '/quarantines', '선택한 범위 격리');
  await state(request, id, 'BLOCKED');
  checkpoint('QUARANTINE_IMPACT');
  await expect(page.getByRole('heading', { name: '실제 영향', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: '정책상 잠재 영향', exact: true })).toBeVisible();
  const impact = await get(request, 'SECURITY', `/incidents/${quarantine.quarantineId}/impact`);
  expect(impact.currentAffectedWorkflowIds).toEqual([id]);
  expect([impact.actual.workflowCount, impact.actual.customerCount, impact.actual.paymentCount]).toEqual([
    1, 1, 0,
  ]);
  expect(impact.actual.atRiskPendingAmountKrw).toBe(1000000);
  await expect(page.getByRole('link', { name: id, exact: true })).toBeVisible();

  checkpoint('QUARANTINE_RELEASE');
  await page.getByRole('button', { name: '조치 검증 후 격리 해제' }).click();
  await page.getByLabel('검토된 안전 문서 UUID').fill(fixture.documentId);
  await page.getByLabel('안전 문서 버전').fill('1');
  const evidence = fixture.customers.find(
    (customer: Json) => customer.customerId === 'customer-103',
  ).evidence;
  await page
    .getByLabel('영향 고객 전원의 유효한 확인 자료 UUID')
    .fill(evidence.map((row: Json) => row.id).join('\n'));
  await page
    .getByLabel('원인 제거 및 조치 사유')
    .fill('CI rechecked the registered safe source and both independent mock evidence records.');
  await page.getByLabel('원인을 해결했으며 안전 출처와 독립 확인 자료의 재검증을 요청합니다.').check();
  await command(page, `/quarantines/${quarantine.quarantineId}/release`, '검증 후 격리 해제');
  await page.getByRole('button', { name: '영향 업무 확인', exact: true }).click();
  checkpoint('QUARANTINE_RELEASE_VERIFY');
  const released = await get(request, 'REVIEWER', `/workflows/${id}`);
  expect([released.state, released.generation, released.usedRisk]).toEqual(['BLOCKED', 1, 35]);
  expect(released.activeQuarantines).toHaveLength(0);

  await login(page, 'REVIEWER');
  await navigate(page, `/workflows/${id}`);
  checkpoint('RECOVERY_OPEN');
  await page.getByRole('button', { name: '새 회차로 명시적 재개', exact: true }).click();
  await page
    .getByLabel('원인 해결 및 재개 사유')
    .fill('CI requests a new bounded generation after verified release.');
  const resumed = await command(page, `/workflows/${id}/resume`, '서버 검증 후 재개 요청');
  expect(resumed.generation).toBe(2);
  await page.getByRole('button', { name: '현재 상태 확인', exact: true }).click();
  const current = await state(request, id, 'REJECTED');
  expect([current.generation, current.usedRisk, current.reservedRisk]).toEqual([2, 35, 0]);
  checkpoint('RECOVERY_VERIFY_HISTORY');
  const trace = await get(request, 'REVIEWER', `/workflows/${id}/trace`);
  expect(trace.payments).toHaveLength(0);
  expect(
    trace.runs
      .filter((row: Json) => row.role === 'KYC')
      .map((row: Json) => row.runIndex)
      .sort(),
  ).toEqual([1, 2]);
  expect(trace.results.some((row: Json) => row.generation === 1 && row.status === 'INVALIDATED')).toBe(true);
  expect(
    trace.riskEvents
      .filter((row: Json) => row.eventType === 'CHARGE')
      .reduce((sum: number, row: Json) => sum + row.points, 0),
  ).toBe(35);
});

test('real browser replay experiment exports match persisted API rows and metrics', async ({
  page,
  request,
}) => {
  test.setTimeout(240000);
  await login(page, 'DEVELOPER');
  checkpoint('REPLAY_OPEN');
  await page.getByRole('link', { name: /비교 실험/ }).click();
  await page.getByRole('button', { name: '새 실험', exact: true }).click();
  checkpoint('REPLAY_CONFIGURE');
  await page.getByLabel('모델 모드', { exact: true }).selectOption('REPLAY');
  await page.getByLabel('실험 전용 Mock 업무 실행을 요청합니다.').check();
  const accepted = await command(page, '/experiments', '비교 실험 접수');
  const id = accepted.experimentId;
  expect(id).toMatch(/^[a-f0-9-]{36}$/);
  checkpoint('REPLAY_WAIT_COMPLETE');
  await expect
    .poll(async () => (await get(request, 'DEVELOPER', `/experiments/${id}`)).status, {
      timeout: 180000,
      intervals: [500, 1000, 2000],
    })
    .toBe('COMPLETED');
  checkpoint('REPLAY_VERIFY_ROWS');
  const persisted = await get(request, 'DEVELOPER', `/experiments/${id}`);
  expect(persisted.resultsSource).toBe('JAVA_POSTGRES_EXECUTION');
  expect(persisted.syntheticModelOutputs).toBe(true);
  expect(persisted.liveRobustnessMeasured).toBe(false);
  expect(persisted.caseOutputs).toHaveLength(12);
  expect(persisted.caseOutputs.every((row: Json) => row.status === 'COMPLETED' && !row.exclusionReason)).toBe(
    true,
  );
  expect(persisted.metrics.excludedPairCount).toBe(0);
  checkpoint('REPLAY_REFRESH');
  await page.getByRole('button', { name: '실험 새로고침' }).click();
  await expect(page.getByText('12 / 12 환경 실행', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'CSV 내보내기' })).toBeEnabled();
  checkpoint('REPLAY_JSON_EXPORT');
  const jsonDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: '정제 JSON 내보내기', exact: true }).click();
  const exported = JSON.parse(await downloaded(await jsonDownload));
  checkpoint('REPLAY_JSON_COMPARE');
  expect(exported.experimentId).toBe(id);
  expect(exported.exportVersion).toBe('FUSE-UI-EVIDENCE-1');
  expect(exported.sanitized).toBe(true);
  expect(exported.caseOutputs).toHaveLength(persisted.caseOutputs.length);
  for (let i = 0; i < exported.caseOutputs.length; i += 1) {
    for (const key of [
      'caseId',
      'environment',
      'status',
      'state',
      'decision',
      'repeat',
      'policyBlocked',
      'normalExpectedReached',
      'forbiddenPaymentCount',
      'pairedInputHash',
      'modelOutputHash',
    ]) {
      expect(exported.caseOutputs[i][key]).toEqual(persisted.caseOutputs[i][key]);
    }
  }
  for (const key of ['excludedPairCount', 'syntheticModelOutputs', 'liveRobustnessMeasured']) {
    expect(exported.metrics[key]).toEqual(persisted.metrics[key]);
  }
  checkpoint('REPLAY_CSV_EXPORT');
  const csvDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'CSV 내보내기' }).click();
  const [headers, ...rows] = csvRows(await downloaded(await csvDownload));
  checkpoint('REPLAY_CSV_COMPARE');
  expect(rows).toHaveLength(12);
  for (let i = 0; i < rows.length; i += 1) {
    for (const key of ['caseId', 'environment', 'status', 'state', 'decision']) {
      const column = headers.indexOf(key);
      expect(column, `CSV column ${key}`).toBeGreaterThanOrEqual(0);
      expect(rows[i][column]).toBe(String(persisted.caseOutputs[i][key]));
    }
  }
});
