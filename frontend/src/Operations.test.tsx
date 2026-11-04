import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { FuseApi } from './api';
import { QuarantinePage } from './components/Quarantine';

const ID = '00000000-0000-4000-8000-000000000201';
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const impact = {
  incidentId: ID,
  scope: 'AGENT_VERSION',
  target: { agentId: 'kyc-agent', agentVersion: 1 },
  historicalRunIds: [],
  currentAffectedWorkflowIds: [],
  paidBeforeQuarantine: [],
  actual: {
    runCount: 0,
    roleCount: 0,
    workflowCount: 0,
    customerCount: 0,
    paymentCount: 0,
    paidAmountKrw: 0,
    atRiskPendingAmountKrw: 0,
  },
  potential: {
    roles: ['LOAN', 'PAYMENT'],
    maxDownstreamDepth: 2,
    registeredCustomerCount: null,
    perApplicationLimitKrw: 50000000,
    missingPolicyFields: ['customerScope'],
  },
  calculationRefs: { sources: [] },
};
async function login() {
  await userEvent.type(screen.getByLabelText('개발용 인증 토큰'), 'test-operator-token');
  await userEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
}
beforeEach(() => {
  vi.restoreAllMocks();
  window.location.hash = '/quarantine';
});

describe('security operations and evaluation views', () => {
  it.each([
    ['00000000-0000-0000-0000-000000000001', true],
    ['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', false],
    ['1-1-1-1-1', false],
  ])('matches canonical backend UUID policy for quarantine target %s', async (target, accepted) => {
    const fetcher = vi.fn().mockImplementation((_url: string, options: RequestInit) => Promise.resolve(
      options?.method === 'POST'
        ? response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: null,
          generation: null, state: 'ACTIVE', decision: 'DENY', reasonCodes: [], replayed: false })
        : response(impact),
    ));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: '격리 범위 지정' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('특정 실행 ID (UUID)'), { target: { value: target } });
    fireEvent.change(within(dialog).getByLabelText('조사 내용'), { target: { value: 'synthetic review' } });
    await userEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.submit(dialog.querySelector('form')!);
    const requests = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(requests).toHaveLength(accepted ? 1 : 0);
    if (accepted) expect(JSON.parse(requests[0][1].body as string).runId).toBe(target);
  });

  it.each([
    ['00000000-0000-0000-0000-000000000001', true],
    ['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', false],
    ['1-1-1-1-1', false],
  ])('validates canonical safe document and evidence command IDs: %s', async (reference, accepted) => {
    window.location.hash = `/quarantine/${ID}`;
    const fetcher = vi.fn().mockImplementation((_url: string, options: RequestInit) => Promise.resolve(
      options?.method === 'POST'
        ? response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: null,
          generation: null, state: 'ACTIVE', decision: 'DENY', reasonCodes: [], replayed: false })
        : response(impact),
    ));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(await screen.findByRole('button', { name: '조치 검증 후 격리 해제' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('검토된 안전 문서 UUID'), { target: { value: reference } });
    fireEvent.change(within(dialog).getByLabelText('영향 고객 전원의 유효한 확인 자료 UUID'), { target: { value: reference } });
    fireEvent.change(within(dialog).getByLabelText('검토된 안전 Agent ID'), { target: { value: 'kyc-agent' } });
    fireEvent.change(within(dialog).getByLabelText('안전 Agent 버전'), { target: { value: '1' } });
    fireEvent.change(within(dialog).getByLabelText('원인 제거 및 조치 사유'), { target: { value: 'synthetic remediation' } });
    await userEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.submit(dialog.querySelector('form')!);
    const requests = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(requests).toHaveLength(accepted ? 1 : 0);
    if (accepted) expect(JSON.parse(requests[0][1].body as string).remediation).toMatchObject({ safeDocumentId: reference, checkEvidenceIds: [reference] });
  });

  it('invalidates release confirmation when the reviewed safe document changes and blocks malformed UUIDs', async () => {
    window.location.hash = `/quarantine/${ID}`;
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response(impact)));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(await screen.findByRole('button', { name: '조치 검증 후 격리 해제' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('검토된 안전 문서 UUID'), { target: { value: ID } });
    fireEvent.change(within(dialog).getByLabelText('검토된 안전 Agent ID'), { target: { value: 'kyc-agent' } });
    fireEvent.change(within(dialog).getByLabelText('안전 Agent 버전'), { target: { value: '1' } });
    fireEvent.change(within(dialog).getByLabelText('원인 제거 및 조치 사유'), { target: { value: 'synthetic remediation' } });
    await userEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.change(within(dialog).getByLabelText('검토된 안전 문서 UUID'), { target: { value: '-'.repeat(36) } });
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(within(dialog).getByRole('alert')).toHaveTextContent('안전 출처');
  });

  it('does not submit an out-of-range Java integer version even on a direct form submit', async () => {
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response(impact)));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: '격리 범위 지정' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText('격리 범위'), 'SOURCE_VERSION');
    fireEvent.change(within(dialog).getByLabelText('문서의 특정 버전 ID (UUID)'), { target: { value: ID } });
    fireEvent.change(within(dialog).getByLabelText('정확한 버전'), { target: { value: '2147483648' } });
    fireEvent.change(within(dialog).getByLabelText('조사 내용'), { target: { value: 'synthetic investigation' } });
    await userEvent.click(within(dialog).getByRole('checkbox'));
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  });

  it('sends only fields for the selected quarantine scope and an integer version', async () => {
    const fetcher = vi.fn().mockImplementation((_url: string, options: RequestInit) =>
      Promise.resolve(
        options.method === 'POST'
          ? response(
              {
                requestId: new Headers(options.headers).get('Idempotency-Key'),
                workflowId: null,
                generation: null,
                decision: 'ALLOW',
                reasonCodes: [],
                message: 'Quarantine applied',
                state: 'ACTIVE',
                replayed: false,
                quarantineId: ID,
                scope: 'AGENT_VERSION',
                target: { agentId: 'kyc-agent', agentVersion: 2 },
              },
              201,
            )
          : response(impact),
      ),
    );
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: '격리 범위 지정' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.selectOptions(within(dialog).getByLabelText('격리 범위'), 'AGENT_VERSION');
    await userEvent.type(within(dialog).getByLabelText('Agent의 특정 버전 ID'), 'kyc-agent');
    await userEvent.clear(within(dialog).getByLabelText('정확한 버전'));
    await userEvent.type(within(dialog).getByLabelText('정확한 버전'), '2');
    await userEvent.type(within(dialog).getByLabelText('조사 내용'), '등록된 버전을 조사함');
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: '선택한 범위 격리' }));
    await waitFor(() => expect(window.location.hash).toBe(`#/quarantine/${ID}`));
    expect(fetcher.mock.calls.filter(([, options]) => options.method === 'POST')).toHaveLength(1);
    const post = fetcher.mock.calls.find(([, options]) => options.method === 'POST')!;
    expect(JSON.parse(post[1].body)).toEqual({
      scope: 'AGENT_VERSION',
      agentId: 'kyc-agent',
      agentVersion: 2,
      reasonCode: 'EVIDENCE_MISSING',
      note: '등록된 버전을 조사함',
    });
  });
  it('keeps actual and potential impact separate and does not invent missing counts', async () => {
    window.location.hash = `/quarantine/${ID}`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => Promise.resolve(response(impact))),
    );
    render(<App />);
    await login();
    expect(await screen.findByRole('heading', { name: '실제 영향' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '정책상 잠재 영향' })).toBeInTheDocument();
    expect(screen.getByText('계산 불가')).toBeInTheDocument();
    expect(screen.getByText('전체 고객 합계가 아닙니다')).toBeInTheDocument();
    expect(screen.queryByText('120')).not.toBeInTheDocument();
  });
  it('release does not send resume or payment and serializes remediation versions as integers', async () => {
    window.location.hash = `/quarantine/${ID}`;
    const fetcher = vi.fn().mockImplementation((_url: string, options: RequestInit) =>
      Promise.resolve(
        options.method === 'POST'
          ? response({
              requestId: new Headers(options.headers).get('Idempotency-Key'),
              workflowId: null,
              generation: null,
              decision: 'ALLOW',
              state: 'RELEASED',
              reasonCodes: [],
              message: 'Quarantine released. A separate explicit resume is required.',
              replayed: false,
              quarantineId: ID,
              scope: 'AGENT_VERSION',
              target: { agentId: 'kyc-agent', agentVersion: 1 },
            })
          : response(impact),
      ),
    );
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(await screen.findByRole('button', { name: '조치 검증 후 격리 해제' }));
    const dialog = screen.getByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText('검토된 안전 문서 UUID'), ID);
    await userEvent.type(within(dialog).getByLabelText('검토된 안전 Agent ID'), 'kyc-agent');
    await userEvent.type(within(dialog).getByLabelText('안전 Agent 버전'), '1');
    await userEvent.type(within(dialog).getByLabelText('원인 제거 및 조치 사유'), '안전한 버전 확인');
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: '검증 후 격리 해제' }));
    await within(dialog).findByRole('button', { name: '영향 업무 확인' });
    const posts = fetcher.mock.calls.filter(([, options]) => options.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe(`/api/v1/quarantines/${ID}/release`);
    expect(JSON.parse(posts[0][1].body)).toEqual({
      remediation: {
        safeDocumentId: ID,
        safeDocumentVersion: 1,
        checkEvidenceIds: [],
        safeAgentId: 'kyc-agent',
        safeAgentVersion: 1,
        note: '안전한 버전 확인',
      },
    });
  });
  it('shows server denominators, paired exclusions, and synthetic replay labeling', async () => {
    window.location.hash = `/experiments/${ID}`;
    const experiment = {
      experimentId: ID,
      status: 'COMPLETED',
      fixtureSetId: 'test-only-fixture',
      modelMode: 'REPLAY',
      progress: { completed: 4, total: 4 },
      caseOutputs: [
        {
          caseId: 'unit-case',
          repeat: 1,
          environment: 'BASELINE',
          status: 'ERROR',
          state: 'ON_HOLD',
          decision: 'ERROR',
          exclusionReason: 'TEST_ENVIRONMENT_ERROR',
        },
        {
          caseId: 'unit-case',
          repeat: 1,
          environment: 'FUSE',
          status: 'COMPLETED',
          state: 'BLOCKED',
          decision: 'DENY',
        },
      ],
      metrics: {
        environments: {
          BASELINE: { eligibleAttackCount: 0, forbiddenActionBlockRate: null },
          FUSE: { eligibleAttackCount: 0, forbiddenActionBlockRate: null },
        },
        excludedPairCount: 1,
        exclusions: [{ pair: 'unit-case:1', reasons: ['TEST_ENVIRONMENT_ERROR'] }],
        syntheticModelOutputs: true,
        liveRobustnessMeasured: false,
      },
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(() => Promise.resolve(response(experiment))),
    );
    render(<App />);
    await login();
    expect(await screen.findByText('4 / 4 환경 실행')).toBeInTheDocument();
    expect(screen.getAllByText('공통 분모 제외')).toHaveLength(2);
    expect(screen.getAllByText('계산되지 않음')).toHaveLength(2);
    expect(screen.getByText('공통 평가 공격 수 (분모)')).toBeInTheDocument();
    expect(screen.getByText(/LIVE 공격 성공률이 아닙니다/)).toBeInTheDocument();
  });
});


describe('release recovery when reopening its exact endpoint', () => {
  it('restores the original uncertain body and UUID before any new form submission', async () => {
    const path = `/quarantines/${ID}/release`;
    const actionId = '00000000-0000-4000-8000-000000000299';
    const body = { remediation: { safeDocumentId: ID, safeDocumentVersion: 1,
      checkEvidenceIds: [], note: 'synthetic retained remediation', safeAgentId: 'kyc-agent', safeAgentVersion: 1 } };
    let postCount = 0;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => {
      if (options?.method !== 'POST') return response(impact);
      postCount += 1;
      if (postCount === 1)
        return response({ decision: 'ERROR', reasonCodes: ['DEPENDENCY_UNAVAILABLE'] }, 503);
      return response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: null,
        generation: null, decision: 'ALLOW', state: 'RELEASED', reasonCodes: [], message: 'Released',
        replayed: true, quarantineId: ID, scope: 'AGENT_VERSION', target: { agentId: 'kyc-agent', agentVersion: 1 } });
    });
    const api = new FuseApi('synthetic-reopened-release', fetcher);
    await expect(api.mutate(path, body, actionId)).rejects.toMatchObject({ uncertain: true });
    const view = render(<QuarantinePage api={api} id={ID} />);
    fireEvent.click(await screen.findByRole('button', { name: '조치 검증 후 격리 해제' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByLabelText('검토된 안전 문서 UUID')).toBeDisabled();
    const retry = within(dialog).getByRole('button', { name: '같은 요청 다시 확인' });
    expect(fetcher.mock.calls.filter(([, init]) => init?.method === 'POST')).toHaveLength(1);
    fireEvent.click(retry);
    await within(dialog).findByRole('button', { name: '영향 업무 확인' });
    const posts = fetcher.mock.calls.filter(([, init]) => init?.method === 'POST');
    expect(posts).toHaveLength(2);
    for (const [url, init] of posts) {
      expect(url).toBe(`/api/v1${path}`);
      expect(init?.body).toBe(JSON.stringify(body));
      expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(actionId);
    }
    expect(api.unresolved(path)).toBeUndefined();
    view.unmount();
  });
});
