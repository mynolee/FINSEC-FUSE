import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { FuseApi } from './api';
import { WorkflowPage } from './components/Workflows';
import type { Workflow } from './types';

const ID = '00000000-0000-4000-8000-000000000102';
const HASH = 'a'.repeat(64);
const workflow: Workflow = {
  workflowId: ID,
  generation: 1,
  customerId: 'customer-102',
  businessReference: 'APP-DEMO-102-001',
  amountKrw: 1000000,
  payoutAccountId: '00000000-0000-4000-8000-000000000102',
  state: 'WAIT_APPROVAL',
  usedRisk: 35,
  reservedRisk: 0,
  riskLimit: 40,
  reasonCodes: ['APPROVAL_REQUIRED'],
  canApprove: true,
  canResume: false,
  activeQuarantines: [],
};
const trace = {
  workflowId: ID,
  generation: 1,
  runs: [],
  results: [],
  grants: [],
  dependencies: [],
  approvals: [],
  riskEvents: [],
  payments: [],
  auditEvents: [],
  sourceUses: [],
  evidenceUses: [],
};
const preview = {
  ...workflow,
  kycResultId: ID,
  loanResultId: ID,
  evidenceBundleHash: 'b'.repeat(64),
  loanResultHash: 'c'.repeat(64),
  policyVersion: 'FUSE-MVP-2',
  riskLimitAfterApproval: 85,
  reviewSnapshotHash: HASH,
};
const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
async function login() {
  await userEvent.type(screen.getByLabelText('개발용 인증 토큰'), 'test-only-token');
  await userEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
}
beforeEach(() => {
  window.location.hash = '/workflows';
  vi.restoreAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});

describe('operator console', () => {
  it('shows no fabricated live records and does not fetch before login', () => {
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    expect(screen.getByRole('heading', { name: '운영 콘솔 연결' })).toBeInTheDocument();
    expect(fetcher).not.toHaveBeenCalled();
    expect(screen.queryByText('1,000,000원')).not.toBeInTheDocument();
  });
  it('rejects a whitespace-only customer even when the native required field is nonempty', async () => {
    const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response({ items: [], total: 0, page: 0, size: 20 })));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: '+ 등록 신청 시작' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('고객 ID'), { target: { value: '   ' } });
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    expect(within(dialog).getByRole('alert')).toHaveTextContent('정수 금액을 확인하세요');
  });

  it.each(['AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', '1-1-1-1-1', '-'.repeat(36)])(
    'does not submit a noncanonical command account UUID: %s', async account => {
      const fetcher = vi.fn().mockImplementation(() => Promise.resolve(response({ items: [], total: 0, page: 0, size: 20 })));
      vi.stubGlobal('fetch', fetcher);
      render(<App />);
      await login();
      await userEvent.click(screen.getByRole('button', { name: '+ 등록 신청 시작' }));
      const dialog = screen.getByRole('dialog');
      fireEvent.change(within(dialog).getByLabelText('고객 소유 Mock 계좌 UUID'), { target: { value: account } });
      fireEvent.submit(dialog.querySelector('form')!);
      expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    },
  );

  it('preserves a canonical synthetic version-zero account in the actual command body', async () => {
    const account = '00000000-0000-0000-0000-000000000001';
    const fetcher = vi.fn().mockImplementation((_url: string, options: RequestInit) => Promise.resolve(
      options?.method === 'POST'
        ? response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: ID,
          generation: 1, state: 'BLOCKED', decision: 'DENY', reasonCodes: [], replayed: false })
        : response({ items: [], total: 0, page: 0, size: 20 }),
    ));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: '+ 등록 신청 시작' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('고객 소유 Mock 계좌 UUID'), { target: { value: account } });
    fireEvent.submit(dialog.querySelector('form')!);
    await waitFor(() => expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1));
    const post = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!;
    expect(JSON.parse(post[1].body as string).payoutAccountId).toBe(account);
  });

  it('requires a fresh approval confirmation after the API subject changes even for the same preview hash', async () => {
    const transport = () => vi.fn<typeof fetch>().mockImplementation(async url =>
      response(String(url).endsWith('/approval-preview') ? preview : String(url).endsWith('/trace') ? trace : workflow));
    const first = transport();
    const second = transport();
    const view = render(<WorkflowPage api={new FuseApi('synthetic-first-subject', first)} id={ID} />);
    await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
    let dialog = screen.getByRole('dialog');
    await within(dialog).findByText(HASH);
    await userEvent.click(within(dialog).getByRole('checkbox'));
    expect(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' })).toBeEnabled();
    view.rerender(<WorkflowPage api={new FuseApi('synthetic-second-subject', second)} id={ID} />);
    dialog = await screen.findByRole('dialog');
    await within(dialog).findByText(HASH);
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(second.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
  });
  it.each(['generation', 'canResume', 'identity'] as const)(
    'blocks the same mounted Resume form after a same-API poll changes %s', async changedField => {
      const scheduledPolls: Array<() => void> = [];
      const realSetTimeout = globalThis.setTimeout.bind(globalThis);
      // Drive the exact callback scheduled by useQuery. Other user-event timers
      // remain real; neither the route key nor the API instance changes.
      vi.spyOn(globalThis, 'setTimeout').mockImplementation(((handler: (...args: unknown[]) => void, timeout?: number, ...args: unknown[]) => {
        if (timeout === 5000 && typeof handler === 'function') {
          scheduledPolls.push(() => handler(...args));
          return 0;
        }
        return realSetTimeout(handler, timeout, ...args);
      }) as typeof setTimeout);
      let currentWorkflow: Workflow = { ...workflow, state: 'ON_HOLD', canApprove: false, canResume: true };
      const fetcher = vi.fn<typeof fetch>().mockImplementation(async url =>
        response(String(url).endsWith('/trace') ? trace : currentWorkflow));
      const api = new FuseApi('synthetic-same-session', fetcher);
      render(<WorkflowPage api={api} id={ID} />);
      await userEvent.click(await screen.findByRole('button', { name: /새 회차로/ }));
      const dialog = screen.getByRole('dialog');
      const reason = within(dialog).getByLabelText('원인 해결 및 재개 사유');
      await userEvent.type(reason, 'synthetic reviewed reason');
      expect(within(dialog).getByRole('button', { name: '서버 검증 후 재개 요청' })).toBeEnabled();
      expect(scheduledPolls.length).toBeGreaterThan(0);
      const initialGets = fetcher.mock.calls.length;
      currentWorkflow = changedField === 'generation'
        ? { ...currentWorkflow, generation: 2 }
        : changedField === 'canResume' ? { ...currentWorkflow, canResume: false }
          : { ...currentWorkflow, workflowId: undefined } as unknown as Workflow;
      const duePolls = scheduledPolls.splice(0);
      await act(async () => { duePolls.forEach(run => run()); });
      await within(dialog).findByText(/세션·업무 회차 또는 재개 가능 상태가 바뀌었습니다/);
      expect(fetcher.mock.calls.length).toBeGreaterThan(initialGets);
      expect(screen.getByRole('dialog')).toBe(dialog);
      expect(within(dialog).getByLabelText('원인 해결 및 재개 사유')).toBe(reason);
      expect(reason).toHaveValue('synthetic reviewed reason');
      expect(within(dialog).getByRole('button', { name: '서버 검증 후 재개 요청' })).toBeDisabled();
      // Direct submit checks the handler, rather than relying only on disabled HTML.
      fireEvent.submit(dialog.querySelector('form')!);
      expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    },
  );

  it('invalidates same-session approval consent when the employee decision changes', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async url =>
      response(String(url).endsWith('/approval-preview') ? preview : String(url).endsWith('/trace') ? trace : workflow));
    const api = new FuseApi('synthetic-decision-session', fetcher);
    render(<WorkflowPage api={api} id={ID} />);
    await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
    const dialog = screen.getByRole('dialog');
    await within(dialog).findByText(HASH);
    const checkbox = within(dialog).getByRole('checkbox');
    await userEvent.click(checkbox);
    expect(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' })).toBeEnabled();
    await userEvent.selectOptions(within(dialog).getByLabelText('직원 판단'), 'REJECT');
    expect(screen.getByRole('dialog')).toBe(dialog);
    expect(checkbox).not.toBeChecked();
    expect(within(dialog).getByRole('button', { name: '직원 거절 제출' })).toBeDisabled();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    await userEvent.click(checkbox);
    expect(within(dialog).getByRole('button', { name: '직원 거절 제출' })).toBeEnabled();
  });

  it('requires fresh consent for a new preview hash after an explicit reload in the same approval modal', async () => {
    let snapshotHash = HASH;
    let postCount = 0;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
      if (options?.method === 'POST') {
        postCount += 1;
        return postCount === 1
          ? response({ reasonCodes: ['REVIEW_CHANGED'] }, 409)
          : response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: ID,
            generation: 1, state: 'APPROVED', decision: 'ALLOW', reasonCodes: [],
            message: 'Synthetic approval accepted; payment remains a separate action.', replayed: false,
            approvalId: ID, extraRiskLimit: 45, riskLimit: 85,
            expiresAt: '2026-10-21T08:10:00Z', payJobId: ID }, 201);
      }
      return response(String(url).endsWith('/approval-preview') ? { ...preview, reviewSnapshotHash: snapshotHash }
        : String(url).endsWith('/trace') ? trace : workflow);
    });
    const api = new FuseApi('synthetic-hash-session', fetcher);
    render(<WorkflowPage api={api} id={ID} />);
    await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
    const dialog = screen.getByRole('dialog');
    await within(dialog).findByText(HASH);
    const comment = within(dialog).getByLabelText('검토 의견');
    await userEvent.type(comment, 'same mounted review');
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' }));
    await within(dialog).findByRole('button', { name: '새 미리보기 확인' });
    snapshotHash = 'd'.repeat(64);
    await userEvent.click(within(dialog).getByRole('button', { name: '새 미리보기 확인' }));
    await within(dialog).findByText(snapshotHash);
    expect(screen.getByRole('dialog')).toBe(dialog);
    expect(within(dialog).getByLabelText('검토 의견')).toBe(comment);
    expect(comment).toHaveValue('same mounted review');
    expect(within(dialog).getByRole('checkbox')).not.toBeChecked();
    fireEvent.submit(dialog.querySelector('form')!);
    expect(postCount).toBe(1);
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' }));
    await waitFor(() => expect(postCount).toBe(2));
    const posts = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(JSON.parse(posts[0][1]!.body as string).reviewSnapshotHash).toBe(HASH);
    expect(JSON.parse(posts[1][1]!.body as string)).toEqual({ decision: 'APPROVE', reviewSnapshotHash: snapshotHash, comment: 'same mounted review' });
    await within(dialog).findByRole('button', { name: '업무 상태 확인' });
    const result = within(dialog).getByRole('status');
    expect(result).toHaveTextContent('직원 승인 완료');
    expect(result).toHaveTextContent('판단: ALLOW');
    expect(result).toHaveTextContent(new Headers(posts[1][1]!.headers).get('Idempotency-Key')!);
    expect(within(dialog).queryByRole('alert')).not.toBeInTheDocument();
    expect(within(dialog).queryByRole('region', { name: '원래 요청 재확인' })).not.toBeInTheDocument();
    expect(api.unresolved(`/workflows/${ID}/approvals`)).toBeUndefined();
  });

  it('keeps the token in memory and shows real API data after connection', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({ items: [workflow], total: 1, page: 0, size: 20 }));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    expect(await screen.findByRole('link', { name: 'customer-102' })).toBeInTheDocument();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
    expect(document.body.textContent).not.toContain('test-only-token');
    await userEvent.click(screen.getByRole('button', { name: '연결 해제' }));
    expect(screen.getByRole('heading', { name: '운영 콘솔 연결' })).toBeInTheDocument();
  });
  it('keeps hash navigation separate from explicit logout before switching tokens', async () => {
    const fetcher = vi
      .fn()
      .mockImplementation(() => Promise.resolve(response({ items: [], total: 0, page: 0, size: 20 })));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    fireEvent.change(screen.getByLabelText('개발용 인증 토큰'), {
      target: { value: 'synthetic-first-role' },
    });
    fireEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
    await screen.findByRole('button', { name: '연결 해제' });
    window.location.hash = '/experiments';
    fireEvent(window, new HashChangeEvent('hashchange'));
    window.location.hash = '';
    fireEvent(window, new HashChangeEvent('hashchange'));
    expect(screen.queryByLabelText('개발용 인증 토큰')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: '연결 해제' }));
    const input = await screen.findByLabelText('개발용 인증 토큰');
    expect(input).toHaveValue('');
    fireEvent.change(input, { target: { value: 'synthetic-second-role' } });
    fireEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
    await waitFor(() =>
      expect(fetcher.mock.lastCall?.[1].headers.Authorization).toBe('Bearer synthetic-second-role'),
    );
    expect([localStorage.length, sessionStorage.length]).toEqual([0, 0]);
  });
  it('displays authentication failure without calling it an attack block', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ reasonCodes: ['UNAUTHENTICATED'] }, 401)));
    render(<App />);
    await login();
    expect(await screen.findByRole('alert')).toHaveTextContent('UNAUTHENTICATED');
    expect(screen.getByText('실시간 업무를 불러오지 못했어요')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'customer-102' })).not.toBeInTheDocument();
  });
  it('hides approval and recovery controls when the server disallows them', async () => {
    window.location.hash = `/workflows/${ID}`;
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockImplementation((url: string) =>
          Promise.resolve(
            url.endsWith('/trace')
              ? response({ reasonCode: 'FORBIDDEN' }, 403)
              : response({ ...workflow, canApprove: false, canResume: false }),
          ),
        ),
    );
    render(<App />);
    await login();
    await screen.findByRole('heading', { name: 'customer-102' });
    expect(screen.queryByRole('button', { name: /정확한 승인 내용 확인/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /새 회차로/ })).not.toBeInTheDocument();
    expect(await screen.findByText(/상세 실행·승인·조사 기록은/)).toBeInTheDocument();
  });
  it('requires review confirmation and posts only the original server snapshot', async () => {
    window.location.hash = `/workflows/${ID}`;
    const fetcher = vi.fn().mockImplementation((url: string, options: RequestInit) =>
      Promise.resolve(
        options.method === 'POST'
          ? response(
              {
                requestId: new Headers(options.headers).get('Idempotency-Key'),
                workflowId: ID,
                generation: 1,
                state: 'APPROVED',
                decision: 'ALLOW',
                reasonCodes: [],
                message: 'Review approved; mock payment is queued.',
                replayed: false,
                approvalId: ID,
                extraRiskLimit: 50,
                riskLimit: 100,
                expiresAt: '2026-10-10T16:00:00Z',
                payJobId: ID,
              },
              201,
            )
          : url.endsWith('/approval-preview')
            ? response(preview)
            : url.endsWith('/trace')
              ? response(trace)
              : response(workflow),
      ),
    );
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByText(HASH);
    const submit = within(dialog).getByRole('button', { name: '정확한 조건으로 승인' });
    expect(submit).toBeDisabled();
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(submit);
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([, options]) => options.method === 'POST')).toBe(true),
    );
    const post = fetcher.mock.calls.find(([, options]) => options.method === 'POST')!;
    expect(JSON.parse(post[1].body)).toEqual({ decision: 'APPROVE', reviewSnapshotHash: HASH, comment: '' });
    expect(post[1].headers['Idempotency-Key']).toMatch(/^[0-9a-f-]{36}$/);
    expect(await within(dialog).findByText(/승인 접수는 지급 완료가 아닙니다/)).toBeInTheDocument();
  });
  it('invalidates approval confirmation on REVIEW_CHANGED', async () => {
    window.location.hash = `/workflows/${ID}`;
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockImplementation((url: string, options: RequestInit) =>
          Promise.resolve(
            options.method === 'POST'
              ? response({ reasonCodes: ['REVIEW_CHANGED'] }, 409)
              : url.endsWith('/approval-preview')
                ? response(preview)
                : url.endsWith('/trace')
                  ? response(trace)
                  : response(workflow),
          ),
        ),
    );
    render(<App />);
    await login();
    await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
    const dialog = await screen.findByRole('dialog');
    await within(dialog).findByText(HASH);
    await userEvent.click(within(dialog).getByRole('checkbox'));
    await userEvent.click(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' }));
    expect(await within(dialog).findByRole('button', { name: '새 미리보기 확인' })).toBeInTheDocument();
    expect(within(dialog).getByRole('button', { name: '정확한 조건으로 승인' })).toBeDisabled();
  });
  it('does not render nonexistent Loan or Payment runs after a blocked KYC', async () => {
    window.location.hash = `/workflows/${ID}`;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) =>
        Promise.resolve(
          url.endsWith('/trace')
            ? response({
                ...trace,
                runs: [
                  {
                    runId: ID,
                    role: 'KYC',
                    status: 'BLOCKED',
                    generation: 1,
                    startedAt: '2026-10-09T04:00:00Z',
                  },
                ],
              })
            : response({
                ...workflow,
                state: 'BLOCKED',
                canApprove: false,
                usedRisk: 10,
                reasonCodes: ['EVIDENCE_MISSING'],
              }),
        ),
      ),
    );
    render(<App />);
    await login();
    await screen.findByRole('heading', { name: 'customer-102' });
    await userEvent.click(screen.getByRole('tab', { name: '실제 의존 관계' }));
    expect(await screen.findByRole('heading', { name: 'KYC' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'LOAN' })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'PAYMENT' })).not.toBeInTheDocument();
  });
  it('canceling a start form sends no mutation', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({ items: [], total: 0, page: 0, size: 20 }));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    await userEvent.click(screen.getByRole('button', { name: /등록 신청 시작/ }));
    const dialog = screen.getByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: '취소' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(fetcher.mock.calls.some(([, options]) => options.method === 'POST')).toBe(false);
  });
  it('rejects malformed deep links without fetching an arbitrary workflow path', async () => {
    window.location.hash = '/workflows/not-a-uuid';
    const fetcher = vi.fn();
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    await login();
    expect(screen.getByRole('alert')).toHaveTextContent('유효한 UUID');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('keeps Browser Back / Forward route changes usable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ items: [], total: 0, page: 0, size: 20 })));
    render(<App />);
    await login();
    fireEvent(window, new HashChangeEvent('hashchange'));
    await userEvent.click(screen.getByRole('link', { name: /비교 실험/ }));
    await waitFor(() => expect(window.location.hash).toBe('#/experiments'));
    fireEvent(window, new HashChangeEvent('hashchange'));
    expect(await screen.findByRole('heading', { name: '비교 실험' })).toBeInTheDocument();
  });
});


describe('explicit workflow command target identity', () => {
  it('keeps an absent-ID detail readable but never starts resume or approval target lookup', async () => {
    const { workflowId: _missing, ...absent } = workflow;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async url => response(
      String(url).endsWith('/trace') ? trace : { ...absent, canResume: true, canApprove: true },
    ));
    const view = render(<WorkflowPage api={new FuseApi('synthetic-missing-id', fetcher)} id={ID} />);
    const resume = await screen.findByRole('button', { name: '새 회차로 명시적 재개' });
    const approval = screen.getByRole('button', { name: /정확한 승인 내용 확인/ });
    expect(resume).toBeDisabled(); expect(approval).toBeDisabled();
    fireEvent.click(resume); fireEvent.click(approval);
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(fetcher.mock.calls.every(([url]) => !String(url).includes('undefined'))).toBe(true);
    expect(fetcher.mock.calls.filter(([url]) => String(url).endsWith('/approval-preview'))).toHaveLength(0);
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
    view.unmount();
  });

  it('submits the existing canonical resume target and exact reason unchanged', async () => {
    const reason = 'synthetic identity-bound recovery';
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
      if (options?.method === 'POST') return response({ requestId: new Headers(options.headers).get('Idempotency-Key'),
        workflowId: ID, generation: 2, state: 'KYC_PENDING', decision: 'ALLOW', reasonCodes: [], message: 'Request accepted', replayed: false });
      return response(String(url).endsWith('/trace') ? trace : { ...workflow, state: 'ON_HOLD', canApprove: false, canResume: true });
    });
    const view = render(<WorkflowPage api={new FuseApi('synthetic-present-id', fetcher)} id={ID} />);
    fireEvent.click(await screen.findByRole('button', { name: '새 회차로 명시적 재개' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('원인 해결 및 재개 사유'), { target: { value: reason } });
    fireEvent.submit(dialog.querySelector('form')!);
    await waitFor(() => expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1));
    const [url, options] = fetcher.mock.calls.find(([, options]) => options?.method === 'POST')!;
    expect(url).toBe(`/api/v1/workflows/${ID}/resume`);
    expect(JSON.parse(String(options?.body))).toEqual({ expectedGeneration: 1, reason });
    view.unmount();
  });
});
