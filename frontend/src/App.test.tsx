import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
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
