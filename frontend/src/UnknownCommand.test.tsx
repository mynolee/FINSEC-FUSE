import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import App from './App';
import { FuseApi } from './api';
import { ExperimentsPage } from './components/Experiments';
import { WorkflowPage } from './components/Workflows';

const ID = '00000000-0000-4000-8000-000000000102';
const NEXT_ID = '00000000-0000-4000-8000-000000000103';
const HASH = 'a'.repeat(64);
const workflow = {
  workflowId: ID,
  generation: 1,
  customerId: 'synthetic-customer',
  businessReference: 'SYNTHETIC',
  amountKrw: 1000000,
  payoutAccountId: ID,
  state: 'WAIT_APPROVAL',
  usedRisk: 35,
  reservedRisk: 0,
  riskLimit: 40,
  reasonCodes: ['APPROVAL_REQUIRED'],
  canApprove: true,
  canResume: false,
  activeQuarantines: [],
};
const preview = {
  ...workflow,
  kycResultId: ID,
  loanResultId: ID,
  evidenceBundleHash: 'b'.repeat(64),
  loanResultHash: 'c'.repeat(64),
  policyVersion: 'synthetic-policy',
  riskLimitAfterApproval: 85,
  reviewSnapshotHash: HASH,
};
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const posts = (fetcher: ReturnType<typeof vi.fn>) =>
  fetcher.mock.calls.filter(([, options]) => options.method === 'POST');
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
function receipt(options: RequestInit, approval = false) {
  return response(
    {
      requestId: new Headers(options.headers).get('Idempotency-Key'),
      workflowId: approval ? ID : null,
      generation: approval ? 1 : null,
      decision: 'ALLOW',
      state: approval ? 'APPROVED' : 'PENDING',
      reasonCodes: [],
      message: 'Synthetic accepted receipt',
      replayed: false,
      ...(approval
        ? {
            approvalId: ID,
            extraRiskLimit: 50,
            riskLimit: 100,
            expiresAt: '2026-10-10T16:00:00Z',
            payJobId: ID,
          }
        : { experimentId: ID, status: 'PENDING', totalRuns: 36 }),
    },
    approval ? 201 : 202,
  );
}
async function openExperiment() {
  await userEvent.click(screen.getByRole('button', { name: '새 실험' }));
  return screen.getByRole('dialog');
}
async function unknownLive(dialog: HTMLElement) {
  await userEvent.selectOptions(within(dialog).getByLabelText('모델 모드'), 'LIVE');
  await userEvent.click(within(dialog).getByRole('checkbox', { name: /외부 모델 전송과 발생 가능한 비용/ }));
  await userEvent.click(
    within(dialog).getByRole('checkbox', { name: '실험 전용 Mock 업무 실행을 요청합니다.' }),
  );
  await userEvent.click(within(dialog).getByRole('button', { name: '비용 확인 후 LIVE 실험 접수' }));
  await within(dialog).findByRole('button', { name: '같은 요청 다시 확인' });
}
async function openApproval(recovery = false) {
  await userEvent.click(await screen.findByRole('button', { name: /정확한 승인 내용 확인/ }));
  const dialog = screen.getByRole('dialog');
  await within(dialog).findByRole(recovery ? 'region' : 'combobox');
  return dialog;
}
const recovery = (dialog: HTMLElement) => within(dialog).getByRole('region', { name: '원래 요청 재확인' });
const close = (dialog: HTMLElement) =>
  userEvent.click(within(dialog).getByLabelText('닫기', { selector: 'button' }));
const approvalFetcher = (snapshot = () => HASH) =>
  vi.fn().mockImplementation((url: string, options: RequestInit) => {
    if (options.method === 'POST') return Promise.reject(new TypeError('synthetic response loss'));
    const id = url.includes(NEXT_ID) ? NEXT_ID : ID;
    return Promise.resolve(
      response(
        url.endsWith('/approval-preview')
          ? { ...preview, workflowId: id, reviewSnapshotHash: snapshot() }
          : { ...workflow, workflowId: id },
      ),
    );
  });

describe('unknown command intent, injected offline transport only', () => {
  it('reopens the exact LIVE intent without a conflicting REPLAY form, and keeps it through retry', async () => {
    const pending = deferred<Response>();
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('synthetic response loss'))
      .mockReturnValueOnce(pending.promise);
    render(<ExperimentsPage api={new FuseApi('synthetic', fetcher)} />);
    const first = await openExperiment();
    await unknownLive(first);
    const originalPost = posts(fetcher)[0][1];
    const originalBody = JSON.parse(originalPost.body);
    expect(recovery(first)).toHaveTextContent('LIVE');
    expect(within(first).queryByLabelText('모델 모드')).not.toBeInTheDocument();
    await close(first);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    const reopened = await openExperiment();
    expect(posts(fetcher)).toHaveLength(1);
    expect(within(reopened).queryByLabelText('모델 모드')).not.toBeInTheDocument();
    expect(
      within(reopened).queryByText(/이 실험을 위한 외부 모델 호출을 요청하지 않습니다/),
    ).not.toBeInTheDocument();
    const panel = recovery(reopened);
    expect(panel).toHaveTextContent('LIVE');
    expect(panel).toHaveTextContent('mvp-security-v1');
    expect(panel).toHaveTextContent('외부 모델 전송과 비용');
    expect(panel).toHaveTextContent('처음 접수·실행될 수 있어요');
    expect(panel).toHaveTextContent(originalPost.headers['Idempotency-Key']);
    expect(JSON.parse(panel.querySelector('pre')!.textContent!)).toEqual(originalBody);
    await userEvent.click(within(panel).getByRole('button', { name: '같은 요청 다시 확인' }));
    expect(recovery(reopened)).toHaveTextContent('LIVE');
    expect(within(reopened).queryByLabelText('모델 모드')).not.toBeInTheDocument();
    expect(within(reopened).getByLabelText('닫기', { selector: 'button' })).toBeDisabled();
    expect(within(panel).getByRole('button')).toBeDisabled();
    fireEvent(reopened, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(posts(fetcher)).toHaveLength(2);
    expect(posts(fetcher)[1][1].body).toBe(originalPost.body);
    expect(posts(fetcher)[1][1].headers['Idempotency-Key']).toBe(originalPost.headers['Idempotency-Key']);
    await act(async () => pending.resolve(receipt(posts(fetcher)[1][1])));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it.each(['APPROVE', 'REJECT'])(
    'reopens the original %s, comment and snapshot rather than a fresh preview',
    async (decision) => {
      let hash = HASH;
      const fetcher = approvalFetcher(() => hash);
      render(<WorkflowPage api={new FuseApi('synthetic', fetcher)} id={ID} />);
      const first = await openApproval();
      await userEvent.selectOptions(within(first).getByLabelText('직원 판단'), decision);
      await userEvent.type(within(first).getByLabelText('검토 의견'), 'original review');
      await userEvent.click(within(first).getByRole('checkbox'));
      await userEvent.click(
        within(first).getByRole('button', {
          name: decision === 'APPROVE' ? '정확한 조건으로 승인' : '직원 거절 제출',
        }),
      );
      await within(first).findByRole('region');
      await close(first);
      hash = 'd'.repeat(64);
      const reopened = await openApproval(true);
      expect(within(reopened).queryByLabelText('직원 판단')).not.toBeInTheDocument();
      expect(within(reopened).queryByText(hash)).not.toBeInTheDocument();
      expect(recovery(reopened)).toHaveTextContent(decision);
      expect(recovery(reopened)).toHaveTextContent(HASH);
      expect(recovery(reopened)).toHaveTextContent('original review');
      expect(recovery(reopened)).toHaveTextContent(`/workflows/${ID}/approvals`);
      expect(recovery(reopened)).toHaveTextContent('처음 접수·실행될 수 있어요');
      await userEvent.click(within(reopened).getByRole('button', { name: '같은 요청 다시 확인' }));
      expect(posts(fetcher)).toHaveLength(2);
      expect(JSON.parse(posts(fetcher)[1][1].body)).toEqual({
        decision,
        reviewSnapshotHash: HASH,
        comment: 'original review',
      });
      expect(posts(fetcher)[1][1].body).toBe(posts(fetcher)[0][1].body);
      expect(posts(fetcher)[1][1].headers['Idempotency-Key']).toBe(
        posts(fetcher)[0][1].headers['Idempotency-Key'],
      );
      fireEvent(reopened, new Event('cancel', { bubbles: true, cancelable: true }));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      const again = await openApproval(true);
      expect(recovery(again)).toHaveTextContent(decision);
      expect(posts(fetcher)).toHaveLength(2);
    },
  );

  it('shows only the verified receipt after approval recovery, without a fresh conflicting preview', async () => {
    let hash = HASH;
    let attempts = 0;
    const fetcher = vi.fn().mockImplementation((url: string, options: RequestInit) => {
      if (options.method === 'POST') {
        attempts += 1;
        return attempts === 1
          ? Promise.reject(new TypeError('synthetic loss'))
          : Promise.resolve(receipt(options, true));
      }
      return Promise.resolve(
        response(url.endsWith('/approval-preview') ? { ...preview, reviewSnapshotHash: hash } : workflow),
      );
    });
    render(<WorkflowPage api={new FuseApi('synthetic', fetcher)} id={ID} />);
    const first = await openApproval();
    await userEvent.click(within(first).getByRole('checkbox'));
    await userEvent.click(within(first).getByRole('button', { name: '정확한 조건으로 승인' }));
    await within(first).findByRole('region');
    await close(first);
    hash = 'd'.repeat(64);
    const reopened = await openApproval(true);
    await userEvent.click(within(reopened).getByRole('button', { name: '같은 요청 다시 확인' }));
    expect(await within(reopened).findByRole('status')).toHaveTextContent('Synthetic accepted receipt');
    expect(within(reopened).queryByLabelText('직원 판단')).not.toBeInTheDocument();
    expect(within(reopened).queryByText(hash)).not.toBeInTheDocument();
    expect(within(reopened).queryByRole('region', { name: '원래 요청 재확인' })).not.toBeInTheDocument();
    expect(reopened).toHaveTextContent('승인 접수는 지급 완료가 아닙니다');
    expect(posts(fetcher)).toHaveLength(2);
    expect(posts(fetcher)[1][1].body).toBe(posts(fetcher)[0][1].body);
    expect(posts(fetcher)[1][1].headers['Idempotency-Key']).toBe(
      posts(fetcher)[0][1].headers['Idempotency-Key'],
    );
  });

  it('keeps unknown approval recovery within its workflow scope across navigation', async () => {
    const fetcher = approvalFetcher();
    const api = new FuseApi('synthetic', fetcher);
    const page = render(<WorkflowPage api={api} id={ID} />);
    const first = await openApproval();
    await userEvent.click(within(first).getByRole('checkbox'));
    await userEvent.click(within(first).getByRole('button', { name: '정확한 조건으로 승인' }));
    await within(first).findByRole('region');
    page.rerender(<WorkflowPage api={api} id={NEXT_ID} />);
    const other = await openApproval();
    expect(within(other).queryByRole('region', { name: '원래 요청 재확인' })).not.toBeInTheDocument();
    expect(within(other).getByLabelText('직원 판단')).toHaveValue('APPROVE');
    expect(posts(fetcher)).toHaveLength(1);
    page.rerender(<WorkflowPage api={api} id={ID} />);
    expect(recovery(await openApproval(true))).toHaveTextContent(`/workflows/${ID}/approvals`);
    expect(posts(fetcher)).toHaveLength(1);
  });

  it('drops the prior session recovery view on explicit logout and reconnect', async () => {
    window.location.hash = '/experiments';
    const fetcher = vi.fn().mockRejectedValue(new TypeError('synthetic response loss'));
    vi.stubGlobal('fetch', fetcher);
    render(<App />);
    async function login(token: string) {
      await userEvent.type(screen.getByLabelText('개발용 인증 토큰'), token);
      await userEvent.click(screen.getByRole('button', { name: /연결하고 업무 조회/ }));
    }
    await login('synthetic-first-session');
    const first = await openExperiment();
    await unknownLive(first);
    const oldKey = posts(fetcher)[0][1].headers['Idempotency-Key'];
    await close(first);
    await userEvent.click(screen.getByRole('button', { name: '연결 해제' }));
    await login('synthetic-second-session');
    await userEvent.click(screen.getByRole('link', { name: /비교 실험/ }));
    await screen.findByRole('button', { name: '새 실험' });
    const second = await openExperiment();
    expect(within(second).queryByRole('region', { name: '원래 요청 재확인' })).not.toBeInTheDocument();
    expect(second).not.toHaveTextContent(oldKey);
    expect(within(second).getByLabelText('모델 모드')).toHaveValue('REPLAY');
    expect(posts(fetcher)).toHaveLength(1);
    expect([localStorage.length, sessionStorage.length]).toEqual([0, 0]);
    vi.unstubAllGlobals();
  });
});
