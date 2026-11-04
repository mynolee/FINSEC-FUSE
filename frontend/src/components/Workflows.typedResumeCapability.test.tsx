import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from '../api';
import type { Workflow } from '../types';
import { WorkflowPage } from './Workflows';

const ID = '00000000-0000-4000-8000-000000000871';
const base = (): Workflow => ({ workflowId: ID, generation: 2, state: 'BLOCKED', customerId: 'synthetic-customer',
  usedRisk: 2, reservedRisk: 0, riskLimit: 20, canResume: true, canApprove: false,
  reasonCodes: [], activeQuarantines: ['synthetic-old-run-hold'] });
const trace = { workflowId: ID, generation: 2, runs: [], results: [], grants: [], dependencies: [],
  approvals: [], riskEvents: [], payments: [], auditEvents: [] };
function setup(initial: Workflow) {
  let current = initial;
  const api = new FuseApi('synthetic-resume-capability', vi.fn());
  vi.spyOn(api, 'workflow').mockImplementation(async () => current);
  vi.spyOn(api, 'trace').mockResolvedValue(trace);
  const mutate = vi.spyOn(api, 'mutate').mockResolvedValue({ workflowId: ID, generation: 3, state: 'KYC_PENDING' });
  const view = render(<WorkflowPage api={api} id={ID} />);
  return { ...view, api, mutate, setCurrent(next: Workflow) { current = next; } };
}
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe('public resume capability is separate from prospective readiness', () => {
  it.each(['TYPED_READINESS_ONLY', undefined, 'LIVE', true, { raw: 'synthetic-hidden' }])(
    'offers no public legacy mutation for readiness with unsupported capability %j', async capability => {
      const workflow = { ...base(), resumeCapability: capability };
      const { mutate, container } = setup(workflow);
      await screen.findByRole('button', { name: '업무 상세 새로고침' });
      await screen.findByText(capability === 'TYPED_READINESS_ONLY'
        ? '다음 세대 재개 조건은 충족됐지만 이 화면의 재개 명령은 지원되지 않습니다.'
        : '재개 명령 지원 여부가 확인되지 않았습니다.');
      expect(screen.queryByRole('button', { name: '새 회차로 명시적 재개' })).not.toBeInTheDocument();
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(mutate).not.toHaveBeenCalled(); expect(workflow.canResume).toBe(true);
      expect(workflow.activeQuarantines).toEqual(['synthetic-old-run-hold']);
      expect(container.textContent).not.toContain('synthetic-hidden');
    });

  it('retains the exact legacy route and reviewed body only with explicit command capability', async () => {
    const { mutate } = setup({ ...base(), resumeCapability: 'LEGACY_HTTP' });
    fireEvent.click(await screen.findByRole('button', { name: '새 회차로 명시적 재개' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText('원인 해결 및 재개 사유'), { target: { value: 'synthetic resolved cause' } });
    fireEvent.click(within(dialog).getByRole('button', { name: '서버 검증 후 재개 요청' }));
    await waitFor(() => expect(mutate).toHaveBeenCalledTimes(1));
    expect(mutate).toHaveBeenCalledWith(`/workflows/${ID}/resume`,
      { expectedGeneration: 2, reason: 'synthetic resolved cause' }, expect.any(String));
  });

  it.each(['TYPED_READINESS_ONLY', undefined, 'unsupported'])(
    'blocks an already open reviewed dialog after capability becomes %s', async capability => {
      const { mutate, setCurrent } = setup({ ...base(), resumeCapability: 'LEGACY_HTTP' });
      fireEvent.click(await screen.findByRole('button', { name: '새 회차로 명시적 재개' }));
      const dialog = screen.getByRole('dialog');
      fireEvent.change(within(dialog).getByLabelText('원인 해결 및 재개 사유'), { target: { value: 'synthetic retained reason' } });
      setCurrent({ ...base(), resumeCapability: capability });
      fireEvent.click(screen.getByRole('button', { name: '업무 상세 새로고침' }));
      await within(dialog).findByText('세션·업무 회차 또는 재개 가능 상태가 바뀌었습니다. 닫고 현재 업무를 다시 확인하세요.');
      expect(within(dialog).getByLabelText('원인 해결 및 재개 사유')).toBeDisabled();
      fireEvent.submit(dialog.querySelector('form')!);
      expect(mutate).not.toHaveBeenCalled();
      expect(within(dialog).queryByRole('button', { name: '같은 요청 다시 확인' })).not.toBeInTheDocument();
    });

  it('does not invoke a capability accessor or inherit a command-capability value', async () => {
    let calls = 0;
    const workflow = base();
    Object.defineProperty(workflow, 'resumeCapability', { get() { calls += 1; return 'LEGACY_HTTP'; } });
    const view = setup(workflow);
    await screen.findByText('재개 명령 지원 여부가 확인되지 않았습니다.');
    expect(calls).toBe(0); expect(view.mutate).not.toHaveBeenCalled(); view.unmount();
    const inherited = Object.assign(Object.create({ resumeCapability: 'LEGACY_HTTP' }), base());
    const second = setup(inherited);
    await screen.findByText('재개 명령 지원 여부가 확인되지 않았습니다.');
    expect(screen.queryByRole('button', { name: '새 회차로 명시적 재개' })).not.toBeInTheDocument();
    expect(second.mutate).not.toHaveBeenCalled();
  });

  it('hides a real retained 503 retry after capability changes without discarding original bytes or UUID', async () => {
    const path = `/workflows/${ID}/resume`;
    const actionId = '00000000-0000-4000-8000-000000000872';
    const original = { expectedGeneration: 2, reason: 'synthetic original unresolved cause' };
    let current: Workflow = { ...base(), resumeCapability: 'LEGACY_HTTP' };
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
      const body = options?.method === 'POST'
        ? { decision: 'ERROR', reasonCodes: ['DEPENDENCY_UNAVAILABLE'] }
        : String(url).endsWith('/trace') ? trace : current;
      return new Response(JSON.stringify(body), { status: options?.method === 'POST' ? 503 : 200,
        headers: { 'Content-Type': 'application/json' } });
    });
    const api = new FuseApi('synthetic-retained-capability', fetcher);
    await expect(api.mutate(path, original, actionId)).rejects.toMatchObject({ uncertain: true });
    expect(api.unresolved(path)).toEqual({ path, body: original, actionId });
    render(<WorkflowPage api={api} id={ID} />);
    fireEvent.click(await screen.findByRole('button', { name: '새 회차로 명시적 재개' }));
    const dialog = screen.getByRole('dialog');
    expect(await within(dialog).findByRole('button', { name: '같은 요청 다시 확인' })).toBeEnabled();
    expect(within(dialog).getByLabelText('원인 해결 및 재개 사유')).toBeDisabled();
    current = { ...base(), resumeCapability: 'TYPED_READINESS_ONLY' };
    fireEvent.click(screen.getByRole('button', { name: '업무 상세 새로고침' }));
    await within(dialog).findByText('세션·업무 회차 또는 재개 가능 상태가 바뀌었습니다. 닫고 현재 업무를 다시 확인하세요.');
    expect(within(dialog).queryByRole('button', { name: '같은 요청 다시 확인' })).not.toBeInTheDocument();
    fireEvent.submit(dialog.querySelector('form')!);
    const posts = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0][0]).toBe(`/api/v1${path}`);
    expect(posts[0][1]?.body).toBe(JSON.stringify(original));
    expect(new Headers(posts[0][1]?.headers).get('Idempotency-Key')).toBe(actionId);
    expect(api.unresolved(path)).toEqual({ path, body: original, actionId });
  });
});
