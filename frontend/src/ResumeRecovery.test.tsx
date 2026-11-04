import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { WorkflowPage } from './components/Workflows';

const ID = '00000000-0000-4000-8000-000000000102';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('resume recovery on reopening its exact workflow endpoint', () => {
  it('shows and replays original generation, reason and UUID without editing the new form', async () => {
    const path = `/workflows/${ID}/resume`;
    const actionId = '00000000-0000-4000-8000-000000000299';
    const body = { expectedGeneration: 1, reason: 'synthetic retained recovery reason' };
    const workflow = { workflowId: ID, generation: 1, state: 'ON_HOLD', reasonCodes: [],
      canResume: true, resumeCapability: 'LEGACY_HTTP', canApprove: false, usedRisk: 5, reservedRisk: 0, riskLimit: 40 };
    const trace = { workflowId: ID, generation: 1, runs: [], results: [], grants: [], dependencies: [],
      approvals: [], riskEvents: [], payments: [], auditEvents: [] };
    let posts = 0;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
      if (options?.method !== 'POST') return response(String(url).endsWith('/trace') ? trace : workflow);
      posts += 1;
      if (posts === 1) return response({ decision: 'ERROR', reasonCodes: ['DEPENDENCY_UNAVAILABLE'] }, 503);
      return response({ requestId: new Headers(options.headers).get('Idempotency-Key'), workflowId: ID,
        generation: 2, state: 'KYC_PENDING', decision: 'ALLOW', reasonCodes: [], message: 'Accepted', replayed: true }, 202);
    });
    const api = new FuseApi('synthetic-reopened-resume', fetcher);
    await expect(api.mutate(path, body, actionId)).rejects.toMatchObject({ uncertain: true });
    const view = render(<WorkflowPage api={api} id={ID} />);
    fireEvent.click(await screen.findByRole('button', { name: '새 회차로 명시적 재개' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByLabelText('원인 해결 및 재개 사유')).toHaveValue('');
    expect(within(dialog).getByLabelText('원인 해결 및 재개 사유')).toBeDisabled();
    expect(posts).toBe(1);
    fireEvent.click(within(dialog).getByRole('button', { name: '같은 요청 다시 확인' }));
    await within(dialog).findByRole('button', { name: '현재 상태 확인' });
    const sent = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(sent).toHaveLength(2);
    for (const [url, options] of sent) {
      expect(url).toBe(`/api/v1${path}`);
      expect(options?.body).toBe(JSON.stringify(body));
      expect(new Headers(options?.headers).get('Idempotency-Key')).toBe(actionId);
    }
    expect(api.unresolved(path)).toBeUndefined();
    view.unmount();
  });
});
