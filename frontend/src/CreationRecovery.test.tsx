import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { WorkflowPage } from './components/Workflows';
import { QuarantinePage } from './components/Quarantine';

const ID = '00000000-0000-4000-8000-000000000102';
const ACTION = '00000000-0000-4000-8000-000000000299';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

describe('creation endpoint unresolved recovery', () => {
  it.each(['workflow', 'quarantine'] as const)('restores the original %s creation request on a fresh modal', async operation => {
    const path = operation === 'workflow' ? '/workflows' : '/quarantines';
    const body = operation === 'workflow'
      ? { businessReference: 'synthetic-original-application', customerId: 'customer-102', amountKrw: 1000000, payoutAccountId: ID }
      : { scope: 'RUN', runId: ID, reasonCode: 'EVIDENCE_MISSING', note: 'synthetic original containment' };
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) =>
      options?.method === 'POST'
        ? response({ decision: 'ERROR', reasonCodes: ['DEPENDENCY_UNAVAILABLE'] }, 503)
        : response({ items: [], total: 0, page: 0, size: 20 }));
    const api = new FuseApi('synthetic-reopen-' + operation, fetcher);
    await expect(api.mutate(path, body, ACTION)).rejects.toMatchObject({ uncertain: true });
    const view = render(operation === 'workflow' ? <WorkflowPage api={api} /> : <QuarantinePage api={api} />);
    fireEvent.click(await screen.findByRole('button', { name: operation === 'workflow' ? /등록 신청 시작/ : '격리 범위 지정' }));
    const dialog = screen.getByRole('dialog');
    expect(dialog.querySelector('fieldset')).toBeDisabled();
    expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    fireEvent.click(within(dialog).getByRole('button', { name: '같은 요청 다시 확인' }));
    await waitFor(() => expect(fetcher.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(2));
    const posts = fetcher.mock.calls.filter(([, options]) => options?.method === 'POST');
    for (const [url, options] of posts) {
      expect(url).toBe(`/api/v1${path}`);
      expect(options?.body).toBe(JSON.stringify(body));
      expect(new Headers(options?.headers).get('Idempotency-Key')).toBe(ACTION);
    }
    expect(api.unresolved(path)).toMatchObject({ path, actionId: ACTION, body });
    view.unmount();
  });
});
