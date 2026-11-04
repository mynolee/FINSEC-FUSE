import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, FuseApi } from './api';
import { CancelExperiment } from './components/CancelExperiment';
import { ExperimentsPage } from './components/Experiments';

const ID = '00000000-0000-0000-0000-000000000301';
const NEXT = '00000000-0000-0000-0000-000000000302';
const response = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });
const receipt = (options?: RequestInit, extra = {}) => ({
  requestId: new Headers(options?.headers).get('Idempotency-Key'), experimentId: ID,
  status: 'CANCELLED', completedPairs: 2, replayed: false, resultsSource: 'VIRTUAL_SIMULATION', ...extra,
});
afterEach(() => { vi.restoreAllMocks(); });

describe('virtual experiment cancellation boundary, synthetic requests only', () => {
  it('sends only the empty body and accepts a terminal no-op receipt without inventing ALLOW fields', async () => {
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => response(receipt(options, { status: 'COMPLETED' })));
    const api = new FuseApi('synthetic-session', fetcher);
    const result = await api.cancelExperiment(ID);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe(`/api/v1/experiments/${ID}/cancel`);
    expect(fetcher.mock.calls[0][1]?.body).toBe('{}');
    expect(result).toMatchObject({ status: 'COMPLETED', completedPairs: 2 });
    expect(result).not.toHaveProperty('decision');
    expect(result).not.toHaveProperty('state');
    expect(api.unresolvedExperimentCancel(ID)).toBeUndefined();
  });

  it('rejects mismatched, nonterminal or open receipts as uncertain without leaking raw fields', async () => {
    for (const extra of [{ experimentId: NEXT }, { status: 'RUNNING' }, { completedPairs: -1 },
      { completedPairs: 1.5 }, { replayed: 'false' }, { message: 'PRIVATE_CANCEL_MARKER' }]) {
      const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => response(receipt(options, extra)));
      const api = new FuseApi('synthetic-session', fetcher);
      await expect(api.cancelExperiment(ID)).rejects.toMatchObject({ uncertain: true, reasonCodes: ['INVALID_RESPONSE'] });
      expect(api.unresolvedExperimentCancel(ID)).toBeTruthy();
    }
  });

  it('shares an active send and preserves the original UUID across unknown outcome and later 403', async () => {
    let reject!: (reason: unknown) => void;
    const pending = new Promise<Response>((_resolve, rejectPromise) => { reject = rejectPromise; });
    const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(() => pending)
      .mockResolvedValueOnce(response({}, 403))
      .mockImplementationOnce(async (_url, options) => response(receipt(options, { replayed: true })));
    const api = new FuseApi('synthetic-session', fetcher);
    const first = api.cancelExperiment(ID); const shared = api.cancelExperiment(ID);
    const firstCheck = expect(first).rejects.toBeInstanceOf(ApiError);
    const sharedCheck = expect(shared).rejects.toBeInstanceOf(ApiError);
    reject(new Error('PRIVATE_NETWORK_REASON'));
    await Promise.all([firstCheck, sharedCheck]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const original = api.unresolvedExperimentCancel(ID);
    await expect(api.cancelExperiment(ID)).rejects.toMatchObject({ status: 403 });
    expect(api.unresolvedExperimentCancel(ID)).toBe(original);
    expect((await api.cancelExperiment(ID)).replayed).toBe(true);
    expect(fetcher.mock.calls.every(([, options]) => new Headers(options?.headers).get('Idempotency-Key') === original && options?.body === '{}')).toBe(true);
    expect(api.unresolvedExperimentCancel(ID)).toBeUndefined();
  });

  it('does not retain a first definitive ownership denial or use the general workflow receipt path', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response({}, 403));
    const api = new FuseApi('synthetic-session', fetcher);
    await expect(api.cancelExperiment(ID)).rejects.toMatchObject({ status: 403, uncertain: false });
    expect(api.unresolvedExperimentCancel(ID)).toBeUndefined();
    await expect(api.mutate(`/experiments/${ID}/cancel`, {}, crypto.randomUUID())).rejects.toMatchObject({ reasonCodes: ['INVALID_REQUEST'] });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('requests cancellation once and reloads preserved results without claiming provider termination', async () => {
    let cancelled = false;
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) => {
      if (options?.method === 'POST') { cancelled = true; return response(receipt(options)); }
      return response({ experimentId: ID, status: cancelled ? 'CANCELLED' : 'RUNNING',
        resultsSource: 'VIRTUAL_SIMULATION', modelMode: 'REPLAY', completedPairs: 2, caseOutputs: [] });
    });
    // Page lookup currently uses its existing versioned UUID display policy.
    const pageId = '00000000-0000-4000-8000-000000000301';
    const pageFetch = vi.fn<typeof fetch>().mockImplementation(async (url, options) => {
      const res = await fetcher(url, options); const body = await res.json();
      return response({ ...body, experimentId: pageId });
    });
    render(<ExperimentsPage api={new FuseApi('synthetic-page-session', pageFetch)} id={pageId} />);
    fireEvent.click(await screen.findByRole('button', { name: '실험 취소 요청' }));
    const modal = screen.getByRole('dialog');
    expect(within(modal).getByText(/제공자의 종료를 보장하지 않습니다/)).toBeVisible();
    fireEvent.click(within(modal).getByRole('button', { name: '이 실험 취소 요청' }));
    await waitFor(() => expect(within(modal).getByRole('status')).toHaveTextContent('처리 상태: CANCELLED · 보존된 비교 쌍: 2'));
    expect(pageFetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(await screen.findByText('전체 실험이 성공적으로 끝나지 않았습니다. 중간 결과를 전체 성공으로 해석하지 마세요.')).toBeVisible();
  });

  it('keeps the current ownership denial visible after clearing experiment data', async () => {
    const pageId = '00000000-0000-4000-8000-000000000301';
    const fetcher = vi.fn<typeof fetch>().mockImplementation(async (_url, options) =>
      options?.method === 'POST' ? response({}, 403) : response({ experimentId: pageId,
        status: 'RUNNING', resultsSource: 'VIRTUAL_SIMULATION', modelMode: 'REPLAY', caseOutputs: [] }));
    render(<ExperimentsPage api={new FuseApi('synthetic-denied-session', fetcher)} id={pageId} />);
    fireEvent.click(await screen.findByRole('button', { name: '실험 취소 요청' }));
    fireEvent.click(screen.getByRole('button', { name: '이 실험 취소 요청' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('현재 인증 주체에게 이 작업의 권한이 없어요.');
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByText('실험 실행 상태')).toBeNull();
  });

  it('does not deliver an old cancellation receipt to a newly selected session/experiment', async () => {
    let finish!: (value: Response) => void; let oldOptions: RequestInit | undefined;
    const oldFetch = vi.fn<typeof fetch>().mockImplementation((_url, options) => {
      oldOptions = options; return new Promise(resolve => { finish = resolve; });
    });
    const oldComplete = vi.fn(); const newComplete = vi.fn(); const denied = vi.fn();
    const view = render(<CancelExperiment api={new FuseApi('old-session', oldFetch)} id={ID} active onComplete={oldComplete} onDenied={denied} />);
    fireEvent.click(screen.getByRole('button', { name: '실험 취소 요청' }));
    fireEvent.click(screen.getByRole('button', { name: '이 실험 취소 요청' }));
    view.rerender(<CancelExperiment api={new FuseApi('new-session', vi.fn<typeof fetch>())} id={NEXT} active onComplete={newComplete} onDenied={denied} />);
    await act(async () => { finish(response(receipt(oldOptions))); });
    expect(oldComplete).not.toHaveBeenCalled(); expect(newComplete).not.toHaveBeenCalled();
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.getByRole('button', { name: '실험 취소 요청' })).toBeEnabled();
  });
});


describe('same-session cancellation request ownership', () => {
  it('keeps a newer target pending when an old target settles, then accepts only its own receipt', async () => {
    const pending: { id: string; options?: RequestInit; finish: (value: Response) => void }[] = [];
    const fetcher = vi.fn<typeof fetch>().mockImplementation((url, options) => new Promise(resolve => {
      pending.push({ id: String(url).includes(NEXT) ? NEXT : ID, options, finish: resolve });
    }));
    const api = new FuseApi('same-session-two-targets', fetcher);
    const completed = vi.fn(); const denied = vi.fn();
    const view = render(<CancelExperiment api={api} id={ID} active onComplete={completed} onDenied={denied} />);
    fireEvent.click(screen.getByRole('button', { name: '실험 취소 요청' }));
    fireEvent.click(screen.getByRole('button', { name: '이 실험 취소 요청' }));
    view.rerender(<CancelExperiment api={api} id={NEXT} active onComplete={completed} onDenied={denied} />);
    fireEvent.click(screen.getByRole('button', { name: '실험 취소 요청' }));
    const submit = screen.getByRole('button', { name: '이 실험 취소 요청' });
    fireEvent.click(submit); fireEvent.click(submit);
    expect(fetcher).toHaveBeenCalledTimes(2);
    await act(async () => { pending[0].finish(response(receipt(pending[0].options))); });
    expect(completed).not.toHaveBeenCalled(); expect(denied).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: '처리 중' })).toBeDisabled();
    expect(screen.queryByRole('status')).toBeNull();
    await act(async () => { pending[1].finish(response(receipt(pending[1].options, { experimentId: NEXT, completedPairs: 1 }))); });
    expect(completed).toHaveBeenCalledTimes(1);
    expect(within(screen.getByRole('dialog')).getByRole('status')).toHaveTextContent('보존된 비교 쌍: 1');
    view.unmount();
  });
});
