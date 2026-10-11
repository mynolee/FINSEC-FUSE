import { act, renderHook, waitFor } from '@testing-library/react';
import { useCallback } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, FuseApi } from './api';
import { useCommand, useQuery } from './hooks';

const WORKFLOW_ID = '00000000-0000-4000-8000-000000000102';
const NEXT_ID = '00000000-0000-4000-8000-000000000002';
function actionResponse(options: RequestInit, approval = false, overrides: Record<string, unknown> = {}) {
  return new Response(
    JSON.stringify({
      requestId: new Headers(options.headers).get('Idempotency-Key'),
      workflowId: WORKFLOW_ID,
      generation: 1,
      state: approval ? 'APPROVED' : 'KYC_PENDING',
      decision: 'ALLOW',
      reasonCodes: [],
      message: 'Request accepted',
      replayed: false,
      ...(approval
        ? {
            approvalId: NEXT_ID,
            extraRiskLimit: 50,
            riskLimit: 100,
            expiresAt: '2026-10-10T16:00:00Z',
            payJobId: NEXT_ID,
          }
        : {}),
      ...overrides,
    }),
    { status: approval ? 201 : 202 },
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
describe('safe request lifecycle', () => {
  it('ignores repeated clicks while a mutation is in flight', async () => {
    const task = deferred<Response>();
    const fetcher = vi.fn().mockReturnValue(task.promise);
    const { result } = renderHook(() => useCommand(new FuseApi('token', fetcher)));
    act(() => {
      void result.current.run('/workflows', { x: 1 });
      void result.current.run('/workflows', { x: 1 });
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => {
      task.resolve(actionResponse(fetcher.mock.calls[0][1]));
    });
    expect(result.current.pending).toBe(false);
  });
  it('retries an uncertain outcome with the exact same body and key', async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('lost'))
      .mockImplementationOnce((_url, options) =>
        Promise.resolve(actionResponse(options, true, { replayed: true })),
      );
    const api = new FuseApi('token', fetcher);
    const { result } = renderHook(() => useCommand(api));
    await act(async () => {
      await result.current.run(`/workflows/${WORKFLOW_ID}/approvals`, { reviewSnapshotHash: 'a'.repeat(64) });
    });
    expect(result.current.retryable).toBe(true);
    await act(async () => {
      await result.current.retry();
    });
    expect(fetcher.mock.calls[0][1].body).toBe(fetcher.mock.calls[1][1].body);
    expect(fetcher.mock.calls[0][1].headers['Idempotency-Key']).toBe(
      fetcher.mock.calls[1][1].headers['Idempotency-Key'],
    );
  });
  it('will not report acceptance before a real server response', async () => {
    const task = deferred<Response>();
    const fetcher = vi.fn().mockReturnValue(task.promise);
    const api = new FuseApi('token', fetcher);
    const { result } = renderHook(() => useCommand(api));
    act(() => {
      void result.current.run('/workflows', {});
    });
    expect(result.current.result).toBeUndefined();
    expect(result.current.pending).toBe(true);
    await act(async () => {
      task.resolve(actionResponse(fetcher.mock.calls[0][1]));
    });
    expect(result.current.result?.state).toBe('KYC_PENDING');
  });
  it('does not overwrite new navigation with a late old response', async () => {
    const old = deferred<string>();
    const newer = deferred<string>();
    const { result, rerender } = renderHook(
      ({ id }) => useQuery(useCallback(() => (id === 'old' ? old.promise : newer.promise), [id])),
      { initialProps: { id: 'old' } },
    );
    rerender({ id: 'new' });
    await act(async () => {
      newer.resolve('new record');
    });
    await act(async () => {
      old.resolve('old record');
    });
    expect(result.current.data).toBe('new record');
  });
  it('keeps the last record visibly stale after a failed refresh', async () => {
    const load = vi
      .fn()
      .mockResolvedValueOnce('last server record')
      .mockRejectedValueOnce(new ApiError('offline', 0));
    const { result } = renderHook(() => useQuery(load));
    await waitFor(() => expect(result.current.data).toBe('last server record'));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.error).toBeInstanceOf(ApiError));
    expect(result.current.data).toBe('last server record');
  });
});

describe('v2.1 revoked scope and uncertain reset', () => {
  it.each([401, 403, 404])('removes cached records after HTTP %s', async (status) => {
    const load = vi
      .fn()
      .mockResolvedValueOnce('private record')
      .mockRejectedValueOnce(new ApiError('denied', status));
    const { result } = renderHook(() => useQuery(load));
    await waitFor(() => expect(result.current.data).toBe('private record'));
    act(() => result.current.reload());
    await waitFor(() => expect(result.current.error).toBeInstanceOf(ApiError));
    expect(result.current.data).toBeUndefined();
    expect(result.current.updatedAt).toBeUndefined();
  });
  it('does not reset an unknown commit or replace its original input', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ state: null, decision: 'ERROR' }), { status: 503 }),
      )
      .mockImplementationOnce((_url, options) =>
        Promise.resolve(actionResponse(options, true, { replayed: true })),
      );
    const api = new FuseApi('synthetic', fetcher);
    const { result } = renderHook(() => useCommand(api));
    await act(async () => {
      await result.current.run(`/workflows/${WORKFLOW_ID}/approvals`, { comment: 'original' });
    });
    act(() => result.current.reset());
    expect(result.current.retryable).toBe(true);
    expect(result.current.result).toBeUndefined();
    await act(async () => {
      await result.current.run(`/workflows/${WORKFLOW_ID}/approvals`, { comment: 'changed' });
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => {
      await result.current.retry();
    });
    expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[0][1].body);
    expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(
      fetcher.mock.calls[0][1].headers['Idempotency-Key'],
    );
  });
});

it('recovers the original request after remount even if the new form contains changed text', async () => {
  const fetcher = vi
    .fn()
    .mockRejectedValueOnce(new TypeError('synthetic response loss'))
    .mockImplementationOnce((_url, options) =>
      Promise.resolve(actionResponse(options, true, { replayed: true })),
    );
  const api = new FuseApi('synthetic', fetcher);
  const first = renderHook(() => useCommand(api));
  await act(async () => {
    await first.result.current.run(`/workflows/${WORKFLOW_ID}/approvals`, { comment: 'original' });
  });
  first.unmount();
  const second = renderHook(() => useCommand(api));
  await act(async () => {
    await second.result.current.run(`/workflows/${WORKFLOW_ID}/approvals`, { comment: 'changed' });
  });
  expect(fetcher).toHaveBeenCalledTimes(1);
  expect(second.result.current.retryable).toBe(true);
  await act(async () => {
    await second.result.current.retry();
  });
  expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[0][1].body);
  expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(
    fetcher.mock.calls[0][1].headers['Idempotency-Key'],
  );
});

describe('receipt-gated command completion', () => {
  it('never completes or navigates on malformed or mismatched receipts, then recovers the original request', async () => {
    const navigate = vi.fn();
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('lost response'))
      .mockResolvedValueOnce(new Response('{}', { status: 202 }))
      .mockImplementationOnce((_url, options) =>
        Promise.resolve(actionResponse(options, false, { requestId: NEXT_ID })),
      )
      .mockImplementationOnce((_url, options) =>
        Promise.resolve(actionResponse(options, false, { replayed: true })),
      );
    const api = new FuseApi('synthetic', fetcher);
    const { result } = renderHook(() => useCommand(api, navigate));
    await act(async () => {
      await result.current.run('/workflows', { amountKrw: 10 });
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      await act(async () => {
        await result.current.retry();
      });
      expect(result.current.result).toBeUndefined();
      expect(result.current.retryable).toBe(true);
      expect(result.current.error).toMatchObject({ uncertain: true, reasonCodes: ['INVALID_RESPONSE'] });
      expect(navigate).not.toHaveBeenCalled();
      act(() => result.current.reset());
      await act(async () => {
        await result.current.run('/workflows', { amountKrw: 20 });
      });
      expect(fetcher).toHaveBeenCalledTimes(attempt + 2);
    }
    await act(async () => {
      await result.current.retry();
    });
    expect(result.current.retryable).toBe(false);
    expect(result.current.result?.replayed).toBe(true);
    expect(navigate).toHaveBeenCalledTimes(1);
    expect(navigate).toHaveBeenCalledWith(result.current.result);
    expect(new Set(fetcher.mock.calls.map(([, options]) => options.body)).size).toBe(1);
    expect(new Set(fetcher.mock.calls.map(([, options]) => options.headers['Idempotency-Key'])).size).toBe(1);
    expect(api.unresolved('/workflows')).toBeUndefined();
  });

  it('ignores a disposed form completion while the remounted form shares the original in-flight send', async () => {
    const response = deferred<Response>();
    const fetcher = vi.fn().mockReturnValueOnce(response.promise);
    const api = new FuseApi('synthetic', fetcher);
    const oldComplete = vi.fn();
    const newComplete = vi.fn();
    const first = renderHook(() => useCommand(api, oldComplete));
    act(() => {
      void first.result.current.run('/workflows', { amountKrw: 10 });
    });
    first.unmount();
    const second = renderHook(() => useCommand(api, newComplete));
    act(() => {
      void second.result.current.run('/workflows', { amountKrw: 10 });
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await act(async () => {
      response.resolve(actionResponse(fetcher.mock.calls[0][1]));
    });
    expect(oldComplete).not.toHaveBeenCalled();
    expect(newComplete).toHaveBeenCalledTimes(1);
    expect(second.result.current.result?.requestId).toBe(fetcher.mock.calls[0][1].headers['Idempotency-Key']);
  });

  it('does not let a disposed token session complete into a new session or clear its unknown request', async () => {
    const response = deferred<Response>();
    const oldFetch = vi.fn().mockReturnValueOnce(response.promise);
    const oldApi = new FuseApi('old-synthetic-token', oldFetch);
    const oldComplete = vi.fn();
    const first = renderHook(() => useCommand(oldApi, oldComplete));
    act(() => {
      void first.result.current.run('/workflows', { amountKrw: 10 });
    });
    first.unmount();
    const newApi = new FuseApi('new-synthetic-token', vi.fn().mockRejectedValueOnce(new TypeError('lost')));
    const newComplete = vi.fn();
    const second = renderHook(() => useCommand(newApi, newComplete));
    await act(async () => {
      await second.result.current.run('/workflows', { amountKrw: 20 });
    });
    const pending = newApi.unresolved('/workflows');
    await act(async () => {
      response.resolve(actionResponse(oldFetch.mock.calls[0][1]));
    });
    expect(oldComplete).not.toHaveBeenCalled();
    expect(newComplete).not.toHaveBeenCalled();
    expect(second.result.current.result).toBeUndefined();
    expect(second.result.current.retryable).toBe(true);
    expect(newApi.unresolved('/workflows')).toEqual(pending);
    expect([localStorage.length, sessionStorage.length]).toEqual([0, 0]);
  });
});
