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
    const api = new FuseApi('token', fetcher);
    const { result } = renderHook(() => useCommand(api));
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

describe('query ownership retirement', () => {
  it.each(['resolve', 'reject'] as const)(
    'clear fences a late %s and timer, then explicit reload recovers',
    async (completion) => {
      vi.useFakeTimers();
      let unmount: (() => void) | undefined;
      try {
        let resolve!: (value: string) => void;
        let reject!: (error: Error) => void;
        const stale = new Promise<string>((yes, no) => {
          resolve = yes;
          reject = no;
        });
        const signals: AbortSignal[] = [];
        const load = vi.fn((signal: AbortSignal) => {
          signals.push(signal);
          return signals.length === 1
            ? Promise.resolve('initial')
            : signals.length === 2
              ? stale
              : Promise.resolve('fresh');
        });
        const hook = renderHook(() => useQuery(load, true, 5000));
        unmount = hook.unmount;
        await act(async () => {});
        expect(hook.result.current.data).toBe('initial');
        await act(async () => {
          await vi.advanceTimersByTimeAsync(5000);
        });
        expect(load).toHaveBeenCalledTimes(2);
        act(() => {
          hook.result.current.clear();
          expect(signals[1].aborted).toBe(true);
        });
        expect(hook.result.current.data).toBeUndefined();
        expect(hook.result.current.loading).toBe(false);
        await act(async () => {
          if (completion === 'resolve') resolve('stale');
          else reject(new Error('stale failure'));
        });
        expect(hook.result.current.data).toBeUndefined();
        expect(hook.result.current.error).toBeUndefined();
        await act(async () => {
          await vi.advanceTimersByTimeAsync(20000);
        });
        expect(load).toHaveBeenCalledTimes(2);
        await act(async () => {
          hook.result.current.reload();
        });
        expect(hook.result.current.data).toBe('fresh');
        expect(load).toHaveBeenCalledTimes(3);
        await act(async () => {
          await vi.advanceTimersByTimeAsync(5000);
        });
        expect(load).toHaveBeenCalledTimes(4);
      } finally {
        unmount?.();
        vi.clearAllTimers();
        vi.useRealTimers();
      }
    },
  );

  it('clear cancels an already scheduled timer and stays paused across interval-only changes', async () => {
    vi.useFakeTimers();
    let unmount: (() => void) | undefined;
    try {
      const load = vi.fn().mockResolvedValue('record');
      const hook = renderHook(({ interval }) => useQuery(load, true, interval), {
        initialProps: { interval: 5000 },
      });
      unmount = hook.unmount;
      await act(async () => {});
      act(() => hook.result.current.clear());
      hook.rerender({ interval: 0 });
      hook.rerender({ interval: 1000 });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(20000);
      });
      expect(load).toHaveBeenCalledTimes(1);
      expect(hook.result.current.data).toBeUndefined();
      await act(async () => {
        hook.result.current.reload();
      });
      expect(load).toHaveBeenCalledTimes(2);
      expect(hook.result.current.data).toBe('record');
    } finally {
      unmount?.();
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it('reload retires a pending owner synchronously before the replacement effect', async () => {
    const stale = deferred<string>();
    const load = vi.fn().mockReturnValueOnce(stale.promise).mockResolvedValueOnce('fresh');
    const hook = renderHook(() => useQuery(load));
    await act(async () => {
      hook.result.current.reload();
      expect(load.mock.calls[0][0].aborted).toBe(true);
      stale.resolve('stale');
    });
    expect(hook.result.current.data).toBe('fresh');
    hook.unmount();
  });

  it('a new query identity or enabled transition recovers a cleared query', async () => {
    const first = vi.fn().mockResolvedValue('first');
    const next = vi.fn().mockResolvedValue('next');
    const hook = renderHook(({ load, enabled }) => useQuery(load, enabled), {
      initialProps: { load: first, enabled: true },
    });
    await act(async () => {});
    act(() => hook.result.current.clear());
    await act(async () => {
      hook.rerender({ load: next, enabled: true });
    });
    expect(hook.result.current.data).toBe('next');
    act(() => hook.result.current.clear());
    hook.rerender({ load: next, enabled: false });
    await act(async () => {
      hook.rerender({ load: next, enabled: true });
    });
    expect(hook.result.current.data).toBe('next');
    expect(next).toHaveBeenCalledTimes(2);
    hook.unmount();
  });

  it('preserves normal transient-error polling', async () => {
    vi.useFakeTimers();
    let unmount: (() => void) | undefined;
    try {
      const load = vi
        .fn()
        .mockResolvedValueOnce('initial')
        .mockRejectedValueOnce(new ApiError('offline', 503))
        .mockResolvedValueOnce('recovered');
      const hook = renderHook(() => useQuery(load, true, 5000));
      unmount = hook.unmount;
      await act(async () => {});
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(hook.result.current.data).toBe('initial');
      expect(hook.result.current.error).toBeInstanceOf(ApiError);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5000);
      });
      expect(hook.result.current.data).toBe('recovered');
      expect(hook.result.current.error).toBeUndefined();
    } finally {
      unmount?.();
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });

  it('keeps StrictMode replay and unmount ownership separate', async () => {
    vi.useFakeTimers();
    let unmount: (() => void) | undefined;
    try {
      const old = deferred<string>();
      const live = deferred<string>();
      const load = vi.fn().mockReturnValueOnce(old.promise).mockReturnValueOnce(live.promise);
      const hook = renderHook(() => useQuery(load, true, 5000), { reactStrictMode: true });
      unmount = hook.unmount;
      expect(load).toHaveBeenCalledTimes(2);
      expect(load.mock.calls[0][0].aborted).toBe(true);
      await act(async () => {
        old.resolve('retired');
      });
      expect(hook.result.current.data).toBeUndefined();
      await act(async () => {
        live.resolve('current');
      });
      expect(hook.result.current.data).toBe('current');
      hook.unmount();
      unmount = undefined;
      expect(load.mock.calls[1][0].aborted).toBe(true);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(20000);
      });
      expect(load).toHaveBeenCalledTimes(2);
    } finally {
      unmount?.();
      vi.clearAllTimers();
      vi.useRealTimers();
    }
  });
});

describe('immutable recovery ownership', () => {
  const firstScope = `/workflows/${WORKFLOW_ID}/approvals`;
  const secondScope = `/workflows/${NEXT_ID}/approvals`;
  const body = { decision: 'APPROVE', reviewSnapshotHash: 'a'.repeat(64), comment: 'original' };

  it('exposes a detached original request on mount without sending or allowing a changed command', async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError('synthetic loss'));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.mutate(firstScope, body, WORKFLOW_ID)).rejects.toBeInstanceOf(ApiError);
    const { result } = renderHook(() => useCommand(api, undefined, firstScope));
    expect(result.current.retryable).toBe(true);
    expect(result.current.retryRequest).toEqual({ path: firstScope, body, actionId: WORKFLOW_ID });
    (result.current.retryRequest!.body as Record<string, unknown>).decision = 'REJECT';
    await act(async () => {
      result.current.reset();
      await result.current.run(firstScope, { ...body, decision: 'REJECT' });
      await result.current.run(secondScope, body);
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.unresolved(firstScope)?.body).toEqual(body);
    await act(async () => {
      await result.current.retry();
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[0][1].body);
    expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(WORKFLOW_ID);
  });

  it('does not transfer recovery or a retained retry callback into another API session', async () => {
    const oldFetch = vi.fn().mockRejectedValue(new TypeError('synthetic loss'));
    const oldApi = new FuseApi('synthetic-old', oldFetch);
    await expect(oldApi.mutate(firstScope, body, WORKFLOW_ID)).rejects.toBeInstanceOf(ApiError);
    const newFetch = vi.fn();
    const newApi = new FuseApi('synthetic-new', newFetch);
    const hook = renderHook(({ api }) => useCommand(api, undefined, firstScope), {
      initialProps: { api: oldApi },
    });
    const staleRetry = hook.result.current.retry;
    hook.rerender({ api: newApi });
    expect(hook.result.current.retryRequest).toBeUndefined();
    expect(hook.result.current.retryable).toBe(false);
    await act(async () => {
      await staleRetry();
      await hook.result.current.retry();
    });
    expect(oldFetch).toHaveBeenCalledTimes(1);
    expect(newFetch).not.toHaveBeenCalled();
    expect(oldApi.unresolved(firstScope)?.body).toEqual(body);
  });

  it('keeps scope changes separate and restores unresolved recovery only upon returning to its endpoint', async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError('synthetic loss'));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.mutate(firstScope, body, WORKFLOW_ID)).rejects.toBeInstanceOf(ApiError);
    const hook = renderHook(({ scope }) => useCommand(api, undefined, scope), {
      initialProps: { scope: firstScope },
    });
    const staleRetry = hook.result.current.retry;
    hook.rerender({ scope: secondScope });
    expect(hook.result.current.retryRequest).toBeUndefined();
    await act(async () => {
      await staleRetry();
      await hook.result.current.retry();
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    hook.rerender({ scope: firstScope });
    expect(hook.result.current.retryRequest).toEqual({ path: firstScope, body, actionId: WORKFLOW_ID });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it.each(['session', 'scope'])('ignores old completion after a same-mounted %s change', async (kind) => {
    const pending = deferred<Response>();
    const oldFetch = vi.fn().mockReturnValue(pending.promise);
    const api = new FuseApi('synthetic-old', oldFetch);
    const nextFetch = vi.fn();
    const nextApi = new FuseApi('synthetic-new', nextFetch);
    const complete = vi.fn();
    const hook = renderHook(({ client, scope }) => useCommand(client, complete, scope), {
      initialProps: { client: api, scope: firstScope },
    });
    act(() => {
      void hook.result.current.run(firstScope, body);
    });
    hook.rerender({
      client: kind === 'session' ? nextApi : api,
      scope: kind === 'scope' ? secondScope : firstScope,
    });
    expect(hook.result.current.pending).toBe(false);
    expect(hook.result.current.retryRequest).toBeUndefined();
    await act(async () => {
      pending.resolve(actionResponse(oldFetch.mock.calls[0][1], true));
    });
    expect(complete).not.toHaveBeenCalled();
    expect(hook.result.current.result).toBeUndefined();
    expect(nextFetch).not.toHaveBeenCalled();
  });

  it.each([401, 403, 404])(
    'retains the original recovery summary after retry receives %s',
    async (status) => {
      const fetcher = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('synthetic loss'))
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ reasonCodes: ['SYNTHETIC_DENIED'] }), { status }),
        );
      const api = new FuseApi('synthetic', fetcher);
      const hook = renderHook(() => useCommand(api, undefined, firstScope));
      await act(async () => {
        await hook.result.current.run(firstScope, body);
      });
      const original = hook.result.current.retryRequest;
      await act(async () => {
        await hook.result.current.retry();
      });
      expect(hook.result.current.retryable).toBe(true);
      expect(hook.result.current.retryRequest).toEqual(original);
      expect(hook.result.current.error).toMatchObject({ status });
      expect(hook.result.current.result).toBeUndefined();
      expect(api.unresolved(firstScope)).toEqual(original);
    },
  );
});
