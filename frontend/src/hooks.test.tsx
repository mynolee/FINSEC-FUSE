import { act, renderHook, waitFor } from '@testing-library/react';
import { useCallback } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { ApiError, FuseApi } from './api';
import { useCommand, useQuery } from './hooks';

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
      task.resolve(new Response(JSON.stringify({ state: 'KYC_PENDING', decision: 'ALLOW' })));
    });
    expect(result.current.pending).toBe(false);
  });
  it('retries an uncertain outcome with the exact same body and key', async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('lost'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ state: 'APPROVED', decision: 'ALLOW' })));
    const api = new FuseApi('token', fetcher);
    const { result } = renderHook(() => useCommand(api));
    await act(async () => {
      await result.current.run('/workflows/a/approvals', { reviewSnapshotHash: 'a'.repeat(64) });
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
    const api = new FuseApi('token', vi.fn().mockReturnValue(task.promise));
    const { result } = renderHook(() => useCommand(api));
    act(() => {
      void result.current.run('/workflows', {});
    });
    expect(result.current.result).toBeUndefined();
    expect(result.current.pending).toBe(true);
    await act(async () => {
      task.resolve(new Response(JSON.stringify({ state: 'KYC_PENDING', decision: 'ALLOW' })));
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
      .mockResolvedValueOnce(new Response(JSON.stringify({ state: 'PAID', replayed: true })));
    const api = new FuseApi('synthetic', fetcher);
    const { result } = renderHook(() => useCommand(api));
    await act(async () => {
      await result.current.run('/workflows/a/approvals', { comment: 'original' });
    });
    act(() => result.current.reset());
    expect(result.current.retryable).toBe(true);
    expect(result.current.result).toBeUndefined();
    await act(async () => {
      await result.current.run('/workflows/a/approvals', { comment: 'changed' });
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
    .mockResolvedValueOnce(new Response(JSON.stringify({ state: 'PAID', replayed: true })));
  const api = new FuseApi('synthetic', fetcher);
  const first = renderHook(() => useCommand(api));
  await act(async () => {
    await first.result.current.run('/workflows/a/approvals', { comment: 'original' });
  });
  first.unmount();
  const second = renderHook(() => useCommand(api));
  await act(async () => {
    await second.result.current.run('/workflows/a/approvals', { comment: 'changed' });
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
