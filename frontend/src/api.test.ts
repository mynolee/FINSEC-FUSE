import { describe, expect, it, vi } from 'vitest';
import { ApiError, FuseApi } from './api';
const ACTION_ID = '00000000-0000-4000-8000-000000000001';
const NEXT_ID = '00000000-0000-4000-8000-000000000002';
const WORKFLOW_ID = '00000000-0000-4000-8000-000000000102';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('Spring-only API client', () => {
  it.each([
    ['default', 'GET'],
    ['default', 'POST'],
    ['injected', 'GET'],
    ['injected', 'POST'],
  ] as const)('calls %s fetch without an invalid receiver for %s', async (source, method) => {
    // Browser Web IDL fetch rejects a FuseApi receiver. Node fetch and arrow-function
    // mocks do not expose that bug, so exercise the browser receiver constraint explicitly.
    const fetcher = vi.fn(function (this: unknown, ..._args: Parameters<typeof fetch>) {
      if (this !== undefined && this !== globalThis && this !== window)
        throw new TypeError('Illegal invocation');
      return Promise.resolve(json({ decision: 'ALLOW', items: [], total: 0, page: 0, size: 20 }));
    });
    try {
      if (source === 'default') vi.stubGlobal('fetch', fetcher);
      const api = source === 'default' ? new FuseApi('synthetic') : new FuseApi('synthetic', fetcher);
      if (method === 'GET') await api.workflows();
      else await api.mutate('/workflows', { customerId: 'synthetic' }, ACTION_ID);
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.contexts).toEqual([undefined]);
      expect(fetcher.mock.calls[0][0]).toBe(
        method === 'GET' ? '/api/v1/workflows?size=20&page=0' : '/api/v1/workflows',
      );
      expect(fetcher.mock.calls[0][1]).toEqual(
        expect.objectContaining({
          method,
          credentials: 'omit',
          cache: 'no-store',
          signal: expect.any(AbortSignal),
        }),
      );
    } finally {
      if (source === 'default') vi.unstubAllGlobals();
    }
  });
  it('sends every read to the same-origin Spring API with a bearer token', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ items: [], total: 0, page: 0, size: 20 }));
    await new FuseApi('unit-test-token', fetcher).workflows('WAIT_APPROVAL', 2);
    expect(fetcher).toHaveBeenCalledWith(
      '/api/v1/workflows?size=20&page=2&state=WAIT_APPROVAL',
      expect.objectContaining({
        method: 'GET',
        headers: { Authorization: 'Bearer unit-test-token', Accept: 'application/json' },
        cache: 'no-store',
        credentials: 'omit',
      }),
    );
  });
  it('preserves the exact server preview hash and action UUID', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ state: 'APPROVED', decision: 'ALLOW' }, 201));
    const body = { decision: 'APPROVE', reviewSnapshotHash: 'a'.repeat(64), comment: '검토' };
    await new FuseApi('token', fetcher).mutate(`/workflows/${WORKFLOW_ID}/approvals`, body, ACTION_ID);
    const [, options] = fetcher.mock.calls[0];
    expect(options.headers['Idempotency-Key']).toBe(ACTION_ID);
    expect(JSON.parse(options.body)).toEqual(body);
    expect(options.headers).not.toHaveProperty('role');
  });
  it('recognizes a network failure after a mutation as uncertain', async () => {
    const fetcher = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(new FuseApi('token', fetcher).mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({
      uncertain: true,
      status: 0,
    });
  });
  it('keeps the same key after an uncertain request even after remount/navigation', async () => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('lost response'))
      .mockResolvedValueOnce(json({ replayed: true }));
    const api = new FuseApi('token', fetcher);
    await expect(api.mutate('/workflows', { amountKrw: 1000000 }, ACTION_ID)).rejects.toBeInstanceOf(
      ApiError,
    );
    await api.mutate('/workflows', { amountKrw: 1000000 }, NEXT_ID);
    expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(ACTION_ID);
  });
  it('retains an unresolved key for malformed 503 responses', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response('<h1>Unavailable</h1>', { status: 503 }))
      .mockResolvedValueOnce(json({ replayed: true }));
    const api = new FuseApi('token', fetcher);
    await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({
      uncertain: true,
      reasonCodes: ['INVALID_RESPONSE'],
    });
    await api.mutate('/workflows', {}, NEXT_ID);
    expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(ACTION_ID);
  });
  it('does not mark read failures as uncertain mutations', async () => {
    const api = new FuseApi('token', vi.fn().mockRejectedValue(new TypeError('offline')));
    await expect(api.workflow(WORKFLOW_ID)).rejects.toMatchObject({ uncertain: false, status: 0 });
  });
  it('exposes REVIEW_CHANGED so the operator must load a new preview', async () => {
    const api = new FuseApi(
      'token',
      vi.fn().mockResolvedValue(json({ reasonCodes: ['REVIEW_CHANGED'], message: 'Changed' }, 409)),
    );
    await expect(api.mutate('/workflows/x/approvals', {}, ACTION_ID)).rejects.toMatchObject({
      status: 409,
      reasonCodes: ['REVIEW_CHANGED'],
      uncertain: false,
    });
  });
  it('rejects HTML success pages rather than presenting invented data', async () => {
    const api = new FuseApi('token', vi.fn().mockResolvedValue(new Response('<html>proxy</html>')));
    await expect(api.workflow(WORKFLOW_ID)).rejects.toMatchObject({ reasonCodes: ['INVALID_RESPONSE'] });
  });
  it('keeps authentication errors distinct from security policy blocks', async () => {
    const api = new FuseApi(
      'invalid',
      vi.fn().mockResolvedValue(json({ reasonCode: 'UNAUTHENTICATED' }, 401)),
    );
    await expect(api.workflows()).rejects.toMatchObject({ status: 401, reasonCodes: ['UNAUTHENTICATED'] });
  });
  it('URL-encodes identifiers instead of allowing path/query injection', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({}));
    await new FuseApi('token', fetcher).impact('a/b?test=1');
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/incidents/a%2Fb%3Ftest%3D1/impact');
  });
});

describe('LIVE experiment API contract, no external provider calls', () => {
  it('forwards the chosen LIVE mode and fixed three repeats only through Spring', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(
        json({ requestId: ACTION_ID, state: 'PENDING', decision: 'ALLOW', experimentId: WORKFLOW_ID }, 202),
      );
    const body = {
      fixtureSetId: 'mvp-security-v1',
      caseIds: ['T02_MISSING_EVIDENCE'],
      mode: 'PAIRED',
      modelMode: 'LIVE',
      repeatCount: 3,
    };
    await new FuseApi('test-developer-token', fetcher).mutate('/experiments', body, ACTION_ID);
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][0]).toBe('/api/v1/experiments');
    expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual(body);
    expect(fetcher.mock.calls[0][1].headers['Idempotency-Key']).toBe(ACTION_ID);
  });
  it('preserves disabled LIVE as a definite refusal without retry or mode fallback', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(
        json({ reasonCodes: ['LIVE_NOT_AVAILABLE'], message: 'Server opt-in is disabled.' }, 400),
      );
    await expect(
      new FuseApi('test-developer-token', fetcher).mutate(
        '/experiments',
        { modelMode: 'LIVE', repeatCount: 3 },
        ACTION_ID,
      ),
    ).rejects.toMatchObject({ status: 400, reasonCodes: ['LIVE_NOT_AVAILABLE'], uncertain: false });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});

describe('v2.1 unknown commit recovery', () => {
  it('locks the original fingerprint across navigation and later auth failure', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(json({ state: null, decision: 'ERROR' }, 503))
      .mockResolvedValueOnce(json({ reasonCodes: ['FORBIDDEN'] }, 403))
      .mockResolvedValueOnce(json({ state: 'PAID', replayed: true }));
    const api = new FuseApi('synthetic', fetcher);
    const body = { amountKrw: 10 };
    await expect(api.mutate('/workflows', body, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
    body.amountKrw = 20;
    await expect(api.mutate('/workflows', body, NEXT_ID)).rejects.toMatchObject({
      reasonCodes: ['COMMIT_OUTCOME_UNKNOWN'],
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    await expect(api.mutate('/workflows', { amountKrw: 10 }, NEXT_ID)).rejects.toMatchObject({ status: 403 });
    expect(api.unresolved('/workflows')?.body).toEqual({ amountKrw: 10 });
    await api.mutate('/workflows', { amountKrw: 10 }, NEXT_ID);
    expect(fetcher.mock.calls.map(([, options]) => options.headers['Idempotency-Key'])).toEqual([
      ACTION_ID,
      ACTION_ID,
      ACTION_ID,
    ]);
    expect(api.unresolved('/workflows')).toBeUndefined();
  });
});
