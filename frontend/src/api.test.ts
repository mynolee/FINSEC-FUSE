import { describe, expect, it, vi } from 'vitest';
import { ApiError, FuseApi } from './api';
const ACTION_ID = '00000000-0000-4000-8000-000000000001';
const NEXT_ID = '00000000-0000-4000-8000-000000000002';
const WORKFLOW_ID = '00000000-0000-4000-8000-000000000102';
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

// Producer-shaped stored ActionResult fixtures. The request UUID is the sent idempotency key.
const receipt = (overrides: Record<string, unknown> = {}) => ({
  requestId: ACTION_ID,
  workflowId: WORKFLOW_ID,
  generation: 1,
  state: 'KYC_PENDING',
  decision: 'ALLOW',
  reasonCodes: [],
  message: 'Workflow request accepted',
  replayed: false,
  ...overrides,
});
const approvalReceipt = (overrides: Record<string, unknown> = {}) =>
  receipt({
    state: 'APPROVED',
    approvalId: NEXT_ID,
    extraRiskLimit: 50,
    riskLimit: 100,
    expiresAt: '2026-10-10T16:00:00.123456789Z',
    payJobId: NEXT_ID,
    ...overrides,
  });
const experimentReceipt = (overrides: Record<string, unknown> = {}) =>
  receipt({
    workflowId: null,
    generation: null,
    state: 'PENDING',
    experimentId: WORKFLOW_ID,
    status: 'PENDING',
    totalRuns: 6,
    ...overrides,
  });
const quarantineReceipt = (overrides: Record<string, unknown> = {}) =>
  receipt({
    workflowId: null,
    generation: null,
    state: 'ACTIVE',
    quarantineId: NEXT_ID,
    scope: 'AGENT_VERSION',
    target: { agentId: 'kyc-agent', agentVersion: 1 },
    ...overrides,
  });
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

describe('Spring-only API client', () => {
  it('rejects an already-aborted mutation before dispatch without commit uncertainty', async () => {
    const controller = new AbortController();
    controller.abort('SYNTHETIC_PRIVATE_PRE_DISPATCH_ABORT');
    const fetcher = vi.fn();
    const failure = await new FuseApi('synthetic', fetcher).request('/workflows', {
      body: {}, actionId: ACTION_ID, signal: controller.signal,
    }).catch(error => error);
    expect(failure).toBeInstanceOf(ApiError);
    expect(failure).toMatchObject({ status: 0, reasonCodes: ['INVALID_REQUEST'], uncertain: false });
    expect(failure.message).not.toContain('SYNTHETIC_PRIVATE_PRE_DISPATCH_ABORT');
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([new Error('SYNTHETIC_PRIVATE_MUTATION_ABORT'), 'SYNTHETIC_PRIVATE_MUTATION_ABORT'])(
    'redacts an aborted sent mutation and preserves unknown commit semantics (%s)', async raw => {
      const controller = new AbortController();
      const headers = deferred<Response>();
      const fetcher = vi.fn().mockReturnValue(headers.promise);
      const pending = new FuseApi('synthetic', fetcher).request('/workflows', {
        body: {}, actionId: ACTION_ID, signal: controller.signal,
      });
      controller.abort(raw);
      headers.reject(raw);
      const failure = await pending.catch(error => error);
      expect(failure).toBeInstanceOf(ApiError);
      expect(failure).toMatchObject({ status: 0, reasonCodes: ['DEPENDENCY_UNAVAILABLE'], uncertain: true });
      expect(failure.message).not.toContain('SYNTHETIC_PRIVATE_MUTATION_ABORT');
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.calls[0][1]).toMatchObject({
        method: 'POST', headers: { 'Idempotency-Key': ACTION_ID }, body: '{}',
      });
    },
  );
  it('retains a definitive matching receipt when mutation fetch ignores cancellation', async () => {
    const controller = new AbortController();
    const headers = deferred<Response>();
    const fetcher = vi.fn().mockReturnValue(headers.promise);
    const pending = new FuseApi('synthetic', fetcher).request('/workflows', {
      body: {}, actionId: ACTION_ID, signal: controller.signal,
    });
    controller.abort('SYNTHETIC_PRIVATE_MUTATION_ABORT');
    headers.resolve(json(receipt(), 201));
    await expect(pending).resolves.toMatchObject({ requestId: ACTION_ID, workflowId: WORKFLOW_ID, decision: 'ALLOW' });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('rejects a pre-cancelled read without calling fetch or echoing its abort reason', async () => {
    const controller = new AbortController();
    controller.abort('SYNTHETIC_PRIVATE_ABORT_REASON');
    const fetcher = vi.fn();
    const failure = await new FuseApi('synthetic', fetcher).workflow(WORKFLOW_ID, controller.signal).catch(error => error);
    expect(failure).toBeInstanceOf(DOMException);
    expect(failure).toMatchObject({ name: 'AbortError', message: '요청이 취소됐어요.' });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('does not decode a cancelled read when a fetcher ignores abort and returns late headers', async () => {
    const controller = new AbortController();
    const headers = deferred<Response>();
    const response = json({ workflowId: WORKFLOW_ID });
    const decode = vi.spyOn(response.body!, 'getReader');
    const fetcher = vi.fn().mockReturnValue(headers.promise);
    const request = new FuseApi('synthetic', fetcher).workflow(WORKFLOW_ID, controller.signal);
    controller.abort('SYNTHETIC_PRIVATE_ABORT_REASON');
    headers.resolve(response);
    await expect(request).rejects.toMatchObject({ name: 'AbortError' });
    expect(decode).not.toHaveBeenCalled();
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it.each(['resolve', 'reject'] as const)('keeps read cancellation distinct when delayed JSON later %s', async completion => {
    const controller = new AbortController();
    const started = deferred<void>();
    const body = deferred<Uint8Array>();
    const response = new Response(new ReadableStream<Uint8Array>({
      async pull(stream) {
        started.resolve();
        try { stream.enqueue(await body.promise); stream.close(); }
        catch (error) { stream.error(error); }
      },
    }));
    const fetcher = vi.fn().mockResolvedValue(response);
    const request = new FuseApi('synthetic', fetcher).workflow(WORKFLOW_ID, controller.signal);
    await started.promise;
    controller.abort('SYNTHETIC_PRIVATE_ABORT_REASON');
    if (completion === 'resolve') body.resolve(new TextEncoder().encode(JSON.stringify({ workflowId: WORKFLOW_ID, customerId: 'SYNTHETIC_PRIVATE_LATE_DATA' })));
    else body.reject(new Error('SYNTHETIC_PRIVATE_JSON_ERROR'));
    const failure = await request.catch(error => error);
    expect(failure).toBeInstanceOf(DOMException);
    expect(failure).toMatchObject({ name: 'AbortError', message: '요청이 취소됐어요.' });
    expect(failure).not.toBeInstanceOf(ApiError);
    expect(String(failure)).not.toContain('SYNTHETIC_PRIVATE');
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

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
      return Promise.resolve(
        json(method === 'POST' ? receipt() : { items: [], total: 0, page: 0, size: 20 }),
      );
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
    const fetcher = vi.fn().mockResolvedValue(json(approvalReceipt(), 201));
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
      .mockResolvedValueOnce(json(receipt({ replayed: true })));
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
      .mockResolvedValueOnce(json(receipt({ replayed: true })));
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
  it.each([400, 401, 403, 404, 409, 500])(
    'does not expose dependency text or unknown codes on HTTP %s',
    async (status) => {
      const marker = 'synthetic-private-error-marker';
      const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
        message: marker,
        reasonCodes: [marker, { detail: marker }, null],
        cause: marker,
      }, status)));
      const error = await api.workflows().catch((failure: unknown) => failure);
      expect(error).toBeInstanceOf(ApiError);
      expect(error).toMatchObject({ status, reasonCodes: [`HTTP_${status}`], uncertain: false });
      expect(String(error)).not.toContain(marker);
      expect(JSON.stringify(error)).not.toContain(marker);
    },
  );
  it('retains known recovery codes while dropping unknown error content', async () => {
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
      message: 'synthetic-private-error-marker',
      reasonCodes: ['REVIEW_CHANGED', 'synthetic-private-error-marker', 'REVIEW_CHANGED'],
    }, 409)));
    await expect(api.workflows()).rejects.toMatchObject({
      message: '요청을 처리하지 못했어요.',
      reasonCodes: ['REVIEW_CHANGED'],
    });
  });
  it.each(['reasonCode', 'code'])('retains a known scalar %s without forwarding its message', async (field) => {
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
      [field]: 'REVIEW_CHANGED', message: 'synthetic-private-error-marker',
    }, 409)));
    await expect(api.workflows()).rejects.toMatchObject({
      message: '요청을 처리하지 못했어요.', reasonCodes: ['REVIEW_CHANGED'],
    });
  });
  it('does not trust an arbitrary suffix on a known error prefix', async () => {
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
      reasonCode: 'CAPTURE_ERROR_synthetic-private-error-marker',
    }, 500)));
    await expect(api.workflows()).rejects.toMatchObject({ reasonCodes: ['HTTP_500'] });
  });
  it('preserves the HTTP 408 body-timeout code without exposing dependency content', async () => {
    const marker = 'synthetic-private-timeout-marker';
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
      message: marker, reasonCodes: ['REQUEST_BODY_TIMEOUT', marker], cause: marker,
    }, 408)));
    const error = await api.mutate('/workflows', {}, ACTION_ID).catch((failure: unknown) => failure);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({
      status: 408, uncertain: false, reasonCodes: ['REQUEST_BODY_TIMEOUT'],
      message: '요청을 처리하지 못했어요.',
    });
    expect(JSON.stringify(error)).not.toContain(marker);
    expect(String(error)).not.toContain(marker);
    expect(api.unresolved('/workflows')).toBeUndefined();
  });
  it('keeps an older unknown outcome unresolved after a later HTTP 408 refusal', async () => {
    const api = new FuseApi('synthetic', vi.fn()
      .mockRejectedValueOnce(new TypeError('synthetic response loss'))
      .mockResolvedValueOnce(json({ reasonCodes: ['REQUEST_BODY_TIMEOUT'] }, 408)));
    await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
    await expect(api.mutate('/workflows', {}, NEXT_ID)).rejects.toMatchObject({
      status: 408, uncertain: false, reasonCodes: ['REQUEST_BODY_TIMEOUT'],
    });
    expect(api.unresolved('/workflows')?.actionId).toBe(ACTION_ID);
  });
  it('keeps HTTP 503 mutation failures uncertain after body-timeout support', async () => {
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({
      reasonCodes: ['DEPENDENCY_UNAVAILABLE'], message: 'synthetic-private-dependency-marker',
    }, 503)));
    await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({
      status: 503, uncertain: true, reasonCodes: ['DEPENDENCY_UNAVAILABLE'],
      message: '요청을 처리하지 못했어요.',
    });
    expect(api.unresolved('/workflows')?.actionId).toBe(ACTION_ID);
  });
  it('keeps authentication errors distinct from security policy blocks', async () => {
    const api = new FuseApi(
      'invalid',
      vi.fn().mockResolvedValue(json({ reasonCode: 'UNAUTHENTICATED' }, 401)),
    );
    await expect(api.workflows()).rejects.toMatchObject({ status: 401, reasonCodes: ['UNAUTHENTICATED'] });
  });
  it.each([-1, 0.5, NaN, Infinity, -Infinity, 2147483648, Number.MAX_SAFE_INTEGER, null, false, '1'])('rejects an invalid Java page before sending: %s', async page => {
    const fetcher = vi.fn();
    await expect(new FuseApi('synthetic', fetcher).workflows('', page as number)).rejects.toMatchObject({
      status: 0, reasonCodes: ['INVALID_REQUEST'], uncertain: false,
    });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it.each([null, false, 0, 'PAID&size=100', 'UNKNOWN', ' PAID'])('does not turn an invalid state into an unfiltered query: %s', async state => {
    const fetcher = vi.fn();
    await expect(new FuseApi('synthetic', fetcher).workflows(state as string)).rejects.toMatchObject({ reasonCodes: ['INVALID_REQUEST'] });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('preserves omitted filters/defaults and the inclusive Java-int page maximum', async () => {
    const fetcher = vi.fn().mockImplementation(async () => json({ items: [], total: 0, page: 0, size: 20 }));
    const api = new FuseApi('synthetic', fetcher);
    await api.workflows(undefined, undefined);
    await api.workflows('PAID', 2147483647);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([
      '/api/v1/workflows?size=20&page=0',
      '/api/v1/workflows?size=20&page=2147483647&state=PAID',
    ]);
  });
  it.each(['workflow', 'trace', 'preview', 'impact', 'experiment'] as const)('%s rejects noncanonical IDs before URL normalization can change the route', async method => {
    const fetcher = vi.fn();
    const api = new FuseApi('synthetic', fetcher);
    for (const id of ['.', '..', '../workflows', 'a/b?test=1#fragment', '%2e%2e', '\\', '', null, undefined, false, 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA']) {
      await expect(api[method](id as string)).rejects.toMatchObject({ reasonCodes: ['INVALID_REQUEST'], uncertain: false });
    }
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('retains all canonical UUID read routes including synthetic version-zero IDs', async () => {
    const id = '00000000-0000-0000-0000-000000000001';
    const fetcher = vi.fn().mockImplementation(async (url: string) => json(url.endsWith('/trace')
      ? { workflowId: id, generation: 1, runs: [], results: [], grants: [], dependencies: [], approvals: [], riskEvents: [], payments: [], auditEvents: [] }
      : { experimentId: id }));
    const api = new FuseApi('synthetic', fetcher);
    await api.workflow(id);
    await api.trace(id);
    await api.preview(id);
    await api.impact(id);
    await api.experiment(id);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([
      `/api/v1/workflows/${id}`, `/api/v1/workflows/${id}/trace`,
      `/api/v1/workflows/${id}/approval-preview`, `/api/v1/incidents/${id}/impact`,
      `/api/v1/experiments/${id}`,
    ]);
  });
  it.each([
    ['/workflows?size=20&page=0', { items: {}, total: 0, page: 0, size: 20 }],
    ['/workflows?size=20&page=0', { items: [null], total: 1, page: 0, size: 20 }],
    ['/workflows?size=20&page=0', { items: [], total: {}, page: 0, size: 20 }],
    ['/workflows?size=20&page=0', { items: [{ canApprove: 'false' }], total: 1, page: 0, size: 20 }],
    [`/workflows/${WORKFLOW_ID}`, { canResume: 'false' }],
    ['/workflows?size=20&page=0', { items: [{ reasonCodes: {} }], total: 1, page: 0, size: 20 }],
    [`/workflows/${WORKFLOW_ID}`, { reasonCodes: [null] }],
    [`/workflows/${WORKFLOW_ID}`, { reasonCodes: null }],
    ['/workflows?size=20&page=0', { items: [{ usedRisk: {} }], total: 1, page: 0, size: 20 }],
    [`/workflows/${WORKFLOW_ID}`, { payoutAccountId: {} }],
    [`/workflows/${WORKFLOW_ID}/approval-preview`, { customerId: {} }],
    [`/workflows/${WORKFLOW_ID}/approval-preview`, { reviewSnapshotHash: [] }],
    [`/workflows/${WORKFLOW_ID}/approval-preview`, null],
    [`/experiments/${WORKFLOW_ID}`, { experimentId: WORKFLOW_ID, fixtureSetId: {} }],
    [`/incidents/${WORKFLOW_ID}/impact`, { actual: { runCount: {} } }],
    [`/incidents/${WORKFLOW_ID}/impact`, { actual: { paymentCount: [1] } }],
    [`/workflows/${WORKFLOW_ID}/trace`, { workflowId: WORKFLOW_ID, generation: 1, runs: {} }],
    [`/experiments/${WORKFLOW_ID}`, { experimentId: WORKFLOW_ID, caseOutputs: {} }],
    [`/experiments/${WORKFLOW_ID}`, { experimentId: WORKFLOW_ID, exclusions: [null] }],
  ] as const)('rejects a malformed consumed read envelope for %s without mutation uncertainty', async (path, data) => {
    const fetcher = vi.fn().mockImplementation(async () => json(data));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.request(path)).rejects.toMatchObject({
      status: 200, reasonCodes: ['INVALID_RESPONSE'], uncertain: false,
      message: '서버가 올바른 JSON 응답을 보내지 않았어요.',
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.unresolved(path)).toBeUndefined();
  });
  it('applies preview leaf checks through the public preview read and preserves safe null/extra values', async () => {
    const data = { customerId: null, payoutAccountId: '', reviewSnapshotHash: 'synthetic future value', extra: { preserved: true } };
    const fetcher = vi.fn().mockImplementationOnce(async () => json({ loanResultHash: {} }))
      .mockImplementationOnce(async () => json(data));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.preview(WORKFLOW_ID)).rejects.toMatchObject({ reasonCodes: ['INVALID_RESPONSE'], uncertain: false });
    await expect(api.preview(WORKFLOW_ID)).resolves.toEqual(data);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([
      `/api/v1/workflows/${WORKFLOW_ID}/approval-preview`,
      `/api/v1/workflows/${WORKFLOW_ID}/approval-preview`,
    ]);
  });
  it('applies impact count checks on the public route without changing potential unavailable data', async () => {
    const data = { actual: { runCount: 0, paymentCount: null }, potential: { totalAmountKrw: {}, applicationCount: [] }, extra: 'preserved' };
    const fetcher = vi.fn().mockImplementationOnce(async () => json({ actual: { paymentCount: {} } }))
      .mockImplementationOnce(async () => json(data));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.impact(WORKFLOW_ID)).rejects.toMatchObject({ reasonCodes: ['INVALID_RESPONSE'], uncertain: false });
    await expect(api.impact(WORKFLOW_ID)).resolves.toEqual(data);
    expect(fetcher.mock.calls.map(call => call[0])).toEqual([
      `/api/v1/incidents/${WORKFLOW_ID}/impact`, `/api/v1/incidents/${WORKFLOW_ID}/impact`,
    ]);
  });
});

describe('LIVE experiment API contract, no external provider calls', () => {
  it('forwards the chosen LIVE mode and fixed three repeats only through Spring', async () => {
    const fetcher = vi.fn().mockResolvedValue(json(experimentReceipt(), 202));
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
      .mockResolvedValueOnce(json(receipt({ state: 'PAID', replayed: true })));
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

describe('closed mutation receipts and original request binding', () => {
  const invalidReceipts: Array<[string, unknown]> = [
    ['empty object', {}],
    ['null', null],
    ['array', []],
    ['string', 'accepted'],
    ['wrong request UUID', receipt({ requestId: NEXT_ID })],
    ['noncanonical UUID', receipt({ requestId: '00000000-0000-4000-8000-00000000000A' })],
    ['numeric request ID', receipt({ requestId: 1 })],
    ['invalid workflow ID', receipt({ workflowId: 'not-a-uuid' })],
    ['null workflow ID', receipt({ workflowId: null })],
    ['string generation', receipt({ generation: '1' })],
    ['fractional generation', receipt({ generation: 1.5 })],
    ['zero generation', receipt({ generation: 0 })],
    ['overflow generation', receipt({ generation: 2147483648 })],
    ['null generation', receipt({ generation: null })],
    ['null state', receipt({ state: null })],
    ['unknown state', receipt({ state: 'SUCCESS' })],
    ['unknown decision', receipt({ decision: 'SUCCESS' })],
    ['array decision', receipt({ decision: ['ALLOW'] })],
    ['scalar reason codes', receipt({ reasonCodes: 'DENY' })],
    ['wrong reason item', receipt({ reasonCodes: [1] })],
    ['wrong message type', receipt({ message: {} })],
    ['wrong replayed type', receipt({ replayed: 'true' })],
    ['unknown field', receipt({ accepted: true })],
    ['foreign route field', receipt({ experimentId: WORKFLOW_ID })],
    ...Object.keys(receipt()).map((key): [string, unknown] => {
      const incomplete: Record<string, unknown> = receipt();
      delete incomplete[key];
      return [`missing ${key}`, incomplete];
    }),
  ];
  it.each(invalidReceipts)('retains the unknown original request after %s', async (_label, invalid) => {
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new TypeError('lost response'))
      .mockResolvedValueOnce(json(invalid, 202))
      .mockResolvedValueOnce(json(receipt({ replayed: true }), 202))
      .mockResolvedValueOnce(json(receipt({ requestId: NEXT_ID }), 202));
    const api = new FuseApi('synthetic', fetcher);
    const original = { amountKrw: 10, comment: 'original' };
    await expect(api.mutate('/workflows', original, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
    await expect(api.mutate('/workflows', original, NEXT_ID)).rejects.toMatchObject({
      status: 202,
      reasonCodes: ['INVALID_RESPONSE'],
      uncertain: true,
    });
    expect(api.unresolved('/workflows')).toEqual({ path: '/workflows', body: original, actionId: ACTION_ID });
    await expect(api.mutate('/workflows', { ...original, amountKrw: 20 }, NEXT_ID)).rejects.toMatchObject({
      reasonCodes: ['COMMIT_OUTCOME_UNKNOWN'],
      uncertain: true,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1][1].body).toBe(fetcher.mock.calls[0][1].body);
    const result = await api.mutate('/workflows', original, NEXT_ID);
    expect(result).toEqual(receipt({ replayed: true, message: '서버가 요청을 처리했어요.' }));
    expect(fetcher.mock.calls.map(([, options]) => options.headers['Idempotency-Key'])).toEqual([
      ACTION_ID,
      ACTION_ID,
      ACTION_ID,
    ]);
    expect(api.unresolved('/workflows')).toBeUndefined();
    await api.mutate('/workflows', { ...original, amountKrw: 20 }, NEXT_ID);
    expect(fetcher.mock.calls[3][1].headers['Idempotency-Key']).toBe(NEXT_ID);
  });

  it.each([200, 201, 202])(
    'keeps malformed JSON and valid-JSON malformed HTTP %s uncertain',
    async (status) => {
      for (const response of [new Response('{', { status }), json({}, status)]) {
        const fetcher = vi.fn().mockResolvedValueOnce(response);
        const api = new FuseApi('synthetic', fetcher);
        await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({
          status,
          reasonCodes: ['INVALID_RESPONSE'],
          uncertain: true,
        });
        expect(api.unresolved('/workflows')?.actionId).toBe(ACTION_ID);
        expect(fetcher).toHaveBeenCalledTimes(1);
      }
    },
  );

  it.each([203, 204, 206])('does not treat an unsupported HTTP %s as a receipt', async (status) => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(status === 204 ? new Response(null, { status }) : json(receipt(), status));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({ uncertain: true, status });
    expect(api.unresolved('/workflows')?.actionId).toBe(ACTION_ID);
  });

  it.each([
    [200, '/workflows', receipt({ state: 'PAID', replayed: true })],
    [
      202,
      '/workflows',
      receipt({ state: 'BLOCKED', decision: 'DENY', reasonCodes: ['EVIDENCE_MISSING'], replayed: true }),
    ],
    [
      202,
      '/workflows',
      receipt({
        state: 'ON_HOLD',
        decision: 'ERROR',
        reasonCodes: ['DEPENDENCY_UNAVAILABLE'],
        replayed: true,
      }),
    ],
    [202, '/workflows', receipt({ state: 'WAIT_APPROVAL', decision: 'WAIT_APPROVAL' })],
    [201, `/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt()],
    [
      201,
      `/workflows/${WORKFLOW_ID}/approvals`,
      approvalReceipt({
        state: 'REJECTED',
        reasonCodes: ['REVIEWER_REJECTED'],
        payJobId: null,
        extraRiskLimit: 0,
      }),
    ],
    [202, `/workflows/${WORKFLOW_ID}/resume`, receipt({ generation: 2, kycJobId: NEXT_ID })],
    [
      202,
      `/workflows/${WORKFLOW_ID}/resume`,
      receipt({
        state: 'ON_HOLD',
        decision: 'DENY',
        reasonCodes: ['MANUAL_REVIEW_REQUIRED'],
        replayed: true,
      }),
    ],
    [202, '/experiments', experimentReceipt()],
    [201, '/quarantines', quarantineReceipt()],
    [200, `/quarantines/${NEXT_ID}/release`, quarantineReceipt({ state: 'RELEASED', replayed: true })],
    ...[
      ['RUN', { runId: WORKFLOW_ID }],
      ['RESULT', { resultId: WORKFLOW_ID }],
      ['WORKFLOW', { workflowId: WORKFLOW_ID }],
      ['SOURCE_VERSION', { documentId: WORKFLOW_ID, documentVersion: 2 }],
    ].map(([scope, target]) => [
      201,
      '/quarantines',
      quarantineReceipt({ scope, target, workflowId: scope === 'WORKFLOW' ? WORKFLOW_ID : null }),
    ]),
  ] as Array<[number, string, unknown]>)(
    'accepts the producer envelope HTTP %s %s %#',
    async (status, path, data) => {
      const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json(data, status)));
      await expect(api.mutate(path, {}, ACTION_ID)).resolves.toEqual({
        ...(data as Record<string, unknown>), message: expect.any(String),
      });
      expect(api.unresolved(path)).toBeUndefined();
    },
  );

  it.each([200, 201, 202])('projects definitive HTTP %s receipts to safe display fields', async (status) => {
    const messages = {
      ALLOW: '서버가 요청을 처리했어요.',
      WAIT_APPROVAL: '직원 승인을 기다리고 있어요.',
      DENY: '요청이 거절됐어요. 처리 상태와 사유를 확인하세요.',
      ERROR: '요청을 완료하지 못했어요. 처리 상태와 사유를 확인하세요.',
    };
    for (const [decision, message] of Object.entries(messages)) {
      const marker = 'synthetic-private-receipt-marker';
      const state = decision === 'DENY' ? 'BLOCKED' : decision === 'ERROR' ? 'ON_HOLD' : decision === 'WAIT_APPROVAL' ? 'WAIT_APPROVAL' : 'KYC_PENDING';
      const code = decision === 'ERROR' ? 'DEPENDENCY_UNAVAILABLE' : 'EVIDENCE_MISSING';
      const source = receipt({ decision, state, message: marker, reasonCodes: [code, marker], replayed: true });
      const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json(source, status)));
      const result = await api.mutate('/workflows', {}, ACTION_ID);
      expect(result).toEqual({ ...source, message, reasonCodes: [code] });
      expect(JSON.stringify(result)).not.toContain(marker);
      expect(api.unresolved('/workflows')).toBeUndefined();
    }
  });

  it.each([
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ workflowId: NEXT_ID })],
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ approvalId: null })],
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ extraRiskLimit: '50' })],
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ expiresAt: 'not-a-date' })],
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ expiresAt: '2026-02-30T00:00:00Z' })],
    [`/workflows/${WORKFLOW_ID}/approvals`, approvalReceipt({ payJobId: null })],
    [`/workflows/${WORKFLOW_ID}/resume`, receipt()],
    [`/workflows/${WORKFLOW_ID}/resume`, receipt({ kycJobId: 1 })],
    ['/experiments', experimentReceipt({ workflowId: WORKFLOW_ID })],
    ['/experiments', experimentReceipt({ experimentId: null })],
    ['/experiments', experimentReceipt({ totalRuns: '6' })],
    ['/experiments', experimentReceipt({ totalRuns: 2147483648 })],
    ['/experiments', experimentReceipt({ status: 'COMPLETED' })],
    ['/quarantines', quarantineReceipt({ quarantineId: 1 })],
    ['/quarantines', quarantineReceipt({ scope: 'ALL' })],
    [
      '/quarantines',
      quarantineReceipt({ target: { agentId: 'kyc-agent', agentVersion: 1, unexpected_field: 'wrong' } }),
    ],
    ['/quarantines', quarantineReceipt({ target: { agentId: 'kyc-agent', agentVersion: '1' } })],
    ['/quarantines', quarantineReceipt({ target: {} })],
    ['/quarantines', quarantineReceipt({ target: { agentId: 'a'.repeat(65), agentVersion: 1 } })],
    ['/quarantines', quarantineReceipt({ target: { agentId: 'kyc-agent', agentVersion: 2147483648 } })],
    [`/quarantines/${WORKFLOW_ID}/release`, quarantineReceipt({ state: 'RELEASED' })],
  ])('rejects an invalid or misbound route receipt for %s %#', async (path, data) => {
    const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json(data)));
    await expect(api.mutate(path as string, {}, ACTION_ID)).rejects.toMatchObject({
      uncertain: true,
      reasonCodes: ['INVALID_RESPONSE'],
    });
    expect(api.unresolved(path as string)?.actionId).toBe(ACTION_ID);
  });

  it.each([
    [
      `/workflows/${WORKFLOW_ID}/approvals`,
      approvalReceipt(),
      ['approvalId', 'extraRiskLimit', 'riskLimit', 'expiresAt', 'payJobId'],
    ],
    [`/workflows/${WORKFLOW_ID}/resume`, receipt({ kycJobId: NEXT_ID }), ['kycJobId']],
    ['/experiments', experimentReceipt(), ['experimentId', 'status', 'totalRuns']],
    ['/quarantines', quarantineReceipt(), ['quarantineId', 'scope', 'target']],
    [
      `/quarantines/${NEXT_ID}/release`,
      quarantineReceipt({ state: 'RELEASED' }),
      ['quarantineId', 'scope', 'target'],
    ],
  ] as Array<[string, Record<string, unknown>, string[]]>)(
    'requires each extension and rejects unknown fields for %s',
    async (path, data, keys) => {
      for (const key of keys) {
        const incomplete = { ...data };
        delete incomplete[key];
        const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json(incomplete)));
        await expect(api.mutate(path, {}, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
        expect(api.unresolved(path)?.actionId).toBe(ACTION_ID);
      }
      const api = new FuseApi('synthetic', vi.fn().mockResolvedValue(json({ ...data, extra: true })));
      await expect(api.mutate(path, {}, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
    },
  );

  it.each([400, 401, 403, 404, 409, 422, 429])(
    'preserves HTTP %s refusal without resolving an older unknown commit',
    async (status) => {
      const error = receipt({
        state: null,
        workflowId: null,
        generation: null,
        decision: 'DENY',
        reasonCodes: ['FORBIDDEN'],
      });
      const initial = new FuseApi('synthetic', vi.fn().mockResolvedValue(json(error, status)));
      await expect(initial.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({
        status,
        uncertain: false,
        reasonCodes: ['FORBIDDEN'],
      });
      expect(initial.unresolved('/workflows')).toBeUndefined();
      const fetcher = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('lost'))
        .mockResolvedValueOnce(json(error, status));
      const api = new FuseApi('synthetic', fetcher);
      await expect(api.mutate('/workflows', {}, ACTION_ID)).rejects.toMatchObject({ uncertain: true });
      await expect(api.mutate('/workflows', {}, NEXT_ID)).rejects.toMatchObject({
        status,
        reasonCodes: ['FORBIDDEN'],
      });
      expect(api.unresolved('/workflows')?.actionId).toBe(ACTION_ID);
      await expect(api.mutate('/workflows', { changed: true }, NEXT_ID)).rejects.toMatchObject({
        reasonCodes: ['COMMIT_OUTCOME_UNKNOWN'],
      });
      expect(fetcher).toHaveBeenCalledTimes(2);
    },
  );
});

describe('concurrent and session-local mutation recovery', () => {
  it('coalesces an in-flight remount and retains a newer unknown action after the old completion', async () => {
    const first = deferred<Response>();
    const second = deferred<Response>();
    const fetcher = vi.fn().mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const api = new FuseApi('synthetic', fetcher);
    const a = api.mutate('/workflows', { amountKrw: 10 }, ACTION_ID);
    const remount = api.mutate('/workflows', { amountKrw: 10 }, NEXT_ID);
    await expect(api.mutate('/workflows', { amountKrw: 20 }, NEXT_ID)).rejects.toMatchObject({
      uncertain: true,
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    first.resolve(json(receipt(), 202));
    await a;
    const b = api.mutate('/workflows', { amountKrw: 20 }, NEXT_ID);
    const failed = expect(b).rejects.toMatchObject({ uncertain: true });
    await remount;
    expect(api.unresolved('/workflows')).toEqual({
      path: '/workflows',
      body: { amountKrw: 20 },
      actionId: NEXT_ID,
    });
    second.reject(new TypeError('newer response lost'));
    await failed;
    expect(api.unresolved('/workflows')).toEqual({
      path: '/workflows',
      body: { amountKrw: 20 },
      actionId: NEXT_ID,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('retains the original record after concurrent callers receive the same malformed response', async () => {
    const response = deferred<Response>();
    const fetcher = vi
      .fn()
      .mockReturnValueOnce(response.promise)
      .mockResolvedValueOnce(json(receipt({ replayed: true })));
    const api = new FuseApi('synthetic', fetcher);
    const first = expect(api.mutate('/workflows', { amountKrw: 10 }, ACTION_ID)).rejects.toMatchObject({
      uncertain: true,
    });
    const second = expect(api.mutate('/workflows', { amountKrw: 10 }, NEXT_ID)).rejects.toMatchObject({
      uncertain: true,
    });
    response.resolve(json({}, 202));
    await Promise.all([first, second]);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const exposed = api.unresolved('/workflows')!;
    (exposed.body as { amountKrw: number }).amountKrw = 99;
    expect(api.unresolved('/workflows')?.body).toEqual({ amountKrw: 10 });
    await api.mutate('/workflows', { amountKrw: 10 }, NEXT_ID);
    expect(fetcher.mock.calls[1][1].headers['Idempotency-Key']).toBe(ACTION_ID);
    expect(api.unresolved('/workflows')).toBeUndefined();
  });

  it('does not share or clear recovery records between token-session clients', async () => {
    const oldResponse = deferred<Response>();
    const oldFetch = vi.fn().mockReturnValueOnce(oldResponse.promise);
    const newFetch = vi.fn().mockRejectedValueOnce(new TypeError('new session response lost'));
    const oldApi = new FuseApi('old-synthetic-token', oldFetch);
    const newApi = new FuseApi('new-synthetic-token', newFetch);
    const old = oldApi.mutate('/workflows', { amountKrw: 10 }, ACTION_ID);
    expect(newApi.unresolved('/workflows')).toBeUndefined();
    await expect(newApi.mutate('/workflows', { amountKrw: 20 }, NEXT_ID)).rejects.toMatchObject({
      uncertain: true,
    });
    oldResponse.resolve(json(receipt()));
    await old;
    expect(newApi.unresolved('/workflows')).toEqual({
      path: '/workflows',
      body: { amountKrw: 20 },
      actionId: NEXT_ID,
    });
    expect(oldFetch.mock.calls[0][1].headers.Authorization).toBe('Bearer old-synthetic-token');
    expect(newFetch.mock.calls[0][1].headers.Authorization).toBe('Bearer new-synthetic-token');
    expect([localStorage.length, sessionStorage.length]).toEqual([0, 0]);
  });
});


describe('read identity across the API/display boundary', () => {
  const otherId = '00000000-0000-0000-0000-000000000002';
  const marker = 'SYNTHETIC_WRONG_ENTITY_RAW_MARKER';
  const traceResponse = (workflowId: string) => ({ workflowId, generation: 1,
    runs: [], results: [], grants: [], dependencies: [], approvals: [], riskEvents: [], payments: [], auditEvents: [],
    extra: { raw: marker } });
  it.each(['trace', 'experiment'] as const)('rejects a valid but foreign %s identity before returning data for display', async method => {
    const data = method === 'trace' ? traceResponse(otherId) : {
      experimentId: otherId, status: 'SYNTHETIC_FUTURE_STATE', progress: null, extra: { raw: marker },
    };
    const fetcher = vi.fn().mockResolvedValue(json(data));
    const api = new FuseApi('synthetic', fetcher);
    try {
      await api[method](WORKFLOW_ID);
      throw new Error('synthetic expected rejection');
    } catch (error) {
      expect(error).toMatchObject({ status: 200, reasonCodes: ['INVALID_RESPONSE'], uncertain: false,
        message: '서버가 올바른 JSON 응답을 보내지 않았어요.' });
      expect((error as Error).message).not.toContain(marker);
      expect(JSON.stringify(error)).not.toContain(marker);
    }
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.unresolved(method === 'trace' ? `/workflows/${WORKFLOW_ID}/trace` : `/experiments/${WORKFLOW_ID}`)).toBeUndefined();
  });
  it('preserves matching trace/experiment payloads and future display facts', async () => {
    const expectedTrace = traceResponse(WORKFLOW_ID);
    const expectedExperiment = { experimentId: WORKFLOW_ID, status: 'SYNTHETIC_FUTURE_STATE', progress: null, results: [] };
    const fetcher = vi.fn().mockResolvedValueOnce(json(expectedTrace)).mockResolvedValueOnce(json(expectedExperiment));
    const api = new FuseApi('synthetic', fetcher);
    await expect(api.trace(WORKFLOW_ID)).resolves.toEqual(expectedTrace);
    await expect(api.experiment(WORKFLOW_ID)).resolves.toEqual(expectedExperiment);
  });
});


describe('optional workflow identity on public detail and preview reads', () => {
  it.each(['workflow', 'preview'] as const)('rejects foreign %s payload without returning raw data, preserves absent/matching identity', async method => {
    const foreign = '00000000-0000-0000-0000-000000000002';
    const marker = 'SYNTHETIC_FOREIGN_OPTIONAL_IDENTITY_MARKER';
    const absent = { customerId: 'synthetic-customer', futureField: { preserved: true }, experimentId: foreign };
    const matching = { ...absent, workflowId: WORKFLOW_ID };
    const fetcher = vi.fn().mockResolvedValueOnce(json({ workflowId: foreign, customerId: marker }))
      .mockResolvedValueOnce(json(absent)).mockResolvedValueOnce(json(matching));
    const api = new FuseApi('synthetic', fetcher);
    try {
      await api[method](WORKFLOW_ID);
      throw new Error('synthetic expected rejection');
    } catch (error) {
      expect(error).toMatchObject({ status: 200, reasonCodes: ['INVALID_RESPONSE'], uncertain: false,
        message: '서버가 올바른 JSON 응답을 보내지 않았어요.' });
      expect(JSON.stringify(error)).not.toContain(marker);
    }
    await expect(api[method](WORKFLOW_ID)).resolves.toEqual(absent);
    await expect(api[method](WORKFLOW_ID)).resolves.toEqual(matching);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(api.unresolved(`/workflows/${WORKFLOW_ID}${method === 'preview' ? '/approval-preview' : ''}`)).toBeUndefined();
  });
});
