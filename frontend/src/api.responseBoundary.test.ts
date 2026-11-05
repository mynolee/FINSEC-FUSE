import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';

const requestId = '00000000-0000-4000-8000-000000000001';
const workflowId = '00000000-0000-4000-8000-000000000002';
const receipt = { requestId, workflowId, generation: 1, state: 'KYC_PENDING', decision: 'ALLOW', reasonCodes: [], message: 'PRIVATE_MESSAGE', replayed: false };
const json = (text: string, status = 200) => new Response(text, { status, headers: { 'Content-Type': 'application/json' } });
describe('active FuseApi bounded response integration', () => {
  it('uses development byte and depth guards on active reads without calling native json', async () => {
    const response = json(' '.repeat(1048576) + '{}'); const fallback = vi.spyOn(response, 'json');
    await expect(new FuseApi('synthetic', vi.fn().mockResolvedValue(response)).workflows()).rejects.toMatchObject({ reasonCodes: ['INVALID_RESPONSE'], uncertain: false });
    expect(fallback).not.toHaveBeenCalled();
    const deep = json('['.repeat(33) + '0' + ']'.repeat(33));
    await expect(new FuseApi('synthetic', vi.fn().mockResolvedValue(deep)).workflows()).rejects.toMatchObject({ reasonCodes: ['INVALID_RESPONSE'] });
  });
  it('rejects duplicate decision wire keys and retains the exact original mutation for reconciliation', async () => {
    const text = JSON.stringify(receipt).replace('"decision":"ALLOW"', '"decision":"DENY","decision":"ALLOW"');
    const fetcher = vi.fn().mockResolvedValue(json(text)); const api = new FuseApi('synthetic', fetcher);
    const body = { customerId: 'synthetic-customer' };
    await expect(api.mutate('/workflows', body, requestId)).rejects.toMatchObject({ uncertain: true, reasonCodes: ['INVALID_RESPONSE'] });
    expect(api.unresolved('/workflows')).toEqual({ path: '/workflows', body, actionId: requestId });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('bounds an error body and never clears an older unknown on a later definitive denial', async () => {
    const fetcher = vi.fn().mockResolvedValueOnce(json(' '.repeat(65), 503)).mockResolvedValueOnce(json('{"code":"FORBIDDEN"}', 403));
    const api = new FuseApi('synthetic', fetcher, { maxResponseBytes: 64, maxJsonDepth: 32 });
    await expect(api.mutate('/workflows', {}, requestId)).rejects.toMatchObject({ uncertain: true, status: 503 });
    await expect(api.mutate('/workflows', {}, workflowId)).rejects.toMatchObject({ uncertain: false, status: 403 });
    expect(api.unresolved('/workflows')?.actionId).toBe(requestId);
    expect(fetcher).toHaveBeenCalledTimes(2);
    const options = fetcher.mock.calls[1][1] as RequestInit;
    expect(options.headers).toMatchObject({ 'Idempotency-Key': requestId }); expect(options.body).toBe('{}');
  });
  it('preserves accepted matching receipts, route headers and the configured finite limit snapshot', async () => {
    const wire = JSON.stringify(receipt); const limits = { maxResponseBytes: new TextEncoder().encode(wire).length, maxJsonDepth: 2 };
    const fetcher = vi.fn().mockResolvedValue(json(wire)); const api = new FuseApi('synthetic', fetcher, limits);
    limits.maxResponseBytes = 1;
    const result = await api.mutate('/workflows', {}, requestId);
    expect(result.requestId).toBe(requestId); expect(result.message).not.toContain('PRIVATE_MESSAGE');
    expect(api.unresolved('/workflows')).toBeUndefined();
    expect(fetcher).toHaveBeenCalledWith('/api/v1/workflows', expect.objectContaining({ method: 'POST', credentials: 'omit', cache: 'no-store', headers: expect.objectContaining({ Authorization: 'Bearer synthetic', 'Idempotency-Key': requestId }) }));
  });
});
