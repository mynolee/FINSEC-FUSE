import { describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { parseSimulationFixtureRegistry, SimulationRegistryProtocolError } from './simulationFixtures';

const registry = () => ({
  fixtureSets: [{
    fixtureSetId: 'synthetic-ui-suite',
    caseIds: ['synthetic-first', 'synthetic-second'],
    modelModes: ['REPLAY'],
    resultsSource: 'VIRTUAL_SIMULATION',
  }],
  executionMode: 'VIRTUAL_NON_DURABLE',
});
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

describe('explicit synthetic registry protocol and authenticated reads', () => {
  it('copies and freezes registered identifiers without substituting historical datasets', () => {
    const input = registry();
    const parsed = parseSimulationFixtureRegistry(input);
    input.fixtureSets[0].caseIds[0] = 'synthetic-changed';
    expect(parsed.fixtureSets[0].caseIds).toEqual(['synthetic-first', 'synthetic-second']);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.fixtureSets)).toBe(true);
    expect(Object.isFrozen(parsed.fixtureSets[0].caseIds)).toBe(true);
    expect(parsed.fixtureSets[0].fixtureSetId).toBe('synthetic-ui-suite');
  });
  it('accepts an empty registry as no available plan rather than inventing a default', () => {
    expect(parseSimulationFixtureRegistry({ executionMode: 'VIRTUAL_NON_DURABLE', fixtureSets: [] }).fixtureSets).toEqual([]);
  });
  it('rejects unknown execution/results modes, LIVE capability and extra metadata', () => {
    const variants: unknown[] = [
      { ...registry(), executionMode: 'PRODUCTION' },
      { ...registry(), hiddenDefault: 'mvp-security-v1' },
      { ...registry(), fixtureSets: [{ ...registry().fixtureSets[0], modelModes: ['REPLAY', 'LIVE'] }] },
      { ...registry(), fixtureSets: [{ ...registry().fixtureSets[0], resultsSource: 'JAVA_POSTGRES_EXECUTION' }] },
      { ...registry(), fixtureSets: [{ ...registry().fixtureSets[0], providerPrompt: 'synthetic-only-marker' }] },
    ];
    for (const input of variants) expect(() => parseSimulationFixtureRegistry(input)).toThrow(SimulationRegistryProtocolError);
  });
  it('rejects ambiguous identity lists and unregistered historical names', () => {
    const duplicate = registry();
    duplicate.fixtureSets.push({ ...duplicate.fixtureSets[0] });
    const duplicateCases = registry();
    duplicateCases.fixtureSets[0].caseIds.push(duplicateCases.fixtureSets[0].caseIds[0]);
    const historical = registry();
    historical.fixtureSets[0].fixtureSetId = 'mvp-security-v1';
    const noCases = registry();
    noCases.fixtureSets[0].caseIds = [];
    for (const input of [duplicate, duplicateCases, historical, noCases])
      expect(() => parseSimulationFixtureRegistry(input)).toThrow(SimulationRegistryProtocolError);
  });
  it('uses the same-origin bearer GET route and preserves abort ownership', async () => {
    const fetcher = vi.fn().mockResolvedValue(json(registry()));
    const controller = new AbortController();
    const data = await new FuseApi('synthetic-registry-token', fetcher).simulationFixtures(controller.signal);
    expect(data.fixtureSets[0].caseIds).toEqual(['synthetic-first', 'synthetic-second']);
    expect(fetcher).toHaveBeenCalledWith('/api/v1/simulation/fixtures', expect.objectContaining({
      method: 'GET',
      headers: { Authorization: 'Bearer synthetic-registry-token', Accept: 'application/json' },
      credentials: 'omit',
      cache: 'no-store',
      signal: expect.any(AbortSignal),
    }));
    expect(fetcher.mock.calls[0][1]).not.toHaveProperty('body');
    expect(fetcher.mock.calls[0][1].headers).not.toHaveProperty('Idempotency-Key');
  });
  it.each([401, 403, 503])('propagates status %s without another request or legacy fallback', async (status) => {
    const marker = 'synthetic-private-registry-marker';
    const fetcher = vi.fn().mockResolvedValue(json({ reasonCodes: [marker], message: marker }, status));
    const failure = await new FuseApi('synthetic-registry-token', fetcher).simulationFixtures().catch((error: unknown) => error);
    expect(failure).toMatchObject({
      status, uncertain: false,
      reasonCodes: [status === 401 ? 'UNAUTHENTICATED' : status === 403 ? 'FORBIDDEN' : 'DEPENDENCY_UNAVAILABLE'],
    });
    expect(String(failure)).not.toContain(marker);
    expect(JSON.stringify(failure)).not.toContain(marker);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('reports malformed success metadata with a fixed error and no reflected field text', async () => {
    const fetcher = vi.fn().mockResolvedValue(json({ ...registry(), syntheticDiagnostic: 'synthetic-private-marker' }));
    const api = new FuseApi('synthetic-registry-token', fetcher);
    await expect(api.simulationFixtures()).rejects.toMatchObject({
      status: 200, uncertain: false, reasonCodes: ['INVALID_RESPONSE'],
      message: '등록된 합성 데이터 응답을 확인하지 못했어요.',
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(api.unresolved('/experiments')).toBeUndefined();
  });
  it('propagates caller cancellation without replacing it with a dependency error', async () => {
    const controller = new AbortController();
    controller.abort();
    const cancellation = new DOMException('synthetic cancellation', 'AbortError');
    const fetcher = vi.fn().mockRejectedValue(cancellation);
    await expect(new FuseApi('synthetic-registry-token', fetcher).simulationFixtures(controller.signal)).rejects.toBe(cancellation);
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it('does not expose a late diagnostic when an injected transport ignores caller cancellation', async () => {
    const controller = new AbortController();
    controller.abort();
    const marker = 'synthetic-private-registry-marker';
    const fetcher = vi.fn().mockResolvedValue(json({ message: marker, reasonCodes: [marker] }, 503));
    const failure = await new FuseApi('synthetic-registry-token', fetcher).simulationFixtures(controller.signal).catch((error: unknown) => error);
    expect(failure).toMatchObject({ name: 'AbortError' });
    expect(String(failure)).not.toContain(marker);
  });
});
