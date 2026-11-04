import { describe, expect, it } from 'vitest';
import { validReadEnvelope } from './responseContract';

const ID = '00000000-0000-0000-0000-000000000001';
const trace = {
  workflowId: ID, generation: 1, runs: [], results: [], grants: [], dependencies: [],
  approvals: [], riskEvents: [], payments: [], auditEvents: [],
};

describe('directly consumed read envelopes', () => {
  it.each(['runCount', 'paymentCount'])('validates only directly rendered impact count %s', key => {
    const path = `/incidents/${ID}/impact`;
    for (const invalid of [{}, [], [1], [{ count: 1 }], '1', false, NaN, Infinity]) {
      expect(validReadEnvelope(path, { actual: { [key]: invalid } })).toBe(false);
    }
    for (const leaf of [undefined, null, 0, 1, -1, 0.5]) {
      expect(validReadEnvelope(path, { actual: { [key]: leaf }, potential: { applicationCount: {}, totalAmountKrw: [] } })).toBe(true);
    }
  });
  it('preserves existing unavailable impact roots/actual and untouched potential values', () => {
    const path = `/incidents/${ID}/impact`;
    for (const actual of [undefined, null, {}, [], 'synthetic unavailable', false, 0]) {
      expect(validReadEnvelope(path, { actual, potential: { roles: {}, totalAmountKrw: {}, applicationCount: [] } })).toBe(true);
    }
    for (const root of [undefined, null, [], 'synthetic unavailable', false, 0]) {
      expect(validReadEnvelope(path, root)).toBe(true);
    }
  });
  it.each(['customerId', 'payoutAccountId', 'kycResultId', 'loanResultId', 'loanResultHash', 'evidenceBundleHash', 'reviewSnapshotHash'])('validates preview direct string leaf %s without changing approval content rules', key => {
    const path = `/workflows/${ID}/approval-preview`;
    for (const invalid of [{}, [], ['synthetic'], [{ body: 'synthetic' }], 1, false]) {
      expect(validReadEnvelope(path, { [key]: invalid })).toBe(false);
    }
    for (const leaf of [undefined, null, '', 'synthetic future public value']) {
      expect(validReadEnvelope(path, { [key]: leaf, generation: 1, extra: 'preserved' })).toBe(true);
    }
  });
  it.each([null, [], 'synthetic preview', 1, false])('rejects a nonrecord preview root: %s', value => {
    expect(validReadEnvelope(`/workflows/${ID}/approval-preview`, value)).toBe(false);
  });
  it.each(['customerAlias', 'customerId', 'businessReference', 'payoutAccountId'])('rejects malformed directly rendered workflow text %s', key => {
    for (const invalid of [{}, [], ['synthetic'], [{ text: 'synthetic' }], 1, false]) {
      const row = { [key]: invalid };
      expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(false);
      expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(false);
    }
    for (const leaf of [undefined, null, '', 'synthetic future value']) {
      expect(validReadEnvelope(`/workflows/${ID}`, { [key]: leaf })).toBe(true);
    }
  });
  it.each(['usedRisk', 'reservedRisk', 'riskLimit'])('rejects malformed directly rendered workflow number %s', key => {
    for (const invalid of [{}, [], '1', false, NaN, Infinity, -Infinity]) {
      const row = { [key]: invalid };
      expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(false);
      expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(false);
    }
    for (const leaf of [undefined, null, 0, 1, 0.5, -1]) {
      expect(validReadEnvelope(`/workflows/${ID}`, { [key]: leaf })).toBe(true);
    }
  });
  it.each(['fixtureSetId', 'modelMode'])('validates direct experiment text %s without requiring it or adding enums', key => {
    for (const invalid of [{}, [], ['synthetic'], 1, false]) {
      expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, [key]: invalid })).toBe(false);
    }
    for (const leaf of [undefined, null, '', 'FUTURE_PUBLIC_VALUE']) {
      expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, [key]: leaf })).toBe(true);
    }
  });
  it('validates consumed reason arrays without inventing reason enums', () => {
    for (const reasonCodes of [{}, 'DENY', false, 1, [null], [1], ['EVIDENCE_MISSING', {}]]) {
      const row = { workflowId: ID, reasonCodes };
      expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(false);
      expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(false);
    }
    for (const reasonCodes of [undefined, [], ['EVIDENCE_MISSING'], ['FUTURE_PUBLIC_REASON']]) {
      const row = { workflowId: ID, reasonCodes };
      expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(true);
      expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(true);
    }
  });
  it('preserves nullable list reasons where join has a fallback but rejects null detail reasons', () => {
    const row = { workflowId: ID, reasonCodes: null };
    expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(true);
    expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(false);
  });
  it('checks explicitly present permission booleans without requiring new workflow fields', () => {
    for (const field of ['canApprove', 'canResume']) {
      for (const invalid of ['false', 'true', 0, 1, null, {}, []]) {
        const row = { workflowId: ID, [field]: invalid };
        expect(validReadEnvelope(`/workflows/${ID}`, row)).toBe(false);
        expect(validReadEnvelope('/workflows', { items: [row], total: 1, page: 0, size: 20 })).toBe(false);
      }
      for (const flag of [false, true]) expect(validReadEnvelope(`/workflows/${ID}`, { [field]: flag })).toBe(true);
    }
    expect(validReadEnvelope(`/workflows/${ID}`, { workflowId: ID })).toBe(true);
  });
  it('accepts empty/populated lists and preserves the original response and extra fields', () => {
    const row = Object.freeze({ workflowId: ID, state: 'PAID', extra: 'synthetic field' });
    const value = Object.freeze({ items: Object.freeze([row]), total: 1, page: 0, size: 20, executionMode: 'VIRTUAL_SIMULATION' });
    expect(validReadEnvelope('/workflows?size=20&page=0', value)).toBe(true);
    expect(value.items[0]).toBe(row);
    expect(validReadEnvelope('/workflows', { items: [], total: 0, page: 2147483647, size: 100 })).toBe(true);
  });
  it.each(['total', 'page', 'size'])('rejects malformed list %s scalars', key => {
    for (const value of [null, {}, '1', -1, 0.5, NaN, Infinity, 2147483648]) {
      expect(validReadEnvelope('/workflows', { items: [], total: 0, page: 0, size: 20, [key]: value })).toBe(false);
    }
  });
  it.each(['runs', 'results', 'grants', 'dependencies', 'approvals', 'riskEvents', 'payments', 'auditEvents', 'sourceUses', 'evidenceUses'])('rejects invalid trace collection %s', key => {
    for (const value of [null, {}, 'synthetic body', [null], [1], [[]]]) {
      expect(validReadEnvelope(`/workflows/${ID}/trace`, { ...trace, [key]: value })).toBe(false);
    }
    expect(validReadEnvelope(`/workflows/${ID}/trace`, { ...trace, [key]: [{}] })).toBe(true);
  });
  it('preserves absent optional trace collections and legacy experiment progress forms', () => {
    expect(validReadEnvelope(`/workflows/${ID}/trace`, trace)).toBe(true);
    for (const progress of [0, 3, { completed: 0, total: 3 }, { completedPairs: 1, totalPairs: 3 }]) {
      expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, progress })).toBe(true);
    }
    for (const size of [0, 101]) expect(validReadEnvelope('/workflows', { items: [], total: 0, page: 0, size })).toBe(false);
  });
  it('preserves optional experiment absence/nulls and unmeasured display facts', () => {
    expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID })).toBe(true);
    expect(validReadEnvelope(`/experiments/${ID}`, {
      experimentId: ID, caseOutputs: null, results: [], exclusions: null, progress: null,
      metrics: { forbiddenActionBlockRate: null, exclusions: [], extra: 'synthetic' },
    })).toBe(true);
  });
  it.each(['caseOutputs', 'results', 'exclusions'])('rejects invalid experiment %s containers', key => {
    for (const value of [{}, 'synthetic', [null], [false]]) {
      expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, [key]: value })).toBe(false);
    }
  });
  it('rejects malformed trace identity/generation and experiment metrics/progress without inventing row enums', () => {
    expect(validReadEnvelope(`/workflows/${ID}/trace`, { ...trace, workflowId: {} })).toBe(false);
    expect(validReadEnvelope(`/workflows/${ID}/trace`, { ...trace, generation: 0.5 })).toBe(false);
    expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, metrics: [] })).toBe(false);
    expect(validReadEnvelope(`/experiments/${ID}`, { experimentId: ID, progress: 'running' })).toBe(false);
  });
});


describe('requested read identity binding', () => {
  const otherId = '00000000-0000-0000-0000-000000000002';
  it('rejects another workflow trace even when its entire envelope is well formed', () => {
    expect(validReadEnvelope(`/workflows/${ID}/trace`, { ...trace, workflowId: otherId })).toBe(false);
    expect(validReadEnvelope(`/workflows/${ID}/trace?view=synthetic`, trace)).toBe(true);
  });
  it('rejects another experiment without narrowing status, progress or optional facts', () => {
    const response = { experimentId: otherId, status: 'SYNTHETIC_FUTURE_STATE', progress: null, caseOutputs: null };
    expect(validReadEnvelope(`/experiments/${ID}`, response)).toBe(false);
    expect(validReadEnvelope(`/experiments/${otherId}?view=synthetic`, response)).toBe(true);
    expect(response.experimentId).toBe(otherId);
    expect(response.status).toBe('SYNTHETIC_FUTURE_STATE');
  });
});


describe('present optional workflow identity binding', () => {
  const foreign = '00000000-0000-0000-0000-000000000002';
  it.each(['', '/approval-preview'])('binds present workflowId on %s while preserving absence and future fields', suffix => {
    const path = `/workflows/${ID}${suffix}`;
    expect(validReadEnvelope(path, { workflowId: foreign })).toBe(false);
    expect(validReadEnvelope(path, { workflowId: ID })).toBe(true);
    // Other unknown keys are not interpreted as identity aliases or new policy.
    expect(validReadEnvelope(path, { experimentId: foreign, futureField: { value: true } })).toBe(true);
    expect(validReadEnvelope(`${path}?view=future`, { workflowId: ID, futureField: ['preserved'] })).toBe(true);
  });
});
