import { describe, expect, it } from 'vitest';
import { parseTypedActionOutcome, TypedActionResponseError, type ExpectedTypedAction, type TypedActionPurpose } from './typedActionResponse';

const COMMAND = '00000000-0000-4000-8000-000000000921';
const REQUEST = '00000000-0000-4000-8000-000000000922';
const WORKFLOW = '00000000-0000-4000-8000-000000000923';
const GRANT = '00000000-0000-4000-8000-000000000924';
const ACTION = '00000000-0000-4000-8000-000000000925';
const TARGET = '00000000-0000-4000-8000-000000000926';
const RESULT = '00000000-0000-4000-8000-000000000927';
const APPROVAL = '00000000-0000-4000-8000-000000000928';
const RESERVATION = '00000000-0000-4000-8000-000000000929';
const CANARY = 'SYNTHETIC_PRIVATE_TYPED_ACTION_MATERIAL';
function expected(purpose: TypedActionPurpose = 'ROOT_PROVISION'): ExpectedTypedAction {
  return { commandRef: COMMAND, purpose, requestId: REQUEST, workflowId: WORKFLOW, requestedGeneration: purpose === 'CONTINUATION' ? 2 : 1 };
}
const rootReceipt = () => ({ kind: 'ROOT_PROVISION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET });
function sample(purpose: TypedActionPurpose = 'ROOT_PROVISION', receipt: Record<string, unknown> = rootReceipt()): Record<string, unknown> {
  return { schemaVersion: 1, ...expected(purpose), status: 'VIRTUAL_COMMITTED_IN_PROCESS', effectKnowledge: 'COMMITTED_IN_PROCESS',
    replayed: false, executionMode: 'VIRTUAL_SIMULATION', actualAuthority: false, durable: false, executionAuthorityGranted: false, receipt };
}
function rejects(row: unknown, wanted = expected(), status = 200) {
  expect(() => parseTypedActionOutcome(row, wanted, status)).toThrow(TypedActionResponseError);
  try { parseTypedActionOutcome(row, wanted, status); } catch (error) {
    expect((error as Error).message).toBe('INVALID_TYPED_ACTION_RESPONSE');
    expect((error as Error).message).not.toContain(CANARY);
  }
}

describe('published typed outcomes, pure parsing without command acquisition or dispatch', () => {
  it.each([
    ['ROOT_PROVISION', rootReceipt()],
    ['KYC_PREPARATION', { kind: 'KYC_PREPARATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, decision: 'PREPARED', refusal: 'NONE' }],
    ['KYC_COMPLETION', { kind: 'CONSUMPTION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, resultId: RESULT }],
    ['PAYMENT_REVIEW', { kind: 'REVIEW', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, approvalId: APPROVAL, decision: 'APPROVE' }],
    ['PAYMENT_RESERVATION', { kind: 'RESERVE', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, approvalId: APPROVAL, decision: 'APPROVE', reservationId: RESERVATION, paymentId: RESULT }],
    ['MOCK_PAYMENT_COMPLETION', { kind: 'CONSUMPTION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, resultId: RESULT, paymentId: RESULT, approvalId: APPROVAL, reservationId: RESERVATION }],
    ['CONTINUATION', { kind: 'CONTINUATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, continuationKind: 'ADVANCED', committedGeneration: 2 }],
  ] as [TypedActionPurpose, Record<string, unknown>][])('keeps only exact %s virtual outcome fields with false authority', (purpose, receipt) => {
    const raw = sample(purpose, receipt); const parsed = parseTypedActionOutcome(raw, expected(purpose), 200);
    expect(parsed).toEqual(raw); expect(parsed).not.toBe(raw); expect(parsed.receipt).not.toBe(receipt);
    expect(parsed.actualAuthority).toBe(false); expect(parsed.durable).toBe(false); expect(parsed.executionAuthorityGranted).toBe(false);
    expect(Object.isFrozen(parsed)).toBe(true); expect(Object.isFrozen(parsed.receipt)).toBe(true);
  });

  it.each([
    ['REFUSED_BEFORE_ADMISSION', 'NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION', 200],
    ['UNCONFIRMED_BEFORE_ADMISSION', 'NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION', 503],
    ['IDENTITY_CONFLICT', 'NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION', 409],
    ['NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH', 'UNKNOWN', 503], ['COMMIT_UNKNOWN', 'UNKNOWN', 503],
    ['RECONCILIATION_UNCONFIRMED', 'UNKNOWN', 503], ['TRANSACTION_INVARIANT_UNCONFIRMED', 'UNKNOWN', 503],
  ] as [string, string, number][])('preserves %s without manufacturing a receipt or retry permission', (status, effectKnowledge, http) => {
    const raw = sample(); delete raw.receipt; Object.assign(raw, { status, effectKnowledge });
    const parsed = parseTypedActionOutcome(raw, expected(), http);
    expect(parsed.status).toBe(status); expect(parsed).not.toHaveProperty('receipt');
    expect(parsed).not.toHaveProperty('automaticRetryAllowed'); expect(parsed).not.toHaveProperty('role');
  });

  it('keeps replay and committed refusal receipts distinct from authorization or generation success', () => {
    const replay = sample(); replay.status = 'VIRTUAL_REPLAYED_IN_PROCESS'; replay.replayed = true;
    expect(parseTypedActionOutcome(replay, expected(), 200).replayed).toBe(true);
    const onHold = sample('KYC_PREPARATION', { kind: 'KYC_PREPARATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET,
      decision: 'ON_HOLD', refusal: 'RISK_LIMIT_EXCEEDED' });
    expect(parseTypedActionOutcome(onHold, expected('KYC_PREPARATION'), 200).receipt?.decision).toBe('ON_HOLD');
    const denied = sample('CONTINUATION', { kind: 'CONTINUATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET,
      continuationKind: 'DENIED', committedGeneration: 1 });
    expect(parseTypedActionOutcome(denied, expected('CONTINUATION'), 200).receipt?.committedGeneration).toBe(1);
    expect(parseTypedActionOutcome(denied, expected('CONTINUATION'), 200).executionAuthorityGranted).toBe(false);
  });

  it('binds every public identity field and requires native positive Java-int generations', () => {
    for (const key of ['commandRef', 'requestId', 'workflowId']) rejects({ ...sample(), [key]: RESULT });
    rejects({ ...sample(), purpose: 'KYC_COMPLETION' }); rejects({ ...sample(), requestedGeneration: 2 });
    for (const value of [null, true, '1', 0, -1, 1.5, 2147483648, Infinity, NaN]) rejects({ ...sample(), requestedGeneration: value });
    rejects(sample(), { ...expected(), requestId: CANARY });
    rejects({ ...sample(), requestId: REQUEST.toUpperCase().replace('000000000922', '00000000092A') });
  });

  it('rejects wrong status, nullable/extra fields and contradictory HTTP, receipt, replay, authority or effect', () => {
    for (const delta of [{ schemaVersion: true }, { schemaVersion: '1' }, { status: 'ACTIVE' }, { status: null }, { receipt: null },
      { actualAuthority: true }, { durable: true }, { executionAuthorityGranted: true }, { replayed: true },
      { executionMode: 'LIVE' }, { effectKnowledge: 'UNKNOWN' }, { source: CANARY }, { customerId: CANARY }]) rejects({ ...sample(), ...delta });
    const missing = sample(); delete missing.receipt; rejects(missing);
    rejects(sample(), expected(), 503); rejects(sample(), expected(), 201);
    const unknown = { ...sample(), status: 'COMMIT_UNKNOWN', effectKnowledge: 'UNKNOWN' }; rejects(unknown, expected(), 503);
    rejects({ ...sample(), receipt: { ...rootReceipt(), raw: CANARY } });
    rejects(sample('KYC_PREPARATION', { kind: 'KYC_PREPARATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, decision: 'ON_HOLD', refusal: 'NONE' }), expected('KYC_PREPARATION'));
    rejects(sample('PAYMENT_RESERVATION', { kind: 'RESERVE', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, approvalId: APPROVAL, decision: 'REJECT', reservationId: RESERVATION, paymentId: RESULT }), expected('PAYMENT_RESERVATION'));
    rejects(sample('MOCK_PAYMENT_COMPLETION', { kind: 'CONSUMPTION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET, resultId: RESULT, paymentId: COMMAND, approvalId: APPROVAL, reservationId: RESERVATION }), expected('MOCK_PAYMENT_COMPLETION'));
  });

  it('never invokes accessors, nested serializers or implicit coercion to recover malformed values', () => {
    let calls = 0;
    const hostile = { toJSON() { calls += 1; return CANARY; }, toString() { calls += 1; return COMMAND; } };
    rejects({ ...sample(), workflowId: hostile });
    const getter = sample(); Object.defineProperty(getter, 'receipt', { get() { calls += 1; return rootReceipt(); } }); rejects(getter);
    const nested = rootReceipt(); Object.defineProperty(nested, 'grantId', { get() { calls += 1; return GRANT; } }); rejects(sample('ROOT_PROVISION', nested));
    const wanted = expected(); Object.defineProperty(wanted, 'workflowId', { get() { calls += 1; return WORKFLOW; } }); rejects(sample(), wanted);
    rejects(Object.assign(Object.create({ inherited: CANARY }), sample()));
    rejects({ ...sample(), [Symbol('unknown')]: hostile });
    expect(calls).toBe(0); // Outside parser catch: callback execution cannot be masked by normalization.
  });

  it('returns a fresh immutable snapshot without retaining mutable receipt or expected objects', () => {
    const raw = sample(); const wanted = expected(); const parsed = parseTypedActionOutcome(raw, wanted, 200);
    (raw.receipt as Record<string, unknown>).grantId = RESULT; raw.status = 'ACTIVE';
    (wanted as { workflowId: string }).workflowId = RESULT;
    expect(parsed.receipt?.grantId).toBe(GRANT); expect(parsed.status).toBe('VIRTUAL_COMMITTED_IN_PROCESS');
    expect(parsed.workflowId).toBe(WORKFLOW); expect(Reflect.set(parsed, 'workflowId', RESULT)).toBe(false);
  });

  it('does not reinterpret existing fixed A01 errors or bare metadata as a typed mutation success', () => {
    rejects({ decision: 'ERROR', reasonCodes: ['FORBIDDEN'], message: 'FORBIDDEN' }, expected(), 403);
    rejects({ ...expected(), schemaVersion: 1, customerId: 'synthetic-customer', executionMode: 'VIRTUAL_SIMULATION',
      actualAuthority: false, durable: false, executionAuthorityGranted: false });
    rejects(null); rejects([]); rejects(CANARY);
  });

  it('joins continuation receipt generation to the exact requested next generation', () => {
    const wire = (kind: string, committedGeneration: number) => sample('CONTINUATION', {
      kind: 'CONTINUATION', grantId: GRANT, actionId: ACTION, targetRunId: TARGET,
      continuationKind: kind, committedGeneration,
    });
    for (const [kind, committed] of [['ADVANCED', 2], ['DENIED', 1]] as [string, number][]) {
      const parsed = parseTypedActionOutcome(wire(kind, committed), expected('CONTINUATION'), 200);
      expect(parsed.receipt?.committedGeneration).toBe(committed);
      expect(parsed.receipt?.continuationKind).toBe(kind);
    }
    // Otherwise identical published shape: only the native generation join is wrong.
    for (const [kind, committed] of [['ADVANCED', 1], ['ADVANCED', 3], ['DENIED', 2], ['DENIED', 3]] as [string, number][])
      rejects(wire(kind, committed), expected('CONTINUATION'));
  });
});
