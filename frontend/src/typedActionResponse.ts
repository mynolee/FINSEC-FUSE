/** Published typed-action outcome parsing only: no transport, command creation, authority or retry. */
export const TYPED_ACTION_PURPOSES = ['ROOT_PROVISION', 'KYC_PREPARATION', 'KYC_COMPLETION', 'PAYMENT_REVIEW',
  'PAYMENT_RESERVATION', 'MOCK_PAYMENT_COMPLETION', 'CONTINUATION'] as const;
export type TypedActionPurpose = typeof TYPED_ACTION_PURPOSES[number];
const STATUSES = ['VIRTUAL_COMMITTED_IN_PROCESS', 'VIRTUAL_REPLAYED_IN_PROCESS', 'NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH',
  'REFUSED_BEFORE_ADMISSION', 'UNCONFIRMED_BEFORE_ADMISSION', 'IDENTITY_CONFLICT', 'COMMIT_UNKNOWN',
  'RECONCILIATION_UNCONFIRMED', 'TRANSACTION_INVARIANT_UNCONFIRMED'] as const;
export type TypedActionStatus = typeof STATUSES[number];
export interface ExpectedTypedAction {
  readonly commandRef: string; readonly purpose: TypedActionPurpose; readonly requestId: string;
  readonly workflowId: string; readonly requestedGeneration: number;
}
export interface TypedActionOutcome extends ExpectedTypedAction {
  readonly schemaVersion: 1; readonly status: TypedActionStatus; readonly effectKnowledge: string;
  readonly replayed: boolean; readonly executionMode: 'VIRTUAL_SIMULATION';
  readonly actualAuthority: false; readonly durable: false; readonly executionAuthorityGranted: false;
  readonly receipt?: Readonly<Record<string, string | number>>;
}
export class TypedActionResponseError extends Error {
  constructor() { super('INVALID_TYPED_ACTION_RESPONSE'); this.name = 'TypedActionResponseError'; }
}
const fail = (): never => { throw new TypedActionResponseError(); };
function object(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return fail();
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || (!required.includes(key) && !optional.includes(key))) return fail();
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return fail();
    result[key] = descriptor.value;
  }
  if (required.some(key => !Object.hasOwn(result, key))) return fail();
  return result;
}
function uuid(value: unknown): string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
    ? value : fail();
}
function generation(value: unknown): number {
  return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 2147483647 ? value : fail();
}
function member<T extends string>(value: unknown, choices: readonly T[]): T {
  return typeof value === 'string' && choices.includes(value as T) ? value as T : fail();
}
const IDENTITY = ['commandRef', 'purpose', 'requestId', 'workflowId', 'requestedGeneration'] as const;
const BASE = ['schemaVersion', ...IDENTITY, 'status', 'effectKnowledge', 'replayed', 'executionMode',
  'actualAuthority', 'durable', 'executionAuthorityGranted'] as const;
const NO_NEW: Record<TypedActionPurpose, string> = {
  ROOT_PROVISION: 'NO_NEW_ROOT_PROVISION_ATTEMPT_THIS_INVOCATION',
  KYC_PREPARATION: 'NO_NEW_PREPARATION_ATTEMPT_THIS_INVOCATION',
  KYC_COMPLETION: 'NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION',
  PAYMENT_REVIEW: 'NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION', PAYMENT_RESERVATION: 'NO_NEW_PLAN_ATTEMPT_THIS_INVOCATION',
  MOCK_PAYMENT_COMPLETION: 'NO_NEW_CONSUMPTION_ATTEMPT_THIS_INVOCATION',
  CONTINUATION: 'NO_NEW_CONTINUATION_ATTEMPT_THIS_INVOCATION',
};
function receipt(value: unknown, purpose: TypedActionPurpose, requestedGeneration: number): Readonly<Record<string, string | number>> {
  const ids = ['grantId', 'actionId', 'targetRunId'];
  const base = ['kind', ...ids];
  const extra: Record<TypedActionPurpose, string[]> = {
    ROOT_PROVISION: [], KYC_PREPARATION: ['decision', 'refusal'], KYC_COMPLETION: ['resultId'],
    PAYMENT_REVIEW: ['approvalId', 'decision'], PAYMENT_RESERVATION: ['approvalId', 'decision', 'reservationId', 'paymentId'],
    MOCK_PAYMENT_COMPLETION: ['resultId', 'paymentId', 'approvalId', 'reservationId'],
    CONTINUATION: ['continuationKind', 'committedGeneration'],
  };
  const row = object(value, [...base, ...extra[purpose]]);
  const kinds: Record<TypedActionPurpose, string> = { ROOT_PROVISION: 'ROOT_PROVISION', KYC_PREPARATION: 'KYC_PREPARATION',
    KYC_COMPLETION: 'CONSUMPTION', PAYMENT_REVIEW: 'REVIEW', PAYMENT_RESERVATION: 'RESERVE',
    MOCK_PAYMENT_COMPLETION: 'CONSUMPTION', CONTINUATION: 'CONTINUATION' };
  if (row.kind !== kinds[purpose]) return fail();
  const clean: Record<string, string | number> = { kind: kinds[purpose] };
  for (const key of [...ids, ...extra[purpose].filter(key => key.endsWith('Id'))]) clean[key] = uuid(row[key]);
  if (purpose === 'KYC_PREPARATION') {
    clean.decision = member(row.decision, ['PREPARED', 'ON_HOLD']);
    clean.refusal = member(row.refusal, ['NONE', 'KYC_PRECONDITION_FAILED', 'RISK_LIMIT_EXCEEDED']);
    if ((clean.decision === 'PREPARED') !== (clean.refusal === 'NONE')) return fail();
  }
  if (purpose === 'PAYMENT_REVIEW' || purpose === 'PAYMENT_RESERVATION') clean.decision = member(row.decision, ['APPROVE', 'REJECT']);
  if (purpose === 'PAYMENT_RESERVATION' && clean.decision !== 'APPROVE') return fail();
  if (purpose === 'CONTINUATION') {
    clean.continuationKind = member(row.continuationKind, ['ADVANCED', 'DENIED']);
    clean.committedGeneration = generation(row.committedGeneration);
    if (clean.committedGeneration !== (clean.continuationKind === 'ADVANCED' ? requestedGeneration : requestedGeneration - 1)) return fail();
  }
  if (purpose === 'MOCK_PAYMENT_COMPLETION' && clean.paymentId !== clean.resultId) return fail();
  return Object.freeze(clean);
}
/** Expected values must come from actual prepared server metadata. Matching them is not authorization. */
export function parseTypedActionOutcome(value: unknown, expected: ExpectedTypedAction, httpStatus: number): TypedActionOutcome {
  try {
    const wanted = object(expected, IDENTITY); const row = object(value, BASE, ['receipt']);
    const identity = { commandRef: uuid(row.commandRef), purpose: member(row.purpose, TYPED_ACTION_PURPOSES),
      requestId: uuid(row.requestId), workflowId: uuid(row.workflowId), requestedGeneration: generation(row.requestedGeneration) };
    uuid(wanted.commandRef); member(wanted.purpose, TYPED_ACTION_PURPOSES); uuid(wanted.requestId);
    uuid(wanted.workflowId); generation(wanted.requestedGeneration);
    if (IDENTITY.some(key => identity[key] !== wanted[key]) || row.schemaVersion !== 1 || row.executionMode !== 'VIRTUAL_SIMULATION'
        || row.actualAuthority !== false || row.durable !== false || row.executionAuthorityGranted !== false) return fail();
    const status = member(row.status, STATUSES);
    const committed = status === 'VIRTUAL_COMMITTED_IN_PROCESS' || status === 'VIRTUAL_REPLAYED_IN_PROCESS';
    const unknown = ['NO_COMMIT_OBSERVED_IN_PROCESS_EPOCH', 'COMMIT_UNKNOWN', 'RECONCILIATION_UNCONFIRMED',
      'TRANSACTION_INVARIANT_UNCONFIRMED'].includes(status);
    const requiredHttp = committed || status === 'REFUSED_BEFORE_ADMISSION' ? 200 : status === 'IDENTITY_CONFLICT' ? 409 : 503;
    if (httpStatus !== requiredHttp || row.replayed !== (status === 'VIRTUAL_REPLAYED_IN_PROCESS')
        || row.effectKnowledge !== (committed ? 'COMMITTED_IN_PROCESS' : unknown ? 'UNKNOWN' : NO_NEW[identity.purpose])
        || Object.hasOwn(row, 'receipt') !== committed) return fail();
    return Object.freeze({ schemaVersion: 1, ...identity, status, effectKnowledge: row.effectKnowledge as string,
      replayed: status === 'VIRTUAL_REPLAYED_IN_PROCESS', executionMode: 'VIRTUAL_SIMULATION',
      actualAuthority: false, durable: false, executionAuthorityGranted: false,
      ...(committed ? { receipt: receipt(row.receipt, identity.purpose, identity.requestedGeneration) } : {}) });
  } catch { throw new TypedActionResponseError(); }
}
