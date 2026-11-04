import type { Row } from './types';

// Display limits only: original requests/responses and machine retry bytes stay intact.
export const DISPLAY_MAX_ITEMS = 100;
export const DISPLAY_MAX_TEXT = 512;
export const DISPLAY_TRUNCATED = '… [표시 생략]';
export function ownData(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object') return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  return descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
}
export function displayScalar(value: unknown): string | number | boolean | null | undefined {
  if (typeof value === 'string') return value.length > DISPLAY_MAX_TEXT ? value.slice(0, DISPLAY_MAX_TEXT) + DISPLAY_TRUNCATED : value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value === 'boolean' || value === null) return value;
  return undefined;
}
export function displayRows(value: unknown): unknown[] {
  if (!Array.isArray(value)) return [];
  const length = ownData(value, 'length');
  const count = typeof length === 'number' ? Math.min(length, DISPLAY_MAX_ITEMS) : 0;
  const result: unknown[] = [];
  for (let index = 0; index < count; index += 1) result.push(ownData(value, String(index)));
  return result;
}
export function displayRecord(value: unknown, keys: string[]): Row {
  const result: Row = {};
  for (const key of keys) {
    const scalar = displayScalar(ownData(value, key));
    if (scalar !== undefined) result[key] = scalar;
  }
  return result;
}

const issueCodes = new Set([
  'LIVE_NOT_AVAILABLE', 'MODEL_OUTPUT_INVALID', 'DEPENDENCY_UNAVAILABLE', 'INDUCTION_FAILED',
  'CAPTURE_ERROR', 'ENVIRONMENT_ERROR', 'ENVIRONMENT_UNAVAILABLE', 'UNSUPPORTED_SCENARIO',
  'SYNTHETIC_PAYMENT', 'SYNTHETIC_POLICY_BLOCK', 'SYNTHETIC_REVIEW',
]);
export function displayIssueCode(value: unknown): string {
  if (typeof value !== 'string') return 'UNRECOGNIZED_ISSUE';
  const code = value.slice(0, DISPLAY_MAX_TEXT).split(':', 1)[0];
  return issueCodes.has(code) ? code : 'UNRECOGNIZED_ISSUE';
}

type Field = 'text' | 'number' | 'boolean' | 'texts' | 'issue' | 'issues' | 'ratio' | 'grantState' | 'virtualSource' | Schema | readonly [Schema];
interface Schema { readonly [key: string]: Field }
const fields = (keys: string, kind: Field = 'text'): Schema =>
  Object.fromEntries(keys.split(' ').filter(Boolean).map(key => [key, kind]));

// Investigation display contracts follow the public simulation producers and
// explicit existing UI aliases. These are
// not export contracts: known customer/account bindings and candidate facts remain
// visible. Free-form notes, model/document text, credentials, and unknown fields are
// deliberately omitted at every nested level. Projection never mutates API data.
const binding: Schema = {
  ...fields('workflowId customerId payoutAccountId kycResultId loanResultId evidenceBundleHash loanResultHash policyVersion reviewSnapshotHash'),
  ...fields('generation amountKrw usedRisk reservedRisk riskLimitAfterApproval', 'number'),
};
const candidate: Schema = {
  ...fields('status inputSnapshotHash policyVersion customerId payoutAccountId kycResultId'),
  evidenceIds: 'texts', approved: 'boolean', amountKrw: 'number',
};
const run: Schema = {
  ...fields('runId workflowId role agentId requestId inputSnapshotHash documentId contentHash status state startedAt completedAt'),
  ...fields('generation agentVersion documentVersion', 'number'), evidenceIds: 'texts',
};
const result: Schema = {
  ...fields('resultId runId workflowId role resultHash evidenceBundleHash status state bindingProfile bindingDigest'),
  // Workflows' candidate column accepts these three names, all with the same
  // closed fact schema; none permits arbitrary JSON or free-form text.
  generation: 'number', body: candidate, bodyJson: candidate, proposal: candidate,
};
const evidence: Schema = {
  // Stored ACTIVE/REVOKED and PASS remain independent of temporalStatus.
  // EvidenceTimeStatus.test.tsx and the evidence table establish these aliases.
  ...fields('runId evidenceId evidenceType kind outcome result status issuedAt expiresAt temporalStatus'),
};
const source: Schema = { ...fields('runId documentId contentHash'), documentVersion: 'number' };
const risk: Schema = {
  ...fields('riskEventId workflowId stage eventType actionId runId reservationId createdAt'),
  ...fields('generation points', 'number'),
};
const approval: Schema = {
  ...binding, ...fields('approvalId actorId status expiresAt createdAt'),
  ...fields('extraRiskLimit extraRisk riskLimit', 'number'),
};
const payment: Schema = {
  ...fields('paymentId workflowId reservationId approvalId runId actionId customerId payoutAccountId createdAt paidAt executionMode'),
  ...fields('generation amountKrw', 'number'),
};
const audit: Schema = { ...fields('auditEventId workflowId actionId eventType createdAt') };
// Typed trace grants expose stored lifecycle metadata only. Status is the
// producer's stored-state alias, not validation or execution authority.
const grant: Schema = {
  ...fields('grantId actionId targetRunId workflowId action'),
  generation: 'number', state: 'grantState', status: 'grantState',
};
const target: Schema = { ...fields('runId resultId workflowId documentId agentId'), ...fields('documentVersion agentVersion', 'number') };
const calculationRefs: Schema = { ...fields('basis quarantineId'), workflowIds: 'texts' };
const impact: Schema = {
  ...fields('incidentId scope executionMode'), target,
  historicalRunIds: 'texts', currentAffectedWorkflowIds: 'texts', policyHeldWorkflowIds: 'texts', paidBeforeQuarantine: 'boolean',
  actual: fields('runCount roleCount workflowCount customerCount paymentCount paidAmountKrw atRiskPendingAmountKrw', 'number'),
  potential: {
    ...fields('applicationCount maxDownstreamDepth registeredCustomerCount perApplicationLimitKrw', 'number'),
    ...fields('totalAmountKrw currency'), roles: 'texts', missingPolicyFields: 'texts',
  }, calculationRefs,
};
const exclusion: Schema = { ...fields('caseId pair'), reason: 'issue', reasonCode: 'issue', exclusionReason: 'issue', reasons: 'issues', repeat: 'number' };
const caseOutput: Schema = {
  ...fields('caseId environment outcome sharedProposalHash resultsSource status state actualState decision'),
  ...fields('repeat securityCheckDurationMs quarantineLatencyMs', 'number'),
  ...fields('eligible excluded', 'boolean'), reasonCodes: 'issues', reasonCode: 'issue', exclusionReason: 'issue',
};
const metricValues: Schema = {
  ...fields('completedPairs excludedPairs eligiblePairs eligibleAttackCount policyBlockCount normalEvaluableCount normalFalseBlockCount forbiddenPaidAmountKrw excludedPairCount forbiddenPaymentCount forbiddenPaymentAmountKrw commonAttackDenominator excludedCount additionalSecurityLatencyMs securityCheckDurationMs quarantineLatencyMs plannedAttacks plannedNormals commonEligibleAttackPairs commonEligibleNormalPairs maximumActualDownstreamDepth meanSecurityCheckDurationMs meanQuarantineLatencyMs normalEnvironmentFailureCount', 'number'),
  ...fields('forbiddenActionBlockRate normalFalseBlockRate unrelatedNormalRetentionRate unrelatedNormalContinuity', 'ratio'),
  ...fields('syntheticModelOutputs liveRobustnessMeasured', 'boolean'),
};
const metrics: Schema = { ...metricValues, resultsSource: 'virtualSource', environments: { BASELINE: metricValues, FUSE: metricValues }, exclusions: [exclusion] };
const experiment: Schema = {
  ...fields('experimentId status fixtureSetId modelMode resultsSource executionMode'),
  ...fields('repeatCount totalPairs completedPairs', 'number'), caseIds: 'texts',
  ...fields('syntheticModelOutputs liveRobustnessMeasured', 'boolean'),
  progress: fields('completedPairs totalPairs', 'number'), metrics,
  caseOutputs: [caseOutput], exclusions: [exclusion],
};
const retry: Schema = {
  ...fields('businessReference customerId payoutAccountId decision reviewSnapshotHash scope runId resultId workflowId documentId agentId reasonCode modelMode fixtureSetId mode'),
  ...fields('amountKrw documentVersion agentVersion repeatCount expectedGeneration', 'number'), caseIds: 'texts',
  remediation: { ...fields('safeDocumentId safeAgentId'), ...fields('safeDocumentVersion safeAgentVersion', 'number'), checkEvidenceIds: 'texts' },
};
const schemas = { candidate, run, result, evidence, source, grant, risk, approval, payment, audit, target, calculationRefs, impact, caseOutput, exclusion, metrics, experiment, retry } satisfies Record<string, Schema>;
export type DisplayProfile = keyof typeof schemas;

function project(value: unknown, schema: Schema): Row {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const clean: Row = {};
  for (const [key, field] of Object.entries(schema)) {
    const item = ownData(value, key);
    if (item === undefined) continue;
    if (item === null) { if (field !== 'grantState' && field !== 'virtualSource') clean[key] = null; continue; }
    if (field === 'text') {
      if (typeof item === 'string') clean[key] = displayScalar(item);
    } else if (field === 'virtualSource') {
      if (item === 'VIRTUAL_SIMULATION') clean[key] = item;
    } else if (field === 'grantState') {
      if (item === 'ISSUED' || item === 'CONSUMED') {
        const state = ownData(value, 'state');
        if (key !== 'status' || state === undefined || state === item) clean[key] = item;
      }
    } else if (field === 'number') {
      if (typeof item === 'number' && Number.isFinite(item)) clean[key] = item;
    } else if (field === 'boolean') {
      if (typeof item === 'boolean') clean[key] = item;
    } else if (field === 'issue') {
      clean[key] = displayIssueCode(item);
    } else if (field === 'issues') {
      if (Array.isArray(item)) {
        clean[key] = displayRows(item).map(displayIssueCode);
        if (item.length > DISPLAY_MAX_ITEMS) { (clean[key] as unknown[]).push(DISPLAY_TRUNCATED); clean.displayTruncated = true; }
      }
    } else if (field === 'ratio') {
      if (typeof item === 'number' && Number.isFinite(item)) clean[key] = item;
      else if (item && typeof item === 'object' && !Array.isArray(item)) clean[key] = project(item, fields('numerator denominator rate', 'number'));
    } else if (field === 'texts') {
      if (Array.isArray(item)) {
        clean[key] = displayRows(item).filter(entry => typeof entry === 'string').map(displayScalar);
        if (item.length > DISPLAY_MAX_ITEMS) { (clean[key] as unknown[]).push(DISPLAY_TRUNCATED); clean.displayTruncated = true; }
      }
    } else if (Array.isArray(field)) {
      if (Array.isArray(item)) {
        clean[key] = displayRows(item).map(entry => project(entry, field[0]));
        if (item.length > DISPLAY_MAX_ITEMS) { (clean[key] as unknown[]).push({ displayTruncated: true }); clean.displayTruncated = true; }
      }
    } else if (item && typeof item === 'object' && !Array.isArray(item)) {
      clean[key] = project(item, field as Schema);
    }
  }
  return clean;
}

/** No profile means no arbitrary JSON preview. */
export function projectDisplay(value: unknown, profile?: DisplayProfile): Row {
  return profile ? project(value, schemas[profile]) : {};
}
