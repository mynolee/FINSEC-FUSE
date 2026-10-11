/** Export only fixed evidence fields. Arbitrary model/database text stays private. */
import labelContract from '../../evaluation/export_labels.json';
import type { Experiment, Row } from './types';

const labels = new Set(labelContract.labels);
const object = (value: unknown): Row =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? (value as Row) : {};
const array = (value: unknown): Row[] =>
  Array.isArray(value)
    ? value.filter((item) => item !== null && typeof item === 'object' && !Array.isArray(item))
    : [];
const label = (value: unknown) => (typeof value === 'string' && labels.has(value) ? value : null);
const number = (value: unknown) => (typeof value === 'number' && Number.isFinite(value) ? value : null);
const boolean = (value: unknown) => (typeof value === 'boolean' ? value : null);
const hash = (value: unknown) => (typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) ? value : null);
const id = (value: unknown) =>
  typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value)
    ? value
    : null;
const reason = (value: unknown) =>
  typeof value === 'string'
    ? value
        .split(';')
        .map((part) => label(part) ?? 'REDACTED_LABEL')
        .join(';')
    : null;
const timestamp = (value: unknown) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value) &&
  Number.isFinite(Date.parse(value))
    ? value
    : null;

const traceIds = new Set([
  'id',
  'workflowId',
  'traceId',
  'bindingId',
  'requestId',
  'runId',
  'actionId',
  'resultId',
  'grantId',
  'parent',
  'sourceRunId',
  'targetRunId',
  'parentRunId',
  'childRunId',
  'parentResultId',
  'approvalId',
  'reservationId',
  'paymentId',
  'quarantineId',
  'documentId',
  'evidenceId',
  'jobId',
]);
const traceHashes = new Set([
  'inputSnapshotHash',
  'requestByteHash',
  'responseByteHash',
  'resultHash',
  'evidenceBundleHash',
  'reviewSnapshotHash',
  'contentHash',
  'promptHash',
  'modelOutputHash',
]);
const traceNumbers = new Set([
  'generation',
  'agentVersion',
  'runIndex',
  'depth',
  'extraRisk',
  'riskLimit',
  'points',
  'amountKrw',
  'documentVersion',
  'elapsedNanos',
  'completedCheckCount',
  'committedQuarantineCount',
  'observedDenialCount',
  'commitObservedNanos',
  'executionDeniedNanos',
  'affectedExecutionCount',
]);
const traceLabels = new Set([
  'role',
  'status',
  'source',
  'target',
  'action',
  'stage',
  'eventType',
  'reasonCode',
  'evidenceType',
  'outcome',
  'boundaryVersion',
  'model',
  'modelMode',
  'promptVersion',
  'attempt',
]);
const traceTimes = new Set([
  'createdAt',
  'startedAt',
  'completedAt',
  'expiresAt',
  'committedAt',
  'observedAt',
]);
const traceBooleans = new Set(['bindingVerified', 'quarantineLatencyMeasured']);
const traceCollections = [
  'runs',
  'results',
  'grants',
  'dependencies',
  'approvals',
  'riskEvents',
  'payments',
  'auditEvents',
  'sourceUses',
  'evidenceUses',
  'armBindings',
];

function traceRecord(value: unknown): Row {
  const result: Row = {};
  for (const [key, item] of Object.entries(object(value))) {
    if (traceIds.has(key)) result[key] = id(item);
    else if (traceHashes.has(key)) result[key] = hash(item);
    else if (traceNumbers.has(key)) result[key] = number(item);
    else if (traceLabels.has(key)) result[key] = label(item);
    else if (traceTimes.has(key)) result[key] = timestamp(item);
    else if (traceBooleans.has(key)) result[key] = boolean(item);
  }
  return result;
}

export function sanitizeExperimentTrace(value: unknown): Row {
  const trace = object(value);
  const result: Row = {
    sanitizationVersion: 'FUSE-EXPORT-ALLOWLIST-1',
    rawTextOmitted: true,
    ...traceRecord(trace),
  };
  for (const collection of traceCollections) {
    if (Array.isArray(trace[collection])) result[collection] = array(trace[collection]).map(traceRecord);
  }
  for (const field of ['securityMeasurement', 'quarantineMeasurement']) {
    if (trace[field] && typeof trace[field] === 'object') {
      const source = object(trace[field]);
      const clean = traceRecord(source);
      if (field === 'quarantineMeasurement' && Array.isArray(source.incidents)) {
        clean.incidents = array(source.incidents).map((incident) => ({
          ...traceRecord(incident),
          firstDenial: incident.firstDenial ? traceRecord(incident.firstDenial) : null,
        }));
      }
      result[field] = clean;
    }
  }
  if (trace.modelCapture && typeof trace.modelCapture === 'object') {
    const source = object(trace.modelCapture);
    const candidate = object(source.modelOutput);
    result.modelCapture = {
      ...traceRecord(source),
      captureRequestId: id(source.captureRequestId),
      captureRunId: id(source.captureRunId),
      sanitizedCandidate: {
        status: ['VERIFIED', 'NEEDS_REVIEW', 'NOT_VERIFIED'].includes(String(candidate.status))
          ? candidate.status
          : null,
        evidenceIds: Array.isArray(candidate.evidenceIds) ? candidate.evidenceIds.map(id) : null,
        textFieldsOmitted: true,
      },
    };
  }
  return result;
}

const metricNumbers = [
  'plannedAttacks',
  'plannedNormals',
  'commonEligibleAttackPairs',
  'commonEligibleNormalPairs',
  'excludedPairCount',
  'normalEvaluableCount',
  'normalEnvironmentFailureCount',
  'forbiddenPaymentCount',
  'forbiddenPaidAmountKrw',
  'maximumActualDownstreamDepth',
  'meanSecurityCheckDurationMs',
  'meanQuarantineLatencyMs',
];
const metricRatios = ['forbiddenActionBlockRate', 'normalFalseBlockRate', 'unrelatedNormalContinuity'];
function sanitizedMetrics(value: unknown, nested = false, allowSplits = true): Row {
  const source = object(value);
  const result: Row = {};
  for (const key of metricNumbers) if (key in source) result[key] = number(source[key]);
  for (const key of metricRatios) {
    if (key in source) {
      const ratio = object(source[key]);
      result[key] = {
        numerator: number(ratio.numerator),
        denominator: number(ratio.denominator),
        rate: number(ratio.rate),
      };
    }
  }
  for (const key of ['syntheticModelOutputs', 'liveRobustnessMeasured'])
    if (key in source) result[key] = boolean(source[key]);
  if (Array.isArray(source.exclusions))
    result.exclusions = array(source.exclusions).map((item) => ({
      caseId: label(item.caseId),
      repeat: number(item.repeat),
      reason: reason(item.reason),
    }));
  if (!nested && source.environments) {
    const environments = object(source.environments);
    result.environments = Object.fromEntries(
      ['BASELINE', 'FUSE']
        .filter((env) => env in environments)
        .map((env) => [env, sanitizedMetrics(environments[env], true)]),
    );
  }
  if (!nested && allowSplits && source.bySplit) {
    const splits = object(source.bySplit);
    result.bySplit = Object.fromEntries(
      ['DEV', 'TUNE', 'FINAL', 'NORMAL']
        .filter((split) => split in splits)
        .map((split) => [split, sanitizedMetrics(splits[split], false, false)]),
    );
  }
  return result;
}

const rowLabels = [
  'caseId',
  'environment',
  'status',
  'state',
  'decision',
  'family',
  'kind',
  'split',
  'pairedInputVersion',
  'policyVersion',
  'model',
  'promptVersion',
  'mockReviewerVersion',
];
const rowHashes = [
  'fixtureHash',
  'pairedInputHash',
  'inputSnapshotHash',
  'modelOutputHash',
  'responseByteHash',
];
const observedNumbers = [
  'forbiddenPaymentCount',
  'forbiddenPaidAmountKrw',
  'actualDownstreamDepth',
  'unrelatedNormalExpected',
  'unrelatedNormalCompleted',
  'securityCheckDurationMs',
  'quarantineLatencyMs',
];
const observedBooleans = ['attackInduced', 'policyBlocked', 'normalExpectedReached'];
const pairKey = (row: Row) => `${String(row.caseId)}:${String(row.repeat ?? 1)}`;

export function sanitizedExperiment(experiment: Experiment): Row & { caseOutputs: Row[]; metrics: Row } {
  const rows = array(experiment.caseOutputs || experiment.results);
  const rawMetrics = object(experiment.metrics);
  const metricsEvaluated =
    number(rawMetrics.commonEligibleAttackPairs) !== null &&
    number(rawMetrics.commonEligibleNormalPairs) !== null &&
    Array.isArray(rawMetrics.exclusions);
  const commonExclusions = new Map<string, string | null>();
  for (const item of array(experiment.exclusions || rawMetrics.exclusions)) {
    const key = typeof item.pair === 'string' ? item.pair : pairKey(item);
    commonExclusions.set(
      key,
      reason(item.reason) ?? (Array.isArray(item.reasons) ? item.reasons.map(reason).join(';') : null),
    );
  }
  for (const row of rows) {
    const pair = rows.filter((other) => pairKey(other) === pairKey(row));
    if (!commonExclusions.has(pairKey(row))) {
      if (pair.length !== 2 || new Set(pair.map((other) => other.environment)).size !== 2)
        commonExclusions.set(pairKey(row), 'INCOMPLETE_PAIR');
      else if (
        pair.some((other) => other.status === 'ERROR' || other.decision === 'ERROR' || other.exclusionReason)
      )
        commonExclusions.set(
          pairKey(row),
          reason(pair.find((other) => other.exclusionReason)?.exclusionReason) ?? 'ENVIRONMENT_ERROR',
        );
    }
  }
  const caseOutputs = rows.map((row) => {
    const clean: Row = {};
    const observed = row.status === 'COMPLETED';
    for (const field of rowLabels) clean[field] = label(row[field]);
    for (const field of rowHashes) clean[field] = hash(row[field]);
    clean.repeat = number(row.repeat);
    clean.reasonCodes = Array.isArray(row.reasonCodes) ? row.reasonCodes.map(reason) : null;
    clean.exclusionReason = reason(row.exclusionReason);
    clean.commonExclusionReason = commonExclusions.get(pairKey(row)) ?? null;
    clean.includedInCommonDenominator = commonExclusions.has(pairKey(row))
      ? false
      : observed && metricsEvaluated
        ? true
        : null;
    for (const field of observedNumbers) clean[field] = observed ? number(row[field]) : null;
    for (const field of observedBooleans) clean[field] = observed ? boolean(row[field]) : null;
    const trace = object(row.trace);
    clean.workflowId = id(trace.workflowId);
    clean.traceId = id(trace.traceId);
    clean.usedRisk = observed ? number(trace.usedRisk) : null;
    clean.reservedRisk = observed ? number(trace.reservedRisk) : null;
    clean.quarantined = observed ? boolean(trace.quarantined) : null;
    const expected = object(object(trace.expected)[String(row.environment)]);
    clean.expected = {
      state: label(expected.state),
      decision: label(expected.decision),
      reasonCode: label(expected.reasonCode),
      forbiddenPaymentCount: number(expected.forbiddenPaymentCount),
    };
    clean.trace = sanitizeExperimentTrace(trace);
    return clean;
  });
  const result: Row & { caseOutputs: Row[]; metrics: Row } = {
    exportVersion: 'FUSE-UI-EVIDENCE-1',
    sanitized: true,
    privacy:
      'Only allowlisted evidence metadata is included. Unknown labels are null; private prompts, documents, candidate explanations and raw database bodies are omitted.',
    measurementScope:
      'Server-reported observations and metrics; the browser does not run experiments or recalculate effectiveness. Use the Python evidence bundle for reproducible file hashes and full fixture selection.',
    experimentId: id(experiment.experimentId),
    caseOutputs,
    metrics: sanitizedMetrics(rawMetrics),
  };
  for (const key of [
    'reportVersion',
    'fixtureSetId',
    'status',
    'state',
    'modelMode',
    'mode',
    'resultsSource',
  ])
    if (key in experiment) result[key] = label(experiment[key]);
  for (const key of ['fixtureHash']) if (key in experiment) result[key] = hash(experiment[key]);
  for (const key of ['repeatCount', 'completedRuns', 'totalRuns'])
    if (key in experiment) result[key] = number(experiment[key]);
  for (const key of ['syntheticModelOutputs', 'liveRobustnessMeasured'])
    if (key in experiment) result[key] = boolean(experiment[key]);
  for (const key of ['createdAt', 'startedAt', 'completedAt'])
    if (key in experiment) result[key] = timestamp(experiment[key]);
  return result;
}

export function csvCell(value: unknown) {
  const raw =
    value === null || value === undefined
      ? 'null'
      : typeof value === 'object'
        ? JSON.stringify(value)
        : String(value);
  const unsafeText =
    typeof value === 'string' && (/^[\u0000-\u0020\uFEFF]*[=+\-@]/.test(raw) || /^[\t\r\n]/.test(raw));
  const safe = unsafeText ? `'${raw}` : raw;
  return `"${safe.replaceAll('"', '""')}"`;
}
export const EVIDENCE_CSV_COLUMNS = [
  'caseId',
  'environment',
  'repeat',
  'status',
  'state',
  'decision',
  'reasonCodes',
  'commonExclusionReason',
  'exclusionReason',
  'includedInCommonDenominator',
  'attackInduced',
  'policyBlocked',
  'normalExpectedReached',
  'forbiddenPaymentCount',
  'forbiddenPaidAmountKrw',
  'actualDownstreamDepth',
  'unrelatedNormalExpected',
  'unrelatedNormalCompleted',
  'securityCheckDurationMs',
  'quarantineLatencyMs',
  'usedRisk',
  'reservedRisk',
  'quarantined',
  'fixtureHash',
  'pairedInputVersion',
  'pairedInputHash',
  'inputSnapshotHash',
  'modelOutputHash',
  'responseByteHash',
  'policyVersion',
  'model',
  'promptVersion',
  'mockReviewerVersion',
  'workflowId',
  'traceId',
];
export function experimentCsv(experiment: Experiment): string {
  const rows = sanitizedExperiment(experiment).caseOutputs;
  return (
    '\uFEFF' +
    [
      EVIDENCE_CSV_COLUMNS.map(csvCell).join(','),
      ...rows.map((row) => EVIDENCE_CSV_COLUMNS.map((key) => csvCell(row[key])).join(',')),
    ].join('\r\n')
  );
}
