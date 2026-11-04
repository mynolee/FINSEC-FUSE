/** Validate the collection envelopes consumed directly by the existing UI.
 * Unknown record fields and intentionally unavailable display scalars stay intact.
 * This is not authorization or a complete schema for every API response.
 */
const record = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);
const rows = (value: unknown) => Array.isArray(value) && value.every(record);
const integer = (value: unknown, minimum = 0, maximum = 2147483647) =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
const optionalRows = (value: Record<string, unknown>, key: string, nullable = false) =>
  value[key] === undefined || (nullable && value[key] === null) || rows(value[key]);
const nullableLeaf = (value: Record<string, unknown>, key: string, kind: 'string' | 'number') => {
  const leaf = value[key];
  return leaf === undefined || leaf === null || (kind === 'string'
    ? typeof leaf === 'string'
    : typeof leaf === 'number' && Number.isFinite(leaf));
};
const workflowView = (value: unknown, nullableReasons = false) => record(value) &&
  ['customerAlias', 'customerId', 'businessReference', 'payoutAccountId'].every(key => nullableLeaf(value, key, 'string')) &&
  ['usedRisk', 'reservedRisk', 'riskLimit'].every(key => nullableLeaf(value, key, 'number')) &&
  ['canApprove', 'canResume'].every(key => !Object.hasOwn(value, key) || typeof value[key] === 'boolean') &&
  (value.reasonCodes === undefined || (nullableReasons && value.reasonCodes === null) ||
    (Array.isArray(value.reasonCodes) && value.reasonCodes.every(code => typeof code === 'string')));

export function validReadEnvelope(path: string, value: unknown): boolean {
  const route = path.split('?', 1)[0];
  if (route === '/workflows') {
    return record(value) && Array.isArray(value.items) && value.items.every(item => workflowView(item, true)) &&
      integer(value.total) && integer(value.page) && integer(value.size, 1, 100);
  }
  const workflowRoute = /^\/workflows\/([^/]+)$/.exec(route);
  if (workflowRoute) return workflowView(value) && record(value) &&
    (value.workflowId === undefined || value.workflowId === workflowRoute[1]);
  const previewRoute = /^\/workflows\/([^/]+)\/approval-preview$/.exec(route);
  if (previewRoute) {
    return record(value) && (value.workflowId === undefined || value.workflowId === previewRoute[1]) &&
      ['customerId', 'payoutAccountId', 'kycResultId', 'loanResultId', 'loanResultHash', 'evidenceBundleHash', 'reviewSnapshotHash']
        .every(key => nullableLeaf(value, key, 'string'));
  }
  const traceRoute = /^\/workflows\/([^/]+)\/trace$/.exec(route);
  if (traceRoute) {
    return record(value) && value.workflowId === traceRoute[1] && integer(value.generation, 1) &&
      ['runs', 'results', 'grants', 'dependencies', 'approvals', 'riskEvents', 'payments', 'auditEvents'].every(key => rows(value[key])) &&
      ['sourceUses', 'evidenceUses'].every(key => optionalRows(value, key));
  }
  if (/^\/incidents\/[^/]+\/impact$/.test(route)) {
    // Optional property access already displays unavailable when actual is absent
    // or not a record. Only these two fields are passed directly to React children.
    return !record(value) || !record(value.actual) ||
      ['runCount', 'paymentCount'].every(key => nullableLeaf(value.actual as Record<string, unknown>, key, 'number'));
  }
  const experimentRoute = /^\/experiments\/([^/]+)$/.exec(route);
  if (experimentRoute) {
    return record(value) && value.experimentId === experimentRoute[1] &&
      ['fixtureSetId', 'modelMode'].every(key => nullableLeaf(value, key, 'string')) &&
      ['caseOutputs', 'results', 'exclusions'].every(key => optionalRows(value, key, true)) &&
      (value.metrics === undefined || value.metrics === null || record(value.metrics)) &&
      (value.progress === undefined || value.progress === null || record(value.progress) ||
        (typeof value.progress === 'number' && Number.isFinite(value.progress)));
  }
  return true;
}
