import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DISPLAY_MAX_ITEMS, DISPLAY_MAX_TEXT, DISPLAY_TRUNCATED, projectDisplay, type DisplayProfile } from './displayProjection';
import { Json, RecordTable } from './components/ui';
import { GrantRecords } from './components/Workflows';
import { describeExperimentIssue } from './components/Experiments';

const PRIVATE = 'SYNTHETIC_UNEXPECTED_PRIVATE_VALUE';
const ID = '00000000-0000-4000-8000-000000000701';
const profiles: DisplayProfile[] = [
  'candidate', 'run', 'result', 'evidence', 'source', 'grant', 'risk', 'approval',
  'payment', 'audit', 'target', 'calculationRefs', 'impact', 'caseOutput', 'exclusion', 'metrics',
  'experiment', 'retry',
];

describe('investigation JSON display boundaries', () => {
  it.each(profiles)('%s omits unknown fields and credential aliases without mutating the source', profile => {
    const source = Object.freeze({
      workflowId: ID, generation: 2, unexpected: PRIVATE, authorization: PRIVATE,
      apiKey: PRIVATE, privateKey: PRIVATE, cookie: PRIVATE, leaseToken: PRIVATE,
      metadata: Object.freeze({ display: PRIVATE }),
    });
    const displayed = JSON.stringify(projectDisplay(source, profile));
    expect(displayed).not.toContain(PRIVATE);
    expect(source.unexpected).toBe(PRIVATE);
    expect(source.authorization).toBe(PRIVATE);
  });

  it('keeps only typed grant identifiers, action and stored lifecycle metadata', () => {
    const source = Object.freeze({ grantId: ID, actionId: ID, targetRunId: ID, workflowId: ID,
      generation: 2, action: 'EVALUATE_KYC', state: 'ISSUED', status: 'ISSUED',
      role: PRIVATE, depth: 3, expiresAt: PRIVATE, token: PRIVATE, mac: PRIVATE,
      bindingBytes: [PRIVATE], canonical: { value: PRIVATE }, providerStatus: PRIVATE });
    expect(projectDisplay(source, 'grant')).toEqual({ grantId: ID, actionId: ID,
      targetRunId: ID, workflowId: ID, generation: 2, action: 'EVALUATE_KYC', state: 'ISSUED', status: 'ISSUED' });
    expect(JSON.stringify(projectDisplay(source, 'grant'))).not.toContain(PRIVATE);
    expect(source.token).toBe(PRIVATE);
    // A missing stored status stays absent; no provider state or lifecycle is invented.
    expect(projectDisplay({ grantId: ID, providerStatus: 'VALIDATED' }, 'grant')).toEqual({ grantId: ID });
  });

  it('keeps typed result profile and digest as scalar metadata without raw binding material', () => {
    const row = { resultId: ID, runId: ID, workflowId: ID, generation: 2,
      bindingProfile: 'AGENT_RESULT_BINDING_RECORD_1', bindingDigest: 'a'.repeat(64),
      bindingBytes: [PRIVATE], canonicalBytes: PRIVATE, receiptBytes: PRIVATE,
      canonicalBody: { text: PRIVATE }, businessConclusion: PRIVATE, token: PRIVATE };
    expect(projectDisplay(row, 'result')).toEqual({ resultId: ID, runId: ID, workflowId: ID,
      generation: 2, bindingProfile: 'AGENT_RESULT_BINDING_RECORD_1', bindingDigest: 'a'.repeat(64) });
    expect(JSON.stringify(projectDisplay(row, 'result'))).not.toContain(PRIVATE);
    expect(projectDisplay({ bindingProfile: { value: PRIVATE }, bindingDigest: [PRIVATE] }, 'result')).toEqual({});
  });

  it('does not invoke typed grant or result accessors, iterators or nested serialization hooks', () => {
    let calls = 0;
    const nested = { toJSON() { calls += 1; return PRIVATE; },
      *[Symbol.iterator]() { calls += 1; yield PRIVATE; } };
    const grant = Object.create({ workflowId: PRIVATE });
    Object.defineProperty(grant, 'grantId', { enumerable: true, get() { calls += 1; return PRIVATE; } });
    Object.defineProperty(grant, 'status', { enumerable: true, get() { calls += 1; return PRIVATE; } });
    Object.defineProperty(grant, 'actionId', { value: nested, enumerable: true });
    Object.defineProperty(grant, 'generation', { value: Infinity, enumerable: true });
    expect(projectDisplay(grant, 'grant')).toEqual({});
    const result = { bindingProfile: nested, bindingDigest: nested };
    Object.defineProperty(result, 'resultId', { get() { calls += 1; return PRIVATE; } });
    expect(projectDisplay(result, 'result')).toEqual({});
    expect(calls).toBe(0);
    expect(projectDisplay({ generation: 2, state: 'CONSUMED', status: 'CONSUMED' }, 'grant'))
      .toEqual({ generation: 2, state: 'CONSUMED', status: 'CONSUMED' });
  });

  it('only displays stored grant lifecycle values and omits contradictory status aliases', () => {
    expect(projectDisplay({ state: 'VALIDATED', status: 'ALLOWED' }, 'grant')).toEqual({});
    expect(projectDisplay({ state: null, status: null }, 'grant')).toEqual({});
    expect(projectDisplay({ state: 'ISSUED', status: 'CONSUMED' }, 'grant')).toEqual({ state: 'ISSUED' });
    expect(projectDisplay({ state: 'ISSUED', status: 'ISSUED' }, 'grant')).toEqual({ state: 'ISSUED', status: 'ISSUED' });
    expect(projectDisplay({ status: 'CONSUMED' }, 'grant')).toEqual({ status: 'CONSUMED' });
  });

  it('projects grant primary cells as well as details before rendering untrusted rows', () => {
    let calls = 0;
    const row = { grantId: ID, targetRunId: ID, generation: 2, state: 'ISSUED', status: PRIVATE,
      action: { toString() { calls += 1; return PRIVATE; } }, source: PRIVATE, sourceAgent: PRIVATE,
      target: PRIVATE, targetAgent: PRIVATE, depth: PRIVATE, expiresAt: PRIVATE, token: PRIVATE };
    Object.defineProperty(row, 'workflowId', { get() { calls += 1; return PRIVATE; } });
    const rows = [row, {}];
    Object.defineProperty(rows, '1', { get() { calls += 1; return { grantId: PRIVATE }; } });
    const { container, unmount } = render(<GrantRecords rows={rows} />);
    expect(screen.getByRole('columnheader', { name: '대상 실행 ID' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: '세대' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: '깊이' })).not.toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: '만료' })).not.toBeInTheDocument();
    expect(container.querySelector('pre')?.textContent).toContain(ID);
    expect(container.textContent).not.toContain(PRIVATE);
    expect(calls).toBe(0);
    unmount();
    const many = Array.from({ length: DISPLAY_MAX_ITEMS + 1 }, () => ({ grantId: ID, state: 'ISSUED' }));
    Object.defineProperty(many, String(DISPLAY_MAX_ITEMS), { get() { calls += 1; return { grantId: PRIVATE }; } });
    const capped = render(<GrantRecords rows={many} />);
    expect(capped.container.textContent).toContain(`앞 ${DISPLAY_MAX_ITEMS}개 기록만 표시합니다.`);
    expect(screen.getAllByRole('row')).toHaveLength(DISPLAY_MAX_ITEMS + 1);
    expect(capped.container.textContent).not.toContain(PRIVATE);
    expect(calls).toBe(0);
  });

  it('keeps KYC evidence and loan decision bindings while dropping free text at each nested level', () => {
    const source = {
      resultId: ID, workflowId: ID, role: 'KYC', generation: 2,
      body: { status: 'VERIFIED', evidenceIds: [ID, { value: PRIVATE }],
        inputSnapshotHash: 'a'.repeat(64), explanation: PRIVATE, documentText: PRIVATE,
        authorization: PRIVATE },
      providerMetadata: { diagnostic: PRIVATE },
    };
    expect(projectDisplay(source, 'result')).toEqual({
      resultId: ID, workflowId: ID, role: 'KYC', generation: 2,
      body: { status: 'VERIFIED', evidenceIds: [ID], inputSnapshotHash: 'a'.repeat(64) },
    });
    expect(projectDisplay({ approved: true, policyVersion: 'LOAN-MOCK-1', customerId: 'synthetic-customer',
      amountKrw: 1000, payoutAccountId: ID, kycResultId: ID, note: PRIVATE }, 'candidate')).toEqual({
      approved: true, policyVersion: 'LOAN-MOCK-1', customerId: 'synthetic-customer',
      amountKrw: 1000, payoutAccountId: ID, kycResultId: ID,
    });
  });

  it.each(['ACTIVE', 'REVOKED'])('retains stored evidence %s/PASS separately from server time status', status => {
    const row = {
      runId: ID, evidenceId: ID, evidenceType: 'ID_DOC', outcome: 'PASS', status,
      issuedAt: '2026-10-09T03:00:00Z', expiresAt: '2026-10-09T05:00:00Z',
      temporalStatus: 'WITHIN_PERIOD', privateKey: PRIVATE,
    };
    const projected = projectDisplay(row, 'evidence');
    expect(projected).toEqual({
      runId: ID, evidenceId: ID, evidenceType: 'ID_DOC', outcome: 'PASS', status,
      issuedAt: '2026-10-09T03:00:00Z', expiresAt: '2026-10-09T05:00:00Z', temporalStatus: 'WITHIN_PERIOD',
    });
    const { container } = render(<RecordTable rows={[row]} rowDetails="evidence" columns={[
      { key: 'evidenceType', label: '종류' }, { key: 'outcome', label: '결과' },
      { key: 'status', label: '저장 상태' }, { key: 'temporalStatus', label: '시간 상태' },
    ]} />);
    expect(screen.getByRole('cell', { name: status })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: 'PASS' })).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: 'WITHIN_PERIOD' })).toBeInTheDocument();
    expect(container.textContent).not.toContain(PRIVATE);
  });

  it('preserves existing candidate body aliases only through the closed candidate fact schema', () => {
    for (const field of ['body', 'bodyJson', 'proposal']) {
      const projected = projectDisplay({ resultId: ID, state: 'VALIDATED', [field]: {
        status: 'VERIFIED', evidenceIds: [ID], inputSnapshotHash: 'a'.repeat(64),
        explanation: PRIVATE, apiKey: PRIVATE, nested: { note: PRIVATE },
      } }, 'result');
      expect(projected).toEqual({ resultId: ID, state: 'VALIDATED', [field]: {
        status: 'VERIFIED', evidenceIds: [ID], inputSnapshotHash: 'a'.repeat(64),
      } });
      expect(JSON.stringify(projected)).not.toContain(PRIVATE);
    }
  });

  it('keeps explicitly rendered risk and payment timestamp aliases without arbitrary row metadata', () => {
    const timestamp = '2026-10-09T04:00:00Z';
    expect(projectDisplay({ createdAt: timestamp, eventType: 'RESERVE', points: 0, metadata: PRIVATE }, 'risk'))
      .toEqual({ createdAt: timestamp, eventType: 'RESERVE', points: 0 });
    expect(projectDisplay({ paidAt: timestamp, paymentId: ID, amountKrw: 0, metadata: PRIVATE }, 'payment'))
      .toEqual({ paidAt: timestamp, paymentId: ID, amountKrw: 0 });
  });

  it('preserves incident counts, explicit unknown policy values and calculation references', () => {
    const projected = projectDisplay({
      incidentId: ID, scope: 'SOURCE_VERSION', target: { documentId: ID, documentVersion: 3, apiKey: PRIVATE },
      actual: { paidAmountKrw: 0, atRiskPendingAmountKrw: 2000, leaked: PRIVATE },
      potential: { applicationCount: null, totalAmountKrw: null, roles: [], missingPolicyFields: ['productionPolicy'], debug: PRIVATE },
      calculationRefs: { basis: 'VIRTUAL_OBSERVED_ROWS', quarantineId: ID, workflowIds: [ID], note: PRIVATE },
      historicalRunIds: [ID], currentAffectedWorkflowIds: [ID], paidBeforeQuarantine: false,
    }, 'impact');
    expect(projected.target).toEqual({ documentId: ID, documentVersion: 3 });
    expect(projected.actual).toEqual({ paidAmountKrw: 0, atRiskPendingAmountKrw: 2000 });
    expect(projected.potential).toEqual({ applicationCount: null, totalAmountKrw: null, roles: [], missingPolicyFields: ['productionPolicy'] });
    expect(projected.calculationRefs).toEqual({ basis: 'VIRTUAL_OBSERVED_ROWS', quarantineId: ID, workflowIds: [ID] });
    expect(JSON.stringify(projected)).not.toContain(PRIVATE);
  });

  it('keeps simulation experiment outcomes and denominators without arbitrary nested metadata', () => {
    const projected = projectDisplay({
      experimentId: ID, status: 'COMPLETED', modelMode: 'REPLAY', syntheticModelOutputs: true,
      progress: { completedPairs: 1, totalPairs: 1, diagnostic: PRIVATE },
      metrics: { completedPairs: 1, excludedPairs: 0, eligiblePairs: 1, privateKey: PRIVATE },
      caseOutputs: [{ caseId: 'synthetic-case', repeat: 1, environment: 'FUSE', outcome: 'ALLOWED',
        reasonCodes: ['SYNTHETIC_POLICY_BLOCK'], trace: { modelCapture: { prompt: PRIVATE } }, apiKey: PRIVATE }],
      exclusions: [{ caseId: 'synthetic-excluded', repeat: 2, reason: 'ENVIRONMENT_UNAVAILABLE', note: PRIVATE }],
    }, 'experiment');
    expect(projected.progress).toEqual({ completedPairs: 1, totalPairs: 1 });
    expect(projected.metrics).toEqual({ completedPairs: 1, excludedPairs: 0, eligiblePairs: 1 });
    expect(projected.caseOutputs).toEqual([{ caseId: 'synthetic-case', repeat: 1, environment: 'FUSE', outcome: 'ALLOWED', reasonCodes: ['SYNTHETIC_POLICY_BLOCK'] }]);
    expect(projected.exclusions).toEqual([{ caseId: 'synthetic-excluded', repeat: 2, reason: 'ENVIRONMENT_UNAVAILABLE' }]);
    expect(JSON.stringify(projected)).not.toContain(PRIVATE);
  });

  it('does not recurse into objects placed in scalar slots or unexpected arrays', () => {
    expect(projectDisplay({ runId: { value: PRIVATE }, generation: Infinity, role: [PRIVATE] }, 'run')).toEqual({});
    expect(projectDisplay({ body: [PRIVATE] }, 'result')).toEqual({});
    expect(projectDisplay({ unexpected: PRIVATE })).toEqual({});
  });

  it('renders the projected record details rather than the original response', () => {
    const { container } = render(<RecordTable rows={[{ runId: ID, role: 'KYC', apiKey: PRIVATE, notes: PRIVATE }]}
      columns={[{ key: 'role', label: '역할' }]} rowDetails="run" />);
    expect(screen.getByRole('columnheader', { name: '표시용 기록' })).toBeInTheDocument();
    expect(container.querySelector('pre')?.textContent).toContain(ID);
    expect(container.textContent).not.toContain(PRIVATE);
  });

  it('does not invoke known-field getters or inherit prototype fields', () => {
    let accessed = false;
    const source = Object.create({ role: PRIVATE });
    Object.defineProperty(source, 'runId', { enumerable: true, get() { accessed = true; throw new Error('must not run'); } });
    Object.defineProperty(source, 'generation', { value: 2, enumerable: true });
    expect(projectDisplay(source, 'run')).toEqual({ generation: 2 });
    const nested = Object.create({ numerator: 7 });
    Object.defineProperty(nested, 'rate', { get() { accessed = true; throw new Error('must not run'); } });
    expect(projectDisplay({ forbiddenActionBlockRate: nested }, 'metrics')).toEqual({ forbiddenActionBlockRate: {} });
    expect(accessed).toBe(false);
  });

  it('caps display arrays and text with visible omission markers while preserving source arrays', () => {
    const ids = Array.from({ length: DISPLAY_MAX_ITEMS + 4 }, () => ID);
    const projected = projectDisplay({ evidenceIds: ids, status: 'x'.repeat(DISPLAY_MAX_TEXT + 5) }, 'candidate');
    expect(projected.evidenceIds).toHaveLength(DISPLAY_MAX_ITEMS + 1);
    expect((projected.evidenceIds as unknown[]).at(-1)).toBe(DISPLAY_TRUNCATED);
    expect(projected.displayTruncated).toBe(true);
    expect(projected.status).toBe('x'.repeat(DISPLAY_MAX_TEXT) + DISPLAY_TRUNCATED);
    expect(ids).toHaveLength(DISPLAY_MAX_ITEMS + 4);
    let accessed = false;
    const rows = [ID];
    Object.defineProperty(rows, '0', { get() { accessed = true; return PRIVATE; } });
    expect(projectDisplay({ evidenceIds: rows }, 'candidate')).toEqual({ evidenceIds: [] });
    expect(accessed).toBe(false);
  });

  it('rejects unknown metric keys and text while keeping finite structured denominators and false/zero', () => {
    const projected = projectDisplay({
      [PRIVATE]: 9, completedPairs: 0, eligiblePairs: PRIVATE, liveRobustnessMeasured: false,
      environments: { FUSE: { forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null, extra: PRIVATE }, apiKey: PRIVATE }, [PRIVATE]: { completedPairs: 1 } },
    }, 'metrics');
    expect(projected).toEqual({ completedPairs: 0, liveRobustnessMeasured: false,
      environments: { FUSE: { forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null } } } });
    expect(JSON.stringify(projected)).not.toContain(PRIVATE);
  });

  it('does not echo issue objects, unknown codes or recognized-code free text suffixes', () => {
    expect(describeExperimentIssue({ explanation: PRIVATE })).not.toContain(PRIVATE);
    expect(describeExperimentIssue(PRIVATE)).not.toContain(PRIVATE);
    expect(describeExperimentIssue(`CAPTURE_ERROR:${PRIVATE}`)).toContain('방어 성공이 아닙니다');
    expect(describeExperimentIssue(`CAPTURE_ERROR:${PRIVATE}`)).not.toContain(PRIVATE);
    expect(projectDisplay({ reasonCodes: [`CAPTURE_ERROR:${PRIVATE}`, PRIVATE] }, 'caseOutput')).toEqual({ reasonCodes: ['CAPTURE_ERROR', 'UNRECOGNIZED_ISSUE'] });
  });

  it('retains machine retry mode and expected generation but omits free memo without mutation', () => {
    const request = { mode: 'PAIRED', expectedGeneration: 3, reason: PRIVATE, remediation: { note: PRIVATE, safeDocumentId: ID } };
    expect(projectDisplay(request, 'retry')).toEqual({ mode: 'PAIRED', expectedGeneration: 3, remediation: { safeDocumentId: ID } });
    expect(request.reason).toBe(PRIVATE);
    expect(request.remediation.note).toBe(PRIVATE);
  });

  it('never stringifies malformed default or custom table scalar values', () => {
    let accessed = false;
    const row = { role: { note: PRIVATE }, runId: ID };
    Object.defineProperty(row, 'status', { enumerable: true, get() { accessed = true; return PRIVATE; } });
    const { container } = render(<RecordTable rows={[row]} columns={[
      { key: 'role', label: '역할' },
      { key: 'status', label: '상태', render: item => String(item.status ?? '미제공') },
    ]} />);
    expect(container.textContent).not.toContain(PRIVATE);
    expect(accessed).toBe(false);
  });

  it('keeps projected text literal and exposes no object when no display contract is selected', () => {
    const literal = '<img src=x onerror="syntheticExecuted=1">';
    const { container } = render(<><Json value={{ status: literal, apiKey: PRIVATE }} profile="candidate" />
      <Json value={{ status: PRIVATE }} /></>);
    expect(container.textContent).toContain(literal);
    expect(container.querySelectorAll('img, script')).toHaveLength(0);
    expect(container.textContent).not.toContain(PRIVATE);
    expect(container.querySelectorAll('pre')[1]).toHaveTextContent('{}');
  });
});


describe('structured virtual metrics public display contract', () => {
  it('preserves structured denominators, nullable timing and explicit synthetic provenance', () => {
    const metrics = { resultsSource: 'VIRTUAL_SIMULATION', syntheticModelOutputs: true, liveRobustnessMeasured: false,
      environments: { FUSE: { forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null },
        unrelatedNormalContinuity: { numerator: 1, denominator: 2, rate: 0.5 },
        meanSecurityCheckDurationMs: null, meanQuarantineLatencyMs: null } } };
    expect(projectDisplay(metrics, 'metrics')).toEqual(metrics);
    const { container, unmount } = render(<Json value={metrics} profile="metrics" />);
    expect(container.textContent).toContain('VIRTUAL_SIMULATION');
    expect(container.textContent).toContain('meanSecurityCheckDurationMs');
    expect(container.textContent).toContain('null');
    expect(container.textContent).not.toContain('SYNTHETIC_UNEXPECTED_PRIVATE_VALUE');
    unmount();
  });

  it('omits unsupported provenance and accessors instead of executing or stringifying them', () => {
    let calls = 0;
    const metrics = { resultsSource: 'LIVE', environments: { FUSE: {
      meanSecurityCheckDurationMs: { secret: PRIVATE },
      forbiddenActionBlockRate: { numerator: 1, denominator: 2, rate: 0.5, raw: PRIVATE } } } };
    Object.defineProperty(metrics, 'syntheticModelOutputs', { get() { calls += 1; return true; } });
    expect(projectDisplay(metrics, 'metrics')).toEqual({ environments: { FUSE: {
      forbiddenActionBlockRate: { numerator: 1, denominator: 2, rate: 0.5 } } } });
    expect(calls).toBe(0);
    expect(projectDisplay({ resultsSource: null }, 'metrics')).toEqual({});
  });
});
