import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { FuseApi } from './api';
import { ExperimentsPage } from './components/Experiments';
import {
  csvCell,
  EVIDENCE_CSV_COLUMNS,
  experimentCsv,
  sanitizedExperiment,
  sanitizeExperimentTrace,
} from './experimentExport';
import type { Experiment, Row } from './types';

const ID = '00000000-0000-4000-8000-000000000301';
const CANARY = 'CANARY_9F643A';
function experiment(): Experiment {
  return {
    experimentId: ID,
    reportVersion: 'FUSE-EVALUATION-2',
    fixtureSetId: 'security-evaluation-v1',
    fixtureHash: 'a'.repeat(64),
    status: 'COMPLETED',
    modelMode: 'REPLAY',
    resultsSource: 'JAVA_POSTGRES_EXECUTION',
    syntheticModelOutputs: true,
    liveRobustnessMeasured: false,
    repeatCount: 1,
    caseOutputs: ['BASELINE', 'FUSE'].map((environment) => ({
      caseId: 'A_EVIDENCE_01',
      environment,
      repeat: 1,
      status: 'COMPLETED',
      state: environment === 'BASELINE' ? 'PAID' : 'BLOCKED',
      decision: environment === 'BASELINE' ? 'ALLOW' : 'DENY',
      reasonCodes: ['EVIDENCE_MISSING'],
      attackInduced: true,
      policyBlocked: environment === 'FUSE',
      forbiddenPaymentCount: environment === 'BASELINE' ? 1 : 0,
      forbiddenPaidAmountKrw: environment === 'BASELINE' ? 1000000 : 0,
      securityCheckDurationMs: 0.5,
      quarantineLatencyMs: null,
      fixtureHash: 'a'.repeat(64),
      pairedInputVersion: 'FUSE-PAIRED-INPUT-1',
      pairedInputHash: 'b'.repeat(64),
      inputSnapshotHash: 'c'.repeat(64),
      responseByteHash: 'd'.repeat(64),
      modelOutputHash: 'e'.repeat(64),
      model: 'replay',
      promptVersion: 'KYC-PROMPT-1',
      policyVersion: 'FUSE-MVP-2',
      mockReviewerVersion: 'MOCK-REVIEWER-1',
      trace: {
        workflowId: ID,
        traceId: ID,
        usedRisk: 10,
        reservedRisk: 0,
        results: [{ resultId: ID, resultHash: 'f'.repeat(64), bodyJson: { explanation: CANARY } }],
        armBindings: [
          {
            bindingId: ID,
            runId: ID,
            inputSnapshotHash: 'c'.repeat(64),
            responseByteHash: 'd'.repeat(64),
            bindingVerified: true,
            responseBytes: CANARY,
          },
        ],
        modelCapture: {
          modelMode: 'LIVE',
          model: 'replay',
          promptHash: 'a'.repeat(64),
          modelOutputHash: 'e'.repeat(64),
          captureRequestId: ID,
          modelOutput: { status: 'VERIFIED', evidenceIds: [ID], explanation: CANARY },
          prompt: CANARY,
        },
        auditEvents: [{ id: ID, actorId: CANARY, detailsJson: { value: CANARY } }],
        expected: { BASELINE: { state: 'BLOCKED', reasonCode: 'EVIDENCE_MISSING' } },
        documents: [{ text: CANARY }],
        token: CANARY,
        unknown: { raw: CANARY },
      },
      providerMessage: CANARY,
    })),
    metrics: {
      plannedAttacks: 1,
      plannedNormals: 0,
      commonEligibleAttackPairs: 1,
      excludedPairCount: 0,
      exclusions: [],
      environments: {
        BASELINE: {
          forbiddenActionBlockRate: { numerator: 0, denominator: 1, rate: 0 },
          meanQuarantineLatencyMs: null,
        },
        FUSE: {
          forbiddenActionBlockRate: { numerator: 1, denominator: 1, rate: 1 },
          meanQuarantineLatencyMs: null,
        },
      },
    },
    unknown: CANARY,
    limitations: [CANARY],
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('safe experiment evidence downloads', () => {
  it('uses fixed fields and removes private nested content from JSON and CSV', () => {
    const source = experiment();
    const safe = sanitizedExperiment(source);
    const serialized = JSON.stringify(safe);
    const csv = experimentCsv(source);
    expect(serialized).not.toContain(CANARY);
    expect(csv).not.toContain(CANARY);
    for (const key of [
      'bodyJson',
      'responseBytes',
      'actorId',
      'detailsJson',
      'explanation',
      'providerMessage',
    ]) {
      expect(serialized).not.toContain(`"${key}"`);
      expect(csv).not.toContain(`"${key}"`);
    }
    expect(safe.exportVersion).toBe('FUSE-UI-EVIDENCE-1');
    expect(safe.sanitized).toBe(true);
    expect(safe.caseOutputs[0].state).toBe('PAID');
    expect(safe.caseOutputs[0].expected).toMatchObject({ state: 'BLOCKED' });
    expect(safe.caseOutputs[0].responseByteHash).toBe('d'.repeat(64));
    const trace = safe.caseOutputs[0].trace as Row;
    expect(trace.armBindings).toEqual([
      {
        bindingId: ID,
        runId: ID,
        inputSnapshotHash: 'c'.repeat(64),
        responseByteHash: 'd'.repeat(64),
        bindingVerified: true,
      },
    ]);
    expect(safe.metrics).toEqual(source.metrics);
    expect(csv.split('\r\n')).toHaveLength(3);
    expect(csv.split('\r\n')[0].slice(1)).toBe(EVIDENCE_CSV_COLUMNS.map(csvCell).join(','));
    expect(EVIDENCE_CSV_COLUMNS).not.toContain('trace');
  });

  it.each(['ghp_' + 'A'.repeat(36), 'github_pat_' + 'B'.repeat(40), CANARY, 'eyJabc.eyJdef.signature'])(
    'rejects unrecognized externally supplied label values: %s',
    (value) => {
      const safe = sanitizeExperimentTrace({
        model: value,
        promptVersion: value,
        status: value,
        reasonCode: value,
        runId: value,
      });
      expect(safe).toMatchObject({
        model: null,
        promptVersion: null,
        status: null,
        reasonCode: null,
        runId: null,
      });
      expect(JSON.stringify(safe)).not.toContain(value);
    },
  );

  it('retains errors in both arms with common exclusion and null unmeasured counts', () => {
    const source = experiment();
    Object.assign(source.caseOutputs![1], {
      status: 'ERROR',
      decision: 'ERROR',
      exclusionReason: 'DATABASE_UNAVAILABLE',
      forbiddenPaymentCount: 0,
      securityCheckDurationMs: 0,
    });
    const safe = sanitizedExperiment(source);
    expect(safe.caseOutputs).toHaveLength(2);
    for (const row of safe.caseOutputs) {
      expect(row.commonExclusionReason).toBe('DATABASE_UNAVAILABLE');
      expect(row.includedInCommonDenominator).toBe(false);
    }
    expect(safe.caseOutputs[0].state).toBe('PAID');
    expect(safe.caseOutputs[1]).toMatchObject({
      status: 'ERROR',
      decision: 'ERROR',
      forbiddenPaymentCount: null,
      securityCheckDurationMs: null,
      policyBlocked: null,
    });
  });

  it('does not claim denominator inclusion before server metrics establish it', () => {
    const source = experiment();
    source.metrics = {};
    const safe = sanitizedExperiment(source);
    expect(safe.caseOutputs.every((row) => row.includedInCommonDenominator === null)).toBe(true);
  });

  it('keeps incomplete observed rows rather than inventing missing results', () => {
    const source = experiment();
    source.caseOutputs = source.caseOutputs!.slice(0, 1);
    source.status = 'INTERRUPTED';
    const safe = sanitizedExperiment(source);
    expect(safe.status).toBe('INTERRUPTED');
    expect(safe.caseOutputs).toHaveLength(1);
    expect(safe.caseOutputs[0]).toMatchObject({
      state: 'PAID',
      commonExclusionReason: 'INCOMPLETE_PAIR',
      includedInCommonDenominator: false,
    });
  });

  it('preserves null rates and approved numeric metrics but removes arbitrary metric bodies', () => {
    const source = experiment();
    source.metrics = {
      plannedAttacks: 0,
      exclusions: [],
      notes: CANARY,
      environments: {
        FUSE: {
          forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null, raw: CANARY },
          raw: CANARY,
        },
      },
      bySplit: {
        FINAL: {
          plannedAttacks: 0,
          environments: { FUSE: { forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null } } },
        },
        unknown: CANARY,
      },
    };
    const safe = sanitizedExperiment(source);
    expect(JSON.stringify(safe)).not.toContain(CANARY);
    expect((safe.metrics.environments as Row).FUSE).toEqual({
      forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null },
    });
    expect((safe.metrics.bySplit as Row).FINAL).toEqual({
      plannedAttacks: 0,
      environments: { FUSE: { forbiddenActionBlockRate: { numerator: 0, denominator: 0, rate: null } } },
    });
  });

  it('retains quarantine measurement endpoint evidence without lease credentials', () => {
    const safe = sanitizeExperimentTrace({
      quarantineMeasurement: {
        boundaryVersion: 'QUARANTINE-COMMIT-TO-EXECUTION-DENIAL-1',
        committedQuarantineCount: 2,
        observedDenialCount: 1,
        incidents: [
          {
            quarantineId: ID,
            commitObservedNanos: 100,
            affectedExecutionCount: 1,
            firstDenial: {
              workflowId: ID,
              runId: ID,
              jobId: ID,
              attempt: 'KYC_RESULT_APPLY',
              executionDeniedNanos: 102,
              elapsedNanos: 2,
              leaseToken: CANARY,
            },
          },
          { quarantineId: ID, firstDenial: null },
        ],
      },
    });
    const incidents = (safe.quarantineMeasurement as Row).incidents as Row[];
    expect(incidents[0].firstDenial).toMatchObject({
      elapsedNanos: 2,
      attempt: 'KYC_RESULT_APPLY',
      jobId: ID,
    });
    expect(incidents[1].firstDenial).toBeNull();
    expect(JSON.stringify(safe)).not.toContain(CANARY);
  });

  it.each([
    '=SUM(A1)',
    '+SUM(A1)',
    '-SUM(A1)',
    '@SUM(A1)',
    '  =SUM(A1)',
    '\t=SUM(A1)',
    '\r\n=SUM(A1)',
    '\uFEFF=SUM(A1)',
  ])('guards spreadsheet formula interpretation including leading whitespace: %s', (formula) => {
    expect(csvCell(formula)).toBe(`"'${formula}"`);
  });
  it('keeps null, zero and false distinct in CSV', () => {
    expect(csvCell(null)).toBe('"null"');
    expect(csvCell(0)).toBe('"0"');
    expect(csvCell(-1.5)).toBe('"-1.5"');
    expect(csvCell('한국어, \"인용\"\n다음')).toBe('"한국어, \"\"인용\"\"\n다음"');
    expect(csvCell(false)).toBe('"false"');
  });

  it('downloads only sanitized JSON/CSV through the visible buttons', async () => {
    const source = experiment();
    const blobs: Blob[] = [];
    const names: string[] = [];
    const NativeURL = URL;
    vi.stubGlobal(
      'URL',
      class extends NativeURL {
        static createObjectURL(blob: Blob) {
          blobs.push(blob);
          return 'blob:evidence-test';
        }
        static revokeObjectURL() {}
      },
    );
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(
        async () => new Response(JSON.stringify(source), { headers: { 'Content-Type': 'application/json' } }),
      );
    render(<ExperimentsPage api={new FuseApi('opaque-test', fetcher)} id={ID} />);
    fireEvent.click(await screen.findByRole('button', { name: '정제 JSON 내보내기' }));
    await waitFor(() => expect(blobs).toHaveLength(1));
    fireEvent.click(screen.getByRole('button', { name: 'CSV 내보내기' }));
    await waitFor(() => expect(blobs).toHaveLength(2));
    expect(screen.queryByRole('button', { name: '원시 JSON' })).not.toBeInTheDocument();
    expect(screen.getByText(/CSV와 JSON은 정제된 근거만/)).toBeInTheDocument();
    expect(blobs).toHaveLength(2);
    const contents = await Promise.all(
      blobs.map(
        (blob) =>
          new Promise<string>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result));
            reader.onerror = reject;
            reader.readAsText(blob);
          }),
      ),
    );
    expect(JSON.parse(contents[0]).sanitized).toBe(true);
    expect(names[0]).toBe(`finsec-${ID}-sanitized.json`);
    expect(contents.every((content) => !content.includes(CANARY))).toBe(true);
    expect(contents[1]).not.toContain('bodyJson');
  });
});

describe('v2.1 current export authorization', () => {
  it.each([401, 403])('emits no file when scope recheck returns HTTP %s', async (status) => {
    const create = vi.fn();
    vi.stubGlobal(
      'URL',
      class extends URL {
        static createObjectURL = create;
        static revokeObjectURL() {}
      },
    );
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => new Response(JSON.stringify(experiment())));
    // Completing the experiment changes the polling interval and triggers another query.
    // Settle all authorized initial reads before revoking access for the export recheck.
    await act(async () => {
      render(<ExperimentsPage api={new FuseApi('synthetic', fetcher)} id={ID} />);
    });
    const exportButton = screen.getByRole('button', { name: '정제 JSON 내보내기' });
    expect(screen.getByText('security-evaluation-v1')).toBeInTheDocument();
    expect(screen.getAllByText('A_EVIDENCE_01').length).toBeGreaterThan(0);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    const initialReadCount = fetcher.mock.calls.length;
    fetcher.mockImplementation(
      async () => new Response(JSON.stringify({ reasonCodes: ['FORBIDDEN'] }), { status }),
    );

    await act(async () => {
      fireEvent.click(exportButton);
    });
    expect(screen.getByRole('alert')).toHaveTextContent(`HTTP ${status}`);
    expect(fetcher).toHaveBeenCalledTimes(initialReadCount + 1);
    expect(create).not.toHaveBeenCalled();
    expect(fetcher.mock.calls.every(([url]) => url === `/api/v1/experiments/${ID}`)).toBe(true);
    expect(screen.queryByText('security-evaluation-v1')).not.toBeInTheDocument();
    expect(screen.queryByText('A_EVIDENCE_01')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '정제 JSON 내보내기' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'CSV 내보내기' })).not.toBeInTheDocument();
  });
});
