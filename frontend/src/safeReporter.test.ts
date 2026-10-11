import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import type { TestResult, TestStep } from '@playwright/test/reporter';
import {
  BROWSER_TEST_INVENTORY,
  summarizeBrowserRun,
  summarizeBrowserTest,
} from '../tests/e2e/safe-reporter';
import {
  isEnforcedFrameAncestorDenial,
  MAX_CHECKPOINTS,
  PHASE_ANNOTATION,
} from '../tests/e2e/diagnostic-contract';

const title = 'real browser replay experiment exports match persisted API rows and metrics';
const file = resolve(import.meta.dirname, '../tests/e2e/fullstack.spec.ts');
const PRIVATE = 'synthetic-private-value-must-never-be-published';
function result(overrides: Partial<TestResult> = {}): TestResult {
  return {
    status: 'passed',
    duration: 20,
    annotations: [],
    errors: [],
    steps: [],
    ...overrides,
  } as unknown as TestResult;
}
function step(overrides: Partial<TestStep> = {}): TestStep {
  return { title: PRIVATE, category: 'pw:api', steps: [], ...overrides } as unknown as TestStep;
}

describe('Chromium frame-ancestor denial correlation', () => {
  const origin = 'http://127.0.0.1:5173';
  const parentFrameId = 'synthetic-parent-frame';
  const issue = {
    blockedURL: `${origin}/`,
    violatedDirective: "frame-ancestors 'none'",
    isReportOnly: false,
    contentSecurityPolicyViolationType: 'kURLViolation',
    frameAncestor: { frameId: parentFrameId },
  };

  it('accepts only the protected origin and exact disallowed parent for an enforced URL violation', () => {
    expect(isEnforcedFrameAncestorDenial(issue, origin, parentFrameId)).toBe(true);
    expect(
      isEnforcedFrameAncestorDenial(
        { ...issue, blockedURL: 'https://127.0.0.1:5173/' },
        'https://127.0.0.1:5173',
        parentFrameId,
      ),
    ).toBe(true);
  });

  it.each([
    { blockedURL: 'http://127.0.0.1:5174/' },
    { blockedURL: origin },
    { blockedURL: `${origin}/another-path` },
    { blockedURL: `${origin}/?fuse-frame-probe=synthetic` },
    { blockedURL: `${origin}/#fragment` },
    { blockedURL: 'http://synthetic@127.0.0.1:5173/' },
    { blockedURL: undefined },
    { frameAncestor: { frameId: 'synthetic-child-frame' } },
    { frameAncestor: { frameId: '' } },
    { frameAncestor: undefined },
    { contentSecurityPolicyViolationType: 'kInlineViolation' },
    { contentSecurityPolicyViolationType: undefined },
    { isReportOnly: true },
    { isReportOnly: undefined },
    { violatedDirective: "frame-src 'none'" },
    { violatedDirective: 'frame-ancestors-other' },
    { violatedDirective: undefined },
  ])('rejects mismatched or incomplete policy evidence %#', (override) => {
    expect(isEnforcedFrameAncestorDenial({ ...issue, ...override }, origin, parentFrameId)).toBe(false);
  });

  it('rejects absent issues and invalid expected origins or parent identities', () => {
    expect(isEnforcedFrameAncestorDenial(undefined, origin, parentFrameId)).toBe(false);
    expect(isEnforcedFrameAncestorDenial(issue, origin, '')).toBe(false);
    for (const invalid of ['invalid', 'null', `${origin}/path`, `${origin}/?query`, 'file://'])
      expect(isEnforcedFrameAncestorDenial(issue, invalid, parentFrameId)).toBe(false);
  });
});

describe('public browser diagnostic allowlist', () => {
  it('recognizes hostile-frame checks while withholding all raw Chromium diagnostics', () => {
    const frameTitle = 'SC-T07 hostile loopback parent cannot frame the deployed UI';
    const phases = [
      'SECURITY_FRAME_TOP_LEVEL',
      'SECURITY_FRAME_PARENT',
      'SECURITY_FRAME_DENIAL',
      'SECURITY_FRAME_UI_ABSENT',
    ];
    for (const phase of phases) {
      const summary = summarizeBrowserTest(
        {
          title: frameTitle,
          location: {
            file: resolve(import.meta.dirname, '../tests/e2e/browser-security.spec.ts'),
            line: 1,
            column: 1,
          },
        },
        result({
          status: 'failed',
          annotations: [{ type: PHASE_ANNOTATION, description: phase }],
          error: { message: `Framing '${PRIVATE}' violates frame-ancestors 'none'` },
          errors: [{ message: `net::ERR_BLOCKED_BY_RESPONSE ${PRIVATE}` }],
          steps: [step({ category: 'expect', error: { message: PRIVATE } })],
          stdout: [PRIVATE],
          stderr: [PRIVATE],
          attachments: [{ name: PRIVATE, contentType: 'text/plain', body: Buffer.from(PRIVATE) }],
        }),
      );
      expect(summary.title).toBe(frameTitle);
      expect(summary.diagnostics.phase).toBe(phase);
      expect(summary.diagnostics.checkpoints).toEqual([phase]);
      expect(summary.diagnostics.failureCode).toBe('ASSERTION_FAILED');
      expect(JSON.stringify(summary)).not.toContain(PRIVATE);
      expect(JSON.stringify(summary)).not.toContain('ERR_BLOCKED_BY_RESPONSE');
      expect(JSON.stringify(summary)).not.toContain('frame-ancestors');
    }
  });

  it('reports fixed checkpoints, failure code and only the test filename/line', () => {
    const error = {
      message: `strict mode violation: ${PRIVATE}`,
      stack: PRIVATE,
      snippet: PRIVATE,
      value: PRIVATE,
      location: { file, line: 40, column: 12 },
    };
    const summary = summarizeBrowserTest(
      { title, location: { file, line: 1, column: 1 } },
      result({
        status: 'failed',
        annotations: [{ type: PHASE_ANNOTATION, description: 'REPLAY_JSON_COMPARE' }],
        error,
        errors: [error],
        steps: [step({ error, location: { file, line: 40, column: 12 } })],
        stdout: [PRIVATE],
        stderr: [PRIVATE],
        attachments: [{ name: PRIVATE, contentType: 'text/plain', body: Buffer.from(PRIVATE) }],
      }),
    );
    expect(summary.diagnostics).toEqual({
      phase: 'REPLAY_JSON_COMPARE',
      checkpoints: ['REPLAY_JSON_COMPARE'],
      failureCode: 'LOCATOR_AMBIGUOUS',
      failureSource: { file: 'fullstack.spec.ts', line: 40 },
      lastSource: { file: 'fullstack.spec.ts', line: 40 },
    });
    expect(JSON.stringify(summary)).not.toContain(PRIVATE);
    expect(JSON.stringify(summary)).not.toContain(resolve(import.meta.dirname));
  });

  it('rejects unknown titles, arbitrary annotations, other paths and invalid lines', () => {
    const summary = summarizeBrowserTest(
      { title: PRIVATE, location: { file, line: 1, column: 1 } },
      result({
        status: 'failed',
        duration: Infinity,
        error: { message: PRIVATE },
        errors: [
          { message: PRIVATE, location: { file: `/other/${PRIVATE}/fullstack.spec.ts`, line: 2, column: 1 } },
        ],
        annotations: [
          { type: PHASE_ANNOTATION, description: PRIVATE },
          { type: PRIVATE, description: 'SESSION_CONNECTED' },
        ],
        steps: [
          step({ location: { file, line: NaN, column: 1 } }),
          step({ location: { file, line: 10001, column: 1 } }),
          step({ location: { file, line: -1, column: 1 } }),
          step({ location: { file, line: 1.2, column: 1 } }),
        ],
      }),
    );
    expect(summary.title).toBe('UNRECOGNIZED_TEST');
    expect(summary.durationMs).toBe(0);
    expect(summary.diagnostics).toEqual({
      phase: 'NOT_STARTED',
      checkpoints: [],
      failureCode: 'TEST_FAILED',
      failureSource: null,
      lastSource: null,
    });
    expect(JSON.stringify(summary)).not.toContain(PRIVATE);
  });

  it('bounds checkpoint history and preserves the active phase on a test timeout', () => {
    const summary = summarizeBrowserTest(
      { title, location: { file, line: 1, column: 1 } },
      result({
        status: 'timedOut',
        annotations: [
          ...Array.from({ length: MAX_CHECKPOINTS + 10 }, () => ({
            type: PHASE_ANNOTATION,
            description: 'SESSION_NAVIGATE',
          })),
          { type: PHASE_ANNOTATION, description: 'COMMAND_RESPONSE' },
        ],
        steps: [step({ location: { file, line: 90, column: 1 } })],
      }),
    );
    expect(summary.diagnostics.checkpoints).toHaveLength(MAX_CHECKPOINTS);
    expect(summary.diagnostics.phase).toBe('COMMAND_RESPONSE');
    expect(summary.diagnostics.failureCode).toBe('TEST_TIMEOUT');
    expect(summary.diagnostics.failureSource).toBeNull();
    expect(summary.diagnostics.lastSource).toEqual({ file: 'fullstack.spec.ts', line: 90 });
  });

  it('finds a nested assertion source without printing its dynamic title or error', () => {
    const error = { message: PRIVATE };
    const summary = summarizeBrowserTest(
      { title, location: { file, line: 1, column: 1 } },
      result({
        status: 'failed',
        error,
        errors: [error],
        steps: [
          step({
            category: 'test.step',
            steps: [step({ category: 'expect', error, location: { file, line: 91, column: 2 } })],
          }),
        ],
      }),
    );
    expect(summary.diagnostics.failureCode).toBe('ASSERTION_FAILED');
    expect(summary.diagnostics.failureSource).toEqual({ file: 'fullstack.spec.ts', line: 91 });
    expect(JSON.stringify(summary)).not.toContain(PRIVATE);
  });

  it('does not report an intermediate polling failure after the test passes', () => {
    const summary = summarizeBrowserTest(
      { title, location: { file, line: 1, column: 1 } },
      result({
        steps: [
          step({ category: 'expect', error: { message: PRIVATE }, location: { file, line: 20, column: 1 } }),
        ],
      }),
    );
    expect(summary.diagnostics.failureCode).toBeNull();
    expect(summary.diagnostics.failureSource).toBeNull();
  });
});

describe('closed browser acceptance inventory', () => {
  const summaries = () =>
    BROWSER_TEST_INVENTORY.map((item) =>
      summarizeBrowserTest(
        {
          title: item.title,
          location: { file: resolve(import.meta.dirname, '../tests/e2e', item.file), line: 1, column: 1 },
        },
        result(),
      ),
    );
  it('retains eleven existing cases and identifies nine native synthetic boundary cases', () => {
    expect(BROWSER_TEST_INVENTORY).toHaveLength(20);
    expect(BROWSER_TEST_INVENTORY.filter((item) => item.file === 'recovery-boundaries.spec.ts')).toHaveLength(
      9,
    );
    expect(new Set(BROWSER_TEST_INVENTORY.map((item) => item.title)).size).toBe(20);
    expect(summarizeBrowserRun(summaries(), 'passed', 0, true)).toMatchObject({
      status: 'passed',
      plannedTestCount: 20,
      observedTestCount: 20,
      missingTestCount: 0,
      duplicateTestCount: 0,
      unknownTestCount: 0,
      passed: 20,
      skipped: 0,
      failed: 0,
    });
  });
  it('rejects every missing or duplicate identity even when the runner says passed', () => {
    const all = summaries();
    for (let index = 0; index < all.length; index += 1) {
      expect(
        summarizeBrowserRun(
          all.filter((_, i) => i !== index),
          'passed',
          0,
          true,
        ),
      ).toMatchObject({ status: 'INCOMPLETE', missingTestCount: 1 });
      expect(summarizeBrowserRun([...all, all[index]], 'passed', 0, true)).toMatchObject({
        status: 'INCOMPLETE',
        duplicateTestCount: 1,
      });
    }
  });
  it('rejects an unknown identity and each valid title attributed to the wrong source', () => {
    for (const item of BROWSER_TEST_INVENTORY) {
      const wrong = summarizeBrowserTest(
        {
          title: item.title,
          location: {
            file: resolve(
              import.meta.dirname,
              '../tests/e2e',
              item.file === 'console.spec.ts' ? 'fullstack.spec.ts' : 'console.spec.ts',
            ),
            line: 1,
            column: 1,
          },
        },
        result(),
      );
      expect(wrong.title).toBe('UNRECOGNIZED_TEST');
      expect(summarizeBrowserRun([...summaries(), wrong], 'passed', 0, true)).toMatchObject({
        status: 'INCOMPLETE',
        unknownTestCount: 1,
      });
    }
    const unknown = summarizeBrowserTest(
      { title: PRIVATE, location: { file, line: 1, column: 1 } },
      result(),
    );
    expect(JSON.stringify(unknown)).not.toContain(PRIVATE);
    expect(summarizeBrowserRun([...summaries(), unknown], 'passed', 0, true).status).toBe('INCOMPLETE');
  });
  it('never turns test, infrastructure, runner failure or skipped integration into a pass', () => {
    for (const status of ['failed', 'timedOut', 'interrupted'] as const) {
      const all = summaries();
      all[0] = { ...all[0], status };
      expect(summarizeBrowserRun(all, 'passed', 0, true).status).toBe('failed');
    }
    expect(summarizeBrowserRun(summaries(), 'passed', 1, true).status).toBe('failed');
    expect(summarizeBrowserRun(summaries(), 'failed', 0, true).status).toBe('failed');
    const skipped = summaries();
    skipped[0] = { ...skipped[0], status: 'skipped' };
    expect(summarizeBrowserRun(skipped, 'passed', 0, true).status).toBe('INCOMPLETE');
    expect(summarizeBrowserRun([], 'passed', 0, true).status).toBe('NOT_RUN');
  });
  it('reports only fixed recovery labels and bounded source lines without HTTP bodies or attachments', () => {
    const item = BROWSER_TEST_INVENTORY.find((entry) =>
      entry.title.startsWith('synthetic browser UNKNOWN APPROVE'),
    )!;
    const location = { file: resolve(import.meta.dirname, '../tests/e2e', item.file), line: 200, column: 1 };
    const error = { message: PRIVATE, stack: PRIVATE, snippet: PRIVATE, location };
    const summary = summarizeBrowserTest(
      { title: item.title, location },
      result({
        status: 'failed',
        error,
        errors: [error],
        annotations: [
          { type: PHASE_ANNOTATION, description: 'UNKNOWN_EXACT_RETRY' },
          { type: PHASE_ANNOTATION, description: PRIVATE },
        ],
        steps: [step({ category: 'expect', error, location })],
        stdout: [PRIVATE],
        stderr: [PRIVATE],
        attachments: [{ name: PRIVATE, contentType: 'application/json', body: Buffer.from(PRIVATE) }],
      }),
    );
    expect(summary.diagnostics).toMatchObject({
      phase: 'UNKNOWN_EXACT_RETRY',
      checkpoints: ['UNKNOWN_EXACT_RETRY'],
      failureCode: 'ASSERTION_FAILED',
      failureSource: { file: 'recovery-boundaries.spec.ts', line: 200 },
    });
    expect(JSON.stringify(summary)).not.toContain(PRIVATE);
    expect(JSON.stringify(summary)).not.toContain(resolve(import.meta.dirname));
  });
});
