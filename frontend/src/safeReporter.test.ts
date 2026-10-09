import { describe, expect, it } from 'vitest';
import { resolve } from 'node:path';
import type { TestResult, TestStep } from '@playwright/test/reporter';
import { summarizeBrowserTest } from '../tests/e2e/safe-reporter';
import { MAX_CHECKPOINTS, PHASE_ANNOTATION } from '../tests/e2e/diagnostic-contract';

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
        { title: frameTitle },
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
      { title },
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
      { title: PRIVATE },
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
      { title },
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
      { title },
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
      { title },
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
