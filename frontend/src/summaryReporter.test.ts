import { afterEach, describe, expect, it, vi } from 'vitest';
import type { FullResult, TestCase, TestResult } from '@playwright/test/reporter';
import SafeReporter from '../tests/e2e/safe-reporter';

afterEach(() => vi.restoreAllMocks());

describe('public aggregate browser test output', () => {
  it('emits counts without forwarding synthetic private errors or standard streams', () => {
    const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const reporter = new SafeReporter();
    const marker = 'SYNTHETIC_PRIVATE_DETAIL';
    reporter.onStdOut(marker);
    reporter.onStdErr(marker);
    reporter.onError({ message: marker, stack: marker });
    reporter.onTestEnd({} as TestCase, { status: 'passed' } as TestResult);
    reporter.onTestEnd({} as TestCase, { status: 'failed' } as TestResult);
    reporter.onEnd({ status: 'failed' } as FullResult);

    expect(write).toHaveBeenCalledTimes(1);
    const output = String(write.mock.calls[0][0]);
    expect(output).not.toContain(marker);
    expect(JSON.parse(output)).toEqual({
      event: 'FUSE_UI_TEST_SUMMARY',
      status: 'failed',
      counts: { passed: 1, failed: 1, timedOut: 0, skipped: 0, interrupted: 0 },
      errors: 1,
    });
  });
});
