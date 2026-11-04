import type { FullResult, Reporter, TestCase, TestError, TestResult } from '@playwright/test/reporter';

/** Public aggregate output only; never serialize test errors, output, titles, or attachments. */
export default class SafeReporter implements Reporter {
  private readonly counts = { passed: 0, failed: 0, timedOut: 0, skipped: 0, interrupted: 0 };
  private errors = 0;

  onTestEnd(_test: TestCase, result: TestResult) {
    if (Object.hasOwn(this.counts, result.status)) this.counts[result.status] += 1;
  }

  onError(_error: TestError) {
    this.errors += 1;
  }

  onStdOut(_chunk: string | Buffer) {}
  onStdErr(_chunk: string | Buffer) {}

  onEnd(result: FullResult) {
    const status = ['passed', 'failed', 'timedout', 'interrupted'].includes(result.status)
      ? result.status
      : 'failed';
    process.stdout.write(
      JSON.stringify({ event: 'FUSE_UI_TEST_SUMMARY', status, counts: this.counts, errors: this.errors }) + '\n',
    );
  }

  printsToStdio() {
    return true;
  }
}
