import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { FullResult, Reporter, TestCase, TestResult } from '@playwright/test/reporter';

/** Public CI never receives errors, source snippets, HTTP headers, or recordings. */
export default class SafeReporter implements Reporter {
  private tests: { title: string; status: string; durationMs: number }[] = [];
  private errors = 0;
  onTestEnd(test: TestCase, result: TestResult) {
    this.tests.push({ title: test.title, status: result.status, durationMs: result.duration });
    process.stdout.write(`Browser check: ${result.status} | ${test.title}\n`);
  }
  onError() {
    this.errors += 1;
    process.stderr.write('Browser infrastructure error; raw diagnostic text withheld.\n');
  }
  async onEnd(result: FullResult) {
    const incomplete =
      this.tests.length === 0 ||
      (process.env.FUSE_E2E_INTEGRATION === '1' && this.tests.some((item) => item.status === 'skipped'));
    const summary = {
      schemaVersion: 'FUSE-BROWSER-SUMMARY-1',
      status: this.tests.length === 0 ? 'NOT_RUN' : incomplete ? 'INCOMPLETE' : result.status,
      runnerStatus: result.status,
      durationMs: result.duration,
      infrastructureErrors: this.errors,
      passed: this.tests.filter((item) => item.status === 'passed').length,
      skipped: this.tests.filter((item) => item.status === 'skipped').length,
      failed: this.tests.filter((item) => !['passed', 'skipped'].includes(item.status)).length,
      tests: this.tests,
      privacy: 'No error messages, request headers, raw responses, screenshots, video, or browser traces.',
    };
    const path = resolve(process.env.FUSE_E2E_SUMMARY_PATH || 'test-results/summary.json');
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(summary, null, 2) + '\n', { mode: 0o600 });
    process.stdout.write(
      `Browser result: ${summary.status}; passed=${summary.passed}, failed=${summary.failed}, skipped=${summary.skipped}\n`,
    );
    if (incomplete) return { status: 'failed' as const };
  }
}
