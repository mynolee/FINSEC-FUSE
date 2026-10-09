import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type {
  FullResult,
  Location,
  Reporter,
  TestCase,
  TestResult,
  TestStep,
} from '@playwright/test/reporter';
import { MAX_CHECKPOINTS, PHASE_ANNOTATION, PHASES, type Phase } from './diagnostic-contract';

const TEST_TITLES = [
  'SC-T07 untrusted customer text never creates executable DOM or network work',
  'SC-T07 deployed UI enforces CSP, no-store, frame and referrer headers',
  'desktop entry has no fabricated live data and supports keyboard login',
  'mobile layout does not overflow and route history stays usable',
  'real browser approval pays exactly once while missing evidence stays blocked',
  'real browser quarantine impact, safe release and explicit recovery preserve history',
  'real browser replay experiment exports match persisted API rows and metrics',
] as const;
const TEST_FILES = ['browser-security.spec.ts', 'console.spec.ts', 'fullstack.spec.ts'] as const;
const STATUSES = ['passed', 'failed', 'timedOut', 'skipped', 'interrupted'] as const;
const RUN_STATUSES = ['passed', 'failed', 'timedout', 'interrupted'] as const;
const MAX_SOURCE_LINE = 10000;
const MAX_STEP_COUNT = 2000;

type Source = { file: (typeof TEST_FILES)[number]; line: number };
function safeSource(location?: Location): Source | null {
  if (!location || !Number.isInteger(location.line) || location.line < 1 || location.line > MAX_SOURCE_LINE)
    return null;
  const file = TEST_FILES.find((name) => resolve(location.file) === resolve(import.meta.dirname, name));
  return file ? { file, line: location.line } : null;
}
function safeDuration(value: number) {
  return Number.isFinite(value) && value >= 0 ? Math.min(Math.round(value), 86400000) : 0;
}
function diagnosticSteps(steps: TestStep[]) {
  const flattened: TestStep[] = [];
  function visit(items: TestStep[], depth: number) {
    if (depth > 20) return;
    for (const item of items) {
      if (flattened.length >= MAX_STEP_COUNT) return;
      flattened.push(item);
      visit(item.steps, depth + 1);
    }
  }
  visit(steps, 0);
  return flattened;
}

/** Do not serialize Playwright objects: their titles, params, errors and attachments may contain secrets. */
export function summarizeBrowserTest(test: Pick<TestCase, 'title'>, result: TestResult) {
  const title = TEST_TITLES.find((item) => item === test.title) ?? 'UNRECOGNIZED_TEST';
  const status = STATUSES.find((item) => item === result.status) ?? 'failed';
  const checkpoints = result.annotations
    .filter((item) => item.type === PHASE_ANNOTATION && PHASES.includes(item.description as Phase))
    .map((item) => PHASES.find((phase) => phase === item.description)!)
    .slice(-MAX_CHECKPOINTS);
  const steps = diagnosticSteps(result.steps);
  const failedSteps = steps.filter((step) => step.error);
  const failed = !['passed', 'skipped'].includes(status);
  const message = result.error?.message?.slice(0, 8192) ?? '';
  // Message matching emits a fixed category only. Never include a substring, stack, snippet or value.
  const failureCode = !failed
    ? null
    : /strict mode violation/i.test(message)
      ? 'LOCATOR_AMBIGUOUS'
      : status === 'timedOut'
        ? 'TEST_TIMEOUT'
        : /browserType\.launch|browser has been closed|Executable doesn't exist/.test(message)
          ? 'BROWSER_UNAVAILABLE'
          : /Timeout .*exceeded|TimeoutError/.test(message)
            ? 'WAIT_TIMEOUT'
            : failedSteps.some((step) => step.category === 'expect')
              ? 'ASSERTION_FAILED'
              : 'TEST_FAILED';
  const failureSource = failed
    ? (result.errors.map((error) => safeSource(error.location)).find((source) => source !== null) ??
      failedSteps
        .slice()
        .reverse()
        .map((step) => safeSource(step.location))
        .find((source) => source !== null) ??
      null)
    : null;
  const lastSource =
    steps
      .slice()
      .reverse()
      .map((step) => safeSource(step.location))
      .find((source) => source !== null) ?? null;
  return {
    title,
    status,
    durationMs: safeDuration(result.duration),
    diagnostics: {
      phase: checkpoints.at(-1) ?? 'NOT_STARTED',
      checkpoints,
      failureCode,
      failureSource,
      // This is the last observed source location, not a claim about which assertion failed.
      lastSource,
    },
  };
}

/** Public CI receives only fixed labels, bounded numbers and allowlisted test-source locations. */
export default class SafeReporter implements Reporter {
  private tests: ReturnType<typeof summarizeBrowserTest>[] = [];
  private errors = 0;
  onTestEnd(test: TestCase, result: TestResult) {
    const summary = summarizeBrowserTest(test, result);
    this.tests.push(summary);
    const { phase, failureCode, failureSource, lastSource } = summary.diagnostics;
    const source = failureSource ?? lastSource;
    process.stdout.write(
      `Browser check: ${summary.status} | ${summary.title} | phase=${phase}` +
        ` | code=${failureCode ?? 'NONE'} | source=${source ? `${source.file}:${source.line}` : 'UNAVAILABLE'}\n`,
    );
  }
  onError() {
    this.errors += 1;
    process.stderr.write('Browser infrastructure error; raw diagnostic text withheld.\n');
  }
  async onEnd(result: FullResult) {
    const incomplete =
      this.tests.length === 0 ||
      this.tests.some((item) => item.title === 'UNRECOGNIZED_TEST') ||
      (process.env.FUSE_E2E_INTEGRATION === '1' && this.tests.some((item) => item.status === 'skipped'));
    const runnerStatus = RUN_STATUSES.find((item) => item === result.status) ?? 'failed';
    const summary = {
      schemaVersion: 'FUSE-BROWSER-SUMMARY-2',
      status: this.tests.length === 0 ? 'NOT_RUN' : incomplete ? 'INCOMPLETE' : runnerStatus,
      runnerStatus,
      durationMs: safeDuration(result.duration),
      infrastructureErrors: this.errors,
      passed: this.tests.filter((item) => item.status === 'passed').length,
      skipped: this.tests.filter((item) => item.status === 'skipped').length,
      failed: this.tests.filter((item) => !['passed', 'skipped'].includes(item.status)).length,
      tests: this.tests,
      privacy:
        'Fixed phases/codes and test-source lines only; no error text, inputs, HTTP data or recordings.',
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
