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

// Closed single-project inventory; changing it requires source review. No dynamic test names.
export const BROWSER_TEST_INVENTORY = [
  {
    title: 'potential impact displays exact API amount and count at 1440px',
    file: 'potential-impact.spec.ts',
  },
  {
    title: 'potential impact displays exact API amount and count at 390px',
    file: 'potential-impact.spec.ts',
  },
  {
    title: 'potential impact distinguishes zero from absent API values in the browser',
    file: 'potential-impact.spec.ts',
  },
  {
    title: 'SC-T07 untrusted customer text never creates executable DOM or network work',
    file: 'browser-security.spec.ts',
  },
  {
    title: 'SC-T07 deployed UI enforces CSP, no-store, frame and referrer headers',
    file: 'browser-security.spec.ts',
  },
  { title: 'SC-T07 hostile loopback parent cannot frame the deployed UI', file: 'browser-security.spec.ts' },
  { title: 'desktop entry has no fabricated live data and supports keyboard login', file: 'console.spec.ts' },
  { title: 'mobile layout does not overflow and route history stays usable', file: 'console.spec.ts' },
  {
    title: 'real browser approval pays exactly once while missing evidence stays blocked',
    file: 'fullstack.spec.ts',
  },
  {
    title: 'real browser quarantine impact, safe release and explicit recovery preserve history',
    file: 'fullstack.spec.ts',
  },
  {
    title: 'real browser replay experiment exports match persisted API rows and metrics',
    file: 'fullstack.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 401 retires delayed RUNNING poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 401 retires delayed COMPLETED poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 403 retires delayed RUNNING poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 403 retires delayed COMPLETED poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 404 retires delayed RUNNING poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser export HTTP 404 retires delayed COMPLETED poll',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser UNKNOWN APPROVE preserves intent through dismissal and navigation',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser UNKNOWN REJECT preserves intent through dismissal and navigation',
    file: 'recovery-boundaries.spec.ts',
  },
  {
    title: 'synthetic browser logout prevents old UNKNOWN command in replacement session',
    file: 'recovery-boundaries.spec.ts',
  },
] as const;
const TEST_FILES = [...new Set(BROWSER_TEST_INVENTORY.map((item) => item.file))];
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
export function summarizeBrowserTest(test: Pick<TestCase, 'title' | 'location'>, result: TestResult) {
  const source = safeSource(test.location);
  const title =
    BROWSER_TEST_INVENTORY.find((item) => item.title === test.title && item.file === source?.file)?.title ??
    'UNRECOGNIZED_TEST';
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

/** One result per fixed title: retries and additional projects require a reviewed contract change. */
export function summarizeBrowserRun(
  tests: ReturnType<typeof summarizeBrowserTest>[],
  observedRunnerStatus: string,
  infrastructureErrors: number,
  integration: boolean,
) {
  const runnerStatus = RUN_STATUSES.find((item) => item === observedRunnerStatus) ?? 'failed';
  const counts = BROWSER_TEST_INVENTORY.map(
    (expected) => tests.filter((item) => item.title === expected.title).length,
  );
  const missingTestCount = counts.filter((count) => count === 0).length;
  const duplicateTestCount = counts.reduce((sum, count) => sum + Math.max(0, count - 1), 0);
  const unknownTestCount = tests.filter((item) => item.title === 'UNRECOGNIZED_TEST').length;
  const passed = tests.filter((item) => item.status === 'passed').length;
  const skipped = tests.filter((item) => item.status === 'skipped').length;
  const failed = tests.length - passed - skipped;
  const incomplete =
    missingTestCount > 0 || duplicateTestCount > 0 || unknownTestCount > 0 || (integration && skipped > 0);
  return {
    status:
      tests.length === 0
        ? 'NOT_RUN'
        : incomplete
          ? 'INCOMPLETE'
          : failed > 0 || infrastructureErrors > 0
            ? 'failed'
            : runnerStatus,
    runnerStatus,
    plannedTestCount: BROWSER_TEST_INVENTORY.length,
    observedTestCount: tests.length,
    missingTestCount,
    duplicateTestCount,
    unknownTestCount,
    passed,
    skipped,
    failed,
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
    const aggregate = summarizeBrowserRun(
      this.tests,
      result.status,
      this.errors,
      process.env.FUSE_E2E_INTEGRATION === '1',
    );
    const summary = {
      schemaVersion: 'FUSE-BROWSER-SUMMARY-2',
      ...aggregate,
      durationMs: safeDuration(result.duration),
      infrastructureErrors: this.errors,
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
    if (summary.status !== 'passed') return { status: 'failed' as const };
  }
}
