#!/usr/bin/env python3
"""Fixed-schema CI diagnostics; private command output is never published."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SAFE = ROOT / 'safe-artifacts'
MAX_REPORT_BYTES = 10 * 1024 * 1024
TEST_FILES = frozenset({
    'frontend/src/App.test.tsx', 'frontend/src/ApprovalHistory.test.tsx',
    'frontend/src/EvidenceTimeStatus.test.tsx',
    'frontend/src/LiveExperiments.test.tsx',
    'frontend/src/Operations.test.tsx', 'frontend/src/PotentialImpact.test.tsx',
    'frontend/src/api.test.ts',
    'frontend/src/browserSecurity.test.tsx', 'frontend/src/experimentExport.test.tsx',
    'frontend/src/format.test.ts', 'frontend/src/hooks.test.tsx',
    'frontend/src/safeReporter.test.ts',
})
spec = importlib.util.spec_from_file_location('ci_run', Path(__file__).with_name('ci-run.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def numeric_version(value):
    # Vendor suffixes, paths and arbitrary strings are never reflected.
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r'v?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})(?:[-+][A-Za-z0-9_.-]{1,40})?', value.strip())
    return match.group(1) if match else None


def captured(command, *, timeout=None):
    with tempfile.TemporaryFile(mode='w+b', dir=os.getenv('RUNNER_TEMP')) as private:
        try:
            process = subprocess.run(command, cwd=ROOT, stdout=private,
                                     stderr=subprocess.STDOUT, timeout=timeout)
            code = process.returncode
            state = 'COMPLETED'
        except FileNotFoundError:
            code, state = None, 'COMMAND_NOT_FOUND'
        except subprocess.TimeoutExpired:
            code, state = None, 'TIMED_OUT'
        except OSError:
            code, state = None, 'INVOCATION_FAILED'
        signals = runner.compose_diagnostic_signals(private)
        private.seek(0)
        # Version JSON is small. Truncated/invalid input fails closed.
        raw = private.read(65537)
    return {'exitCode': code if type(code) is int and -255 <= code <= 255 else None,
            'invocation': state, 'signals': signals}, raw


def emit(name, summary):
    SAFE.mkdir(mode=0o700, exist_ok=True)
    target = SAFE / name
    target.write_text(json.dumps(summary, indent=2, sort_keys=True, allow_nan=False) + '\n')
    target.chmod(0o600)
    print(json.dumps(summary, sort_keys=True, allow_nan=False))


def compose_preflight():
    docker, raw = captured(['docker', 'version', '--format', '{{json .}}'], timeout=30)
    try:
        data = json.loads(raw) if len(raw) <= 65536 else {}
        client = numeric_version(data.get('Client', {}).get('Version'))
        server = numeric_version(data.get('Server', {}).get('Version'))
    except (ValueError, AttributeError, TypeError):
        client = server = None
    docker.update(clientVersion=client, serverVersion=server)
    compose, raw = captured(['docker', 'compose', 'version', '--short'], timeout=30)
    try:
        version = numeric_version(raw.decode('utf-8')) if len(raw) <= 65536 else None
    except UnicodeError:
        version = None
    compose['version'] = version
    config, _ = captured(['docker', 'compose', 'config', '--quiet'], timeout=30)
    passed = (all(item['invocation'] == 'COMPLETED' and item['exitCode'] == 0
                  for item in (docker, compose, config)) and
              all(value is not None for value in (client, server, version)))
    summary = {'schemaVersion': 'FUSE-COMPOSE-PREFLIGHT-1',
               'status': 'PASS' if passed else 'FAIL', 'docker': docker,
               'compose': compose, 'configuration': config,
               'scope': 'Read-only CLI, daemon version and quiet configuration checks; no services started.'}
    emit('compose-preflight.json', summary)
    return 0 if passed else 1


def count(value):
    if type(value) is not int or not 0 <= value <= 100000:
        raise ValueError('Invalid count')
    return value


def test_file(value):
    if not isinstance(value, str):
        raise ValueError('Invalid file')
    for allowed in TEST_FILES:
        if value == str(ROOT / allowed) or value == allowed:
            return allowed
    raise ValueError('Unlisted test file')


def failure_code(messages):
    # Classification reads private strings but emits only this closed vocabulary.
    if not isinstance(messages, list) or any(not isinstance(x, str) for x in messages):
        return 'UNKNOWN'
    text = '\n'.join(x[:4096] for x in messages[:20])
    if re.search(r'timed?\s*out|timeout|exceeded.{0,40}[0-9]+\s*ms', text, re.I):
        return 'TIMEOUT'
    if re.search(r'unhandled|uncaught', text, re.I):
        return 'UNHANDLED_ERROR'
    if re.search(r'AssertionError|TestingLibraryElementError|expected.{0,100}to', text, re.I):
        return 'ASSERTION_FAILED'
    return 'UNKNOWN'


def frontend_summary(report, exit_code):
    if not isinstance(report, dict) or type(report.get('success')) is not bool:
        raise ValueError('Invalid report')
    suites = report.get('testResults')
    if not isinstance(suites, list) or not 1 <= len(suites) <= len(TEST_FILES):
        raise ValueError('Invalid suite list')
    counts = {'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0, 'todo': 0}
    failures, failed_files, seen = [], [], set()
    for suite in suites:
        if not isinstance(suite, dict) or suite.get('status') not in ('passed', 'failed'):
            raise ValueError('Invalid suite')
        filename = test_file(suite.get('name'))
        if filename in seen:
            raise ValueError('Duplicate suite')
        seen.add(filename)
        assertions = suite.get('assertionResults')
        if not isinstance(assertions, list) or len(assertions) > 10000:
            raise ValueError('Invalid assertions')
        if suite['status'] == 'failed':
            failed_files.append({'file': filename, 'code': failure_code([suite.get('message', '')])})
        max_line = len((ROOT / filename).read_text().splitlines())
        for ordinal, assertion in enumerate(assertions, 1):
            if not isinstance(assertion, dict):
                raise ValueError('Invalid assertion')
            status = assertion.get('status')
            field = {'passed': 'passed', 'failed': 'failed', 'pending': 'skipped',
                     'skipped': 'skipped', 'todo': 'todo'}.get(status)
            if field is None:
                raise ValueError('Invalid status')
            counts['total'] += 1
            counts[field] += 1
            if status == 'failed':
                location = assertion.get('location')
                line = location.get('line') if isinstance(location, dict) else None
                line = line if type(line) is int and 1 <= line <= max_line else None
                failures.append({'file': filename, 'testOrdinal': ordinal, 'line': line,
                                 'code': failure_code(assertion.get('failureMessages'))})
    for key, field in (('numTotalTests', 'total'), ('numPassedTests', 'passed'),
                       ('numFailedTests', 'failed'), ('numPendingTests', 'skipped'), ('numTodoTests', 'todo')):
        if count(report.get(key)) != counts[field]:
            raise ValueError('Inconsistent report counts')
    passed = exit_code == 0 and report['success'] and counts['total'] > 0 and not failures and not failed_files
    return {'schemaVersion': 'FUSE-FRONTEND-COUNTS-1', 'status': 'PASS' if passed else 'FAIL',
            'reportState': 'PARSED', 'exitCode': exit_code,
            'files': len(suites), 'counts': counts, 'failedFiles': failed_files, 'failedTests': failures,
            'privacy': 'Counts, fixed test-file paths, source lines and fixed codes only; no titles, errors or HTTP data.'}


def frontend_tests():
    state, summary, exit_code = 'MISSING', None, None
    with tempfile.TemporaryDirectory(prefix='fuse-private-vitest-', dir=os.getenv('RUNNER_TEMP')) as work:
        report_path = Path(work) / 'report.json'
        observation, _ = captured(['npm', '--prefix', 'frontend', 'test', '--', '--run',
                                   '--includeTaskLocation', '--reporter=json', f'--outputFile={report_path}'])
        exit_code = observation['exitCode']
        try:
            if not report_path.is_file() or report_path.is_symlink():
                state = 'MISSING'
            elif report_path.stat().st_size > MAX_REPORT_BYTES:
                state = 'OVERSIZED'
            else:
                state = 'INVALID'
                summary = frontend_summary(json.loads(report_path.read_bytes()), exit_code)
        except (ValueError, TypeError, OSError, UnicodeError, RecursionError):
            state = 'INVALID'
    if summary is None:
        summary = {'schemaVersion': 'FUSE-FRONTEND-COUNTS-1', 'status': 'FAIL',
                   'reportState': state, 'exitCode': exit_code}
    emit('frontend-test-summary.json', summary)
    if exit_code != 0:
        return exit_code if isinstance(exit_code, int) and exit_code > 0 else 1
    return 0 if summary['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['compose-preflight', 'frontend-tests'])
    command = parser.parse_args().command
    try:
        return compose_preflight() if command == 'compose-preflight' else frontend_tests()
    except Exception:
        # Even an unexpected dependency failure must not print diagnostic bodies.
        print('CI diagnostic helper failed; private details withheld.')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
