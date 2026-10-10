#!/usr/bin/env python3
"""Offline diagnostic and privacy regression checks; no Java, database or provider."""
import copy
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('startup_report', ROOT / 'scripts/ci-startup-report.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)
import test_startup_admission as runner


class StartupDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.report = {'schemaVersion': 'FUSE-STARTUP-ADMISSION-1', 'status': 'PASS',
            'plannedScenarioCount': 11, 'passedScenarioCount': 11, 'exitCode': 0, 'cleanupVerified': True,
            'resultsSource': 'REAL_POSTGRES_CHILD_JVM_STARTUP', 'syntheticModelOutputs': True,
            'liveRobustnessMeasured': False, 'sourceHashBefore': 'a'*64, 'sourceHashAfter': 'a'*64,
            'sourceUnchangedDuringRun': True, 'scenarios': [{'scenario': n, 'verdict': 'PASS'} for n in reporter.SCENARIOS]}
        self.diag = {'schemaVersion': 'FUSE-STARTUP-DIAGNOSTIC-1', 'status': 'PASS',
                     'scenario': 'NONE', 'stage': 'COMPLETE', 'failureCategory': 'NONE'}

    def summarize(self):
        return reporter.summarize(self.report, self.diag, 'a'*64)

    def test_complete_evidence_passes(self):
        self.assertEqual('PASS', self.summarize()['status'])

    def test_partial_duplicate_unknown_and_oversized_rows_fail(self):
        for rows in [self.report['scenarios'][:-1], [self.report['scenarios'][0]]*11,
                     [{'scenario': 'SECRET', 'verdict': 'PASS'}]*11, self.report['scenarios']*2]:
            with self.subTest(rows=len(rows)):
                self.report['scenarios'] = rows
                result = self.summarize()
                self.assertEqual('FAIL', result['status'])
                self.assertLessEqual(result['observedScenarioCount'], 11)
                self.assertLessEqual(result['passedScenarioCount'], 11)

    def test_all_pass_attestations_required(self):
        for key in self.report:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.report); del changed[key]
                self.assertEqual('FAIL', reporter.summarize(changed, self.diag, 'a'*64)['status'])

    def test_unknown_schema_and_non_integer_counts_fail(self):
        for key, value in [('schemaVersion', 'OTHER'), ('plannedScenarioCount', True),
                           ('passedScenarioCount', 10**30), ('exitCode', False)]:
            changed = copy.deepcopy(self.report); changed[key] = value
            self.assertEqual('FAIL', reporter.summarize(changed, self.diag, 'a'*64)['status'])

    def test_arbitrary_strings_never_escape(self):
        canary = 'CANARY_SECRET Bearer password=/synthetic-private-fixture/runtime.env\\n::error::bad'
        self.report.update(reason=canary, logs=canary, environment={'API_KEY': canary})
        self.report['scenarios'][0].update(scenario=canary, verdict=canary, exception=canary)
        self.diag.update(scenario=canary, stage=canary, failureCategory=canary, reason=canary)
        result = self.summarize()
        self.assertNotIn('CANARY', json.dumps(result))
        self.assertEqual(('UNKNOWN',)*3, tuple(result[k] for k in ('scenario','stage','failureCategory')))
        self.assertEqual('FAIL', result['status'])

    def test_malformed_values_fail_closed(self):
        for value in [None, [], {}, 4, True, ['CANARY']]:
            for field in ('scenario', 'stage', 'failureCategory', 'status', 'schemaVersion'):
                diag = dict(self.diag); diag[field] = value
                self.assertEqual('FAIL', reporter.summarize(self.report, diag, 'a'*64)['status'])

    def test_fixed_failure_ids_preserved(self):
        self.diag.update(status='FAIL', scenario='MISSING_KEY', stage='PREPARE_START', failureCategory='ASSERTION_FAILED')
        result = self.summarize()
        self.assertEqual('FAIL', result['status'])
        self.assertEqual('PREPARE_START', result['stage'])

    def test_runner_prerequisite_failure_has_no_exception_text(self):
        with tempfile.TemporaryDirectory() as directory:
            args = type('Args', (), {'report_dir': Path(directory)})()
            with mock.patch.object(runner, 'source_digest', return_value='a'*64), mock.patch.object(runner, 'java_executable', side_effect=RuntimeError('CANARY_SECRET')):
                with self.assertRaises(RuntimeError): runner.run(args)
            diag = json.loads((Path(directory)/'startup-admission-diagnostic.json').read_text())
            self.assertEqual('PREREQUISITES', diag['stage'])
            self.assertEqual('EXECUTION_FAILED', diag['failureCategory'])
            self.assertNotIn('CANARY', json.dumps(diag))

    def test_java_closed_enums_match_reporter(self):
        source = (ROOT/'backend/src/test/java/com/finsec/fuse/testing/StartupAdmissionHarness.java').read_text()
        for enum, allowed in [('Stage', reporter.STAGES), ('FailureCategory', reporter.CATEGORIES)]:
            values = re.search(r'private enum '+enum+r' \{([^}]+)\}', source)[1]
            self.assertTrue(set(re.findall('[A-Z][A-Z_]+', values)).issubset(allowed))

    def test_runner_failed_harness_and_timeout_preserve_checkpoint(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as directory:
                destination = Path(directory)
                args = type('Args', (), {'report_dir': destination, 'gradle': None, 'build_timeout': 10, 'timeout': 10})()
                def execute(command, *unused):
                    if 'writeTestClasspath' in command:
                        classpath = next(x.partition('=')[2] for x in command if x.startswith('-PtestClasspathFile='))
                        Path(classpath).write_text('synthetic-test-classpath')
                        return 0
                    diag = dict(self.diag, status='FAIL', scenario='MISSING_KEY', stage='PREPARE_START', failureCategory='ASSERTION_FAILED')
                    (destination/'startup-admission-diagnostic.json').write_text(json.dumps(diag))
                    if timeout:
                        raise subprocess.TimeoutExpired('CANARY_SECRET', 10)
                    return 1
                with mock.patch.object(runner, 'source_digest', return_value='a'*64), mock.patch.object(runner, 'java_executable', return_value='java'), mock.patch.object(runner, 'execute', side_effect=execute):
                    with self.assertRaises((RuntimeError, subprocess.TimeoutExpired)): runner.run(args)
                diag = json.loads((destination/'startup-admission-diagnostic.json').read_text())
                self.assertEqual('PREPARE_START', diag['stage'])
                self.assertEqual('MISSING_KEY', diag['scenario'])
                self.assertEqual('TIMEOUT' if timeout else 'ASSERTION_FAILED', diag['failureCategory'])
                self.assertEqual('FAIL', diag['status'])
                self.assertNotIn('CANARY', json.dumps(diag))

    def test_repeated_digest_failure_invalidates_terminal_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            args = type('Args', (), {'report_dir': destination, 'gradle': None, 'build_timeout': 10, 'timeout': 10})()
            def execute(command, *unused):
                if 'writeTestClasspath' in command:
                    classpath = next(x.partition('=')[2] for x in command if x.startswith('-PtestClasspathFile='))
                    Path(classpath).write_text('synthetic-test-classpath')
                else:
                    (destination/'startup-admission-report.json').write_text(json.dumps(self.report))
                return 0
            calls = 0
            before_retry = []
            def digest():
                nonlocal calls
                calls += 1
                if calls == 1:
                    return 'a'*64
                if calls == 3:
                    before_retry.append(json.loads((destination/'startup-admission-report.json').read_text()))
                raise OSError('CANARY_SECRET')
            with mock.patch.object(runner, 'source_digest', side_effect=digest), mock.patch.object(runner, 'java_executable', return_value='java'), mock.patch.object(runner, 'execute', side_effect=execute):
                with self.assertRaisesRegex(OSError, 'CANARY_SECRET'):
                    runner.run(args)
            saved = json.loads((destination/'startup-admission-report.json').read_text())
            diag = json.loads((destination/'startup-admission-diagnostic.json').read_text())
            self.assertEqual(3, calls)
            self.assertEqual('INCOMPLETE_OR_FAILED', before_retry[0]['status'])
            self.assertFalse(before_retry[0]['sourceUnchangedDuringRun'])
            self.assertEqual('INCOMPLETE_OR_FAILED', saved['status'])
            self.assertEqual('', saved['sourceHashAfter'])
            self.assertEqual('FAIL', diag['status'])
            summary = reporter.summarize(saved, diag, 'a'*64)
            self.assertEqual('FAIL', summary['status'])
            self.assertNotIn('CANARY', json.dumps(summary))

    def test_missing_or_malformed_input_cli_is_safe_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'input.json'; source.write_text('CANARY_SECRET')
            result = subprocess.run([sys.executable, str(ROOT/'scripts/ci-startup-report.py'), '--input', str(source),
                                     '--diagnostic', str(source), '--output', str(Path(directory)/'safe.json')], capture_output=True, text=True)
            self.assertEqual(1, result.returncode)
            self.assertEqual('', result.stderr)
            self.assertNotIn('CANARY', result.stdout)
            self.assertEqual('FAIL', json.loads(result.stdout)['status'])

    def test_symlink_and_oversized_input_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'source'; source.write_bytes(b' '* (reporter.MAX_BYTES+1))
            link = Path(directory)/'link'; link.symlink_to(source)
            self.assertIsNone(reporter.read_private(source)); self.assertIsNone(reporter.read_private(link))


if __name__ == '__main__':
    unittest.main()
