#!/usr/bin/env python3
"""Synthetic offline regressions: no Uvicorn, provider or model is launched."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('startup_report', Path(__file__).with_name('ci-python-startup-report.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
SECRET = 'secret-token-/private/path-private-exception'


class Synthetic(unittest.TestCase):
    def __init__(self, behavior='pass'):
        super().__init__('runTest')
        self.behavior = behavior

    def id(self):
        return M.TEST

    def runTest(self):
        if self.behavior == 'fail':
            self.fail(SECRET)
        if self.behavior == 'error':
            raise RuntimeError(SECRET)
        if self.behavior == 'skip':
            self.skipTest(SECRET)


class HarnessTests(unittest.TestCase):
    def payload(self, behavior='pass'):
        return M.execute(unittest.TestSuite([Synthetic(behavior)]))

    def test_pass_exact_counts(self):
        self.assertEqual(M.validate(self.payload()), dict(zip(M.COUNTS, (1, 1, 0, 0, 0, 0, 0))))

    def test_failure_error_skip_never_pass(self):
        for behavior, key in [('fail', 'failures'), ('error', 'errors'), ('skip', 'skips')]:
            payload = self.payload(behavior)
            self.assertNotIn(SECRET, json.dumps(payload))
            counts = M.validate(payload)
            self.assertEqual(counts[key], 1)
            self.assertEqual(counts['passed'], 0)

    def test_expected_failure_and_unexpected_success(self):
        for succeeds, key in [(False, 'expectedFailures'), (True, 'unexpectedSuccesses')]:
            class Expected(Synthetic):
                @unittest.expectedFailure
                def runTest(self):
                    if not succeeds:
                        self.fail(SECRET)
            counts = M.validate(M.execute(unittest.TestSuite([Expected()])))
            self.assertEqual(counts[key], 1)
            self.assertEqual(counts['passed'], 0)

    def test_no_execution_and_duplicate_inventory(self):
        for suite in (unittest.TestSuite(), unittest.TestSuite([Synthetic(), Synthetic()])):
            with self.assertRaises(M.Invalid):
                M.execute(suite)
        payload = self.payload()
        payload['identities'] = []
        with self.assertRaises(M.Invalid):
            M.validate(payload)

    def test_wrong_identity_and_extra_fields(self):
        for key, value in [('identity', SECRET), ('identities', [SECRET]), ('extra', SECRET)]:
            payload = self.payload()
            payload[key] = value
            with self.assertRaises(M.Invalid):
                M.validate(payload)

    def test_invalid_counts(self):
        for key in M.COUNTS:
            for value in (True, -1, 2, SECRET, None):
                payload = self.payload()
                payload['counts'][key] = value
                with self.assertRaises(M.Invalid):
                    M.validate(payload)
        payload = self.payload()
        payload['counts']['skips'] = 1
        with self.assertRaises(M.Invalid):
            M.validate(payload)

    def env(self, root):
        return {'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123',
                'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_WORKSPACE': str(root)}

    def test_unsafe_context_never_emitted(self):
        root = Path('/synthetic')
        for key in self.env(root):
            env = self.env(root)
            env[key] = SECRET
            result = M.report(root, env)
            self.assertIsNone(result['binding'])
            self.assertEqual(result['outcome'], 'UNAVAILABLE')
            self.assertNotIn(SECRET, json.dumps(result))

    def test_report_pass_and_every_nonpass(self):
        root = Path('/synthetic')
        files = {'agent/fixture.py': b'x'}
        for behavior in ('pass', 'fail', 'error', 'skip'):
            with patch.object(M, 'source', return_value=(files, 'b' * 64)), \
                    patch.object(M, 'pinned', return_value=True), \
                    patch.object(M, 'run_snapshot', return_value=M.validate(self.payload(behavior))):
                result = M.report(root, self.env(root))
            self.assertEqual(result['outcome'], 'PASS' if behavior == 'pass' else 'FAIL')
            self.assertNotIn(SECRET, json.dumps(result))

    def test_source_drift_invalid_execution_dependencies(self):
        root = Path('/synthetic')
        files = {'agent/fixture.py': b'x'}
        for stage in ('source', 'pinned', 'run_snapshot', 'drift'):
            with patch.object(M, 'source', side_effect=[(files, 'b' * 64), (files, 'c' * 64)]
                              if stage == 'drift' else None, return_value=(files, 'b' * 64)) as source, \
                    patch.object(M, 'pinned', return_value=True) as pinned, \
                    patch.object(M, 'run_snapshot', return_value=M.validate(self.payload())) as run:
                if stage != 'drift':
                    {'source': source, 'pinned': pinned, 'run_snapshot': run}[stage].side_effect = RuntimeError(SECRET)
                result = M.report(root, self.env(root))
            self.assertEqual(result['outcome'], 'UNAVAILABLE')
            self.assertEqual(result['counts']['executed'], 0)
            self.assertNotIn(SECRET, json.dumps(result))

    def test_environment_drops_injections(self):
        with patch.dict(os.environ, {'PYTHONPATH': SECRET, 'FUSE_SERVICE_TOKEN': SECRET,
                                    'GIT_DIR': SECRET, 'LD_PRELOAD': SECRET}):
            self.assertNotIn(SECRET, json.dumps(M.environment()))

    def test_safe_read_rejects_links_and_oversize(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'data').write_bytes(b'ok')
            (root / 'link').symlink_to(root / 'data')
            with self.assertRaises(OSError):
                M.safe_read(root / 'link')
            (root / 'dirlink').symlink_to(root, target_is_directory=True)
            with self.assertRaises(OSError):
                M.safe_read(root / 'dirlink/data')
            (root / 'data').write_bytes(b'x' * (M.LIMIT + 1))
            with self.assertRaises(M.Invalid):
                M.safe_read(root / 'data')

    def test_git_fixture_binding_mutation_missing_stale(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            names = [M.POLICY, M.RUNNER, 'agent/__init__.py', 'agent/tests/test_startup_process.py', 'agent/app.py',
                     'agent/security_policy.py', 'agent/requirements.txt', 'agent/requirements-dev.txt']
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('synthetic\n')
            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-C', str(root), *args], stderr=subprocess.DEVNULL)
            git('init', '-q')
            git('add', '.')
            git('-c', 'user.name=Synthetic', '-c', 'user.email=synthetic@example.invalid',
                'commit', '-qm', 'Synthetic fixture')
            head = git('rev-parse', 'HEAD').decode().strip()
            files, digest = M.source(root, head)
            self.assertEqual(set(files), set(names))
            self.assertEqual(len(digest), 64)
            (root / 'agent/__pycache__').mkdir()
            (root / 'agent/__pycache__/stale.pyc').write_bytes(b'stale')
            (root / 'agent/untracked.py').write_text(SECRET)
            self.assertEqual(M.source(root, head)[1], digest)
            with self.assertRaises(M.Invalid):
                M.source(root, '0' * 40)
            (root / 'agent/app.py').write_text(SECRET)
            with self.assertRaises(M.Invalid):
                M.source(root, head)
            (root / 'agent/app.py').unlink()
            with self.assertRaises(OSError):
                M.source(root, head)

    def test_worker_report_bounds_and_strict_json(self):
        good = json.dumps(self.payload())
        reports = [good[:-1], good + SECRET, 'x' * 8193,
                   good.replace('"identity":', '"identity": "wrong", "identity":', 1),
                   good.replace('"passed": 1', '"passed": true'),
                   good.replace(M.TEST, SECRET)]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / M.RUNNER
            script.parent.mkdir()
            for payload in reports:
                script.write_text('import sys\nsys.stdout.write(' + repr(payload) + ')\n')
                with self.assertRaises((M.Invalid, ValueError)):
                    M.run_snapshot(root)
            script.write_text('import sys\nsys.stderr.write(' + repr(SECRET) + ')\n'
                              + 'sys.stdout.write(' + repr(good) + ')\n')
            self.assertEqual(M.run_snapshot(root)['passed'], 1)
            script.write_text('import sys\nsys.stdout.write(' + repr(good) + ')\nsys.exit(1)\n')
            with self.assertRaises(M.Invalid):
                M.run_snapshot(root)

    def test_actual_worker_import_failure_and_fd_privacy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'agent/tests').mkdir(parents=True)
            (root / 'agent/__init__.py').write_text('')
            (root / 'agent/tests/__init__.py').write_text('')
            fixture = root / 'agent/tests/test_startup_process.py'
            script = root / M.RUNNER
            script.parent.mkdir()
            # Override pins only in this synthetic worker driver; the production
            # executable has no override. No real startup source is loaded here.
            script.write_text('import importlib.util\nfrom pathlib import Path\n'
                + 's = importlib.util.spec_from_file_location("runner", ' + repr(M.__file__) + ')\n'
                + 'm = importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\n'
                + 'm.pinned = lambda: True\nraise SystemExit(m.worker(Path(' + repr(str(root)) + ')))\n')
            method = M.TEST.rsplit('.', 1)[1]
            noise = ('import os, sys, unittest\nprint(' + repr(SECRET) + ')\n'
                     + 'os.write(1, ' + repr(SECRET.encode()) + ')\n'
                     + 'os.write(2, ' + repr(SECRET.encode()) + ')\n')
            fixture.write_text(noise + 'raise RuntimeError(' + repr(SECRET) + ')\n')
            with self.assertRaises(M.Invalid):
                M.run_snapshot(root)
            fixture.write_text(noise + 'class PythonStartupProcessTest(unittest.TestCase):\n'
                + '    def ' + method + '(self):\n        print(' + repr(SECRET) + ')\n')
            self.assertEqual(M.run_snapshot(root)['passed'], 1)
            fixture.write_text(noise + 'class PythonStartupProcessTest(unittest.TestCase):\n'
                + '    def id(self):\n        return ' + repr(SECRET) + '\n'
                + '    def ' + method + '(self):\n        pass\n')
            with self.assertRaises(M.Invalid):
                M.run_snapshot(root)

    def test_pinned_versions_are_exact(self):
        with patch.object(M.sys, 'version_info', (3, 12, 15)), \
                patch.object(M.importlib.metadata, 'version', side_effect=lambda name: M.PINS[name]):
            self.assertTrue(M.pinned())
        with patch.object(M.sys, 'version_info', (3, 12, 14)):
            self.assertFalse(M.pinned())
        for changed in M.PINS:
            with patch.object(M.sys, 'version_info', (3, 12, 15)), \
                    patch.object(M.importlib.metadata, 'version',
                                 side_effect=lambda name: '0.0' if name == changed else M.PINS[name]):
                self.assertFalse(M.pinned())

    def test_timeout_kills_owned_group_and_reaps(self):
        with patch.object(M.subprocess, 'Popen') as popen, patch.object(M.os, 'killpg') as kill:
            process = popen.return_value
            process.pid = 12345
            process.wait.side_effect = [subprocess.TimeoutExpired(SECRET, 100), -9]
            with self.assertRaises(subprocess.TimeoutExpired):
                M.run_snapshot(Path('/synthetic'))
            kill.assert_called_once_with(12345, M.signal.SIGKILL)
            self.assertEqual(process.wait.call_count, 2)

    def test_snapshot_mutation_rejected(self):
        root = Path('/synthetic')
        files = {'agent/fixture.py': b'x'}
        def mutate(snapshot):
            (snapshot / 'agent/fixture.py').write_text(SECRET)
            return M.validate(self.payload())
        with patch.object(M, 'source', return_value=(files, 'b' * 64)), \
                patch.object(M, 'pinned', return_value=True), \
                patch.object(M, 'run_snapshot', side_effect=mutate):
            result = M.report(root, self.env(root))
        self.assertEqual(result['outcome'], 'UNAVAILABLE')
        self.assertEqual(result['reason'], 'SOURCE_CHANGED')
        self.assertNotIn(SECRET, json.dumps(result))

    def test_invalid_arguments_do_not_echo(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(M.__file__)), SECRET],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b'PYTHON_STARTUP_ARGUMENTS_REJECTED\n')
        self.assertEqual(result.stderr, b'')


if __name__ == '__main__':
    unittest.main()
