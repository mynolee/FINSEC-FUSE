#!/usr/bin/env python3
"""Offline synthetic safeguards only; does not claim pinned-runtime execution."""
import contextlib
import io
import json
import importlib.util
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('ci-dns-lifecycle-evidence.py')
spec = importlib.util.spec_from_file_location('dns_evidence', PATH)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def good():
    return {'collected': list(m.EXPECTED), 'phases': [[n, p, 'PASS'] for n in m.EXPECTED
            for p in ('setup', 'call', 'teardown')], 'invalid': False, 'exitCode': 0}


class EvidenceTests(unittest.TestCase):
    def reject(self, value):
        with self.assertRaises(m.helper.Invalid):
            m.validate(value)

    def test_exact_pass_only(self):
        self.assertEqual(len(m.EXPECTED), 37)
        self.assertEqual(len(m.validate(good())), 37)

    def test_missing_extra_duplicate_collection(self):
        for collected in (list(m.EXPECTED[:-1]), list(m.EXPECTED) + ['private value'],
                          list(m.EXPECTED[:-1]) + [m.EXPECTED[0]]):
            value = good()
            value['collected'] = collected
            self.reject(value)

    def test_missing_duplicate_extra_phases(self):
        for change in ('missing', 'duplicate', 'extra'):
            value = good()
            if change == 'missing': value['phases'].pop()
            elif change == 'duplicate': value['phases'][-1] = value['phases'][0]
            else: value['phases'].append(value['phases'][0])
            self.reject(value)

    def test_every_phase_must_pass(self):
        for phase in range(3):
            for outcome in ('FAIL', 'SKIP', 'XFAIL', 'XPASS', 'passed'):
                value = good()
                value['phases'][phase][2] = outcome
                self.reject(value)

    def test_closed_schema_and_types(self):
        for field, bad in [('invalid', 0), ('invalid', True), ('exitCode', False),
                           ('exitCode', 1), ('exitCode', '0'), ('collected', ()),
                           ('phases', None)]:
            value = good()
            value[field] = bad
            self.reject(value)
        value = good()
        value['private'] = 'secret'
        self.reject(value)

    def test_plugin_pass_records_all_phases(self):
        plugin = m.EvidencePlugin()
        plugin.pytest_collection_finish(SimpleNamespace(items=[SimpleNamespace(nodeid=n) for n in m.EXPECTED]))
        for node, phase, _ in good()['phases']:
            plugin.pytest_runtest_logreport(SimpleNamespace(nodeid=node, when=phase, outcome='passed'))
        self.assertEqual(len(m.validate(plugin.payload(0))), 37)

    def test_plugin_rejects_skip_xfail_xpass_unknown_and_failed_teardown(self):
        for fields in ({'outcome': 'skipped'}, {'wasxfail': ''}, {'wasxfail': 'private'},
                       {'nodeid': 'private'}, {'when': 'unknown'},
                       {'outcome': 'failed', 'when': 'teardown'}):
            plugin = m.EvidencePlugin()
            report = dict(nodeid=m.EXPECTED[0], when='call', outcome='passed')
            report.update(fields)
            plugin.pytest_runtest_logreport(SimpleNamespace(**report))
            self.assertTrue(plugin.invalid)
            self.assertEqual(plugin.phases, [])

    def test_collection_errors_or_skips_rejected(self):
        for outcome in ('failed', 'skipped'):
            plugin = m.EvidencePlugin()
            plugin.pytest_collectreport(SimpleNamespace(outcome=outcome))
            self.assertTrue(plugin.invalid)

    def run_report(self, source_changes=False, runtime=True, child_error=False):
        binding = {'checkout': 'a' * 40, 'run': '1', 'attempt': '1'}
        source = ({'agent/example.py': b'synthetic'}, 'b' * 64, 'c' * 40)
        after = (source[0], 'd' * 64, source[2]) if source_changes else source
        with patch.object(m.helper, 'context', return_value=binding), \
             patch.object(m, 'source', side_effect=[source, after]), \
             patch.object(m.helper, 'pinned', return_value=runtime), \
             patch.object(m, 'run_snapshot', side_effect=RuntimeError('private') if child_error else None,
                          return_value=m.validate(good())):
            return m.report()

    def test_report_binds_runtime_revision_and_both_digests(self):
        result, reason = self.run_report()
        self.assertIsNone(reason)
        self.assertEqual(result['binding']['tree'], 'c' * 40)
        self.assertEqual(result['sourceSha256Before'], result['sourceSha256After'])
        self.assertEqual(result['dependencies'], m.helper.PINS)
        self.assertEqual(result['python'], '3.12.15')
        self.assertEqual(result['scope'], 'OFFLINE_DNS_LIFECYCLE_ONLY')

    def test_source_change_cannot_publish(self):
        self.assertEqual(self.run_report(source_changes=True), (None, 'SOURCE_CHANGED'))

    def test_runtime_mismatch_cannot_publish(self):
        self.assertEqual(self.run_report(runtime=False), (None, 'DEPENDENCIES_UNAVAILABLE'))

    def test_child_failure_is_sanitized(self):
        self.assertEqual(self.run_report(child_error=True), (None, 'EXECUTION_REJECTED'))

    def test_context_and_source_failure_are_sanitized(self):
        with patch.object(m.helper, 'context', side_effect=ValueError('private')):
            self.assertEqual(m.report(), (None, 'CONTEXT_REJECTED'))
        with patch.object(m.helper, 'context', return_value={'checkout': 'a' * 40}), \
             patch.object(m, 'source', side_effect=ValueError('private')):
            self.assertEqual(m.report(), (None, 'SOURCE_REJECTED'))

    def test_child_json_duplicates_nonzero_and_oversize_rejected(self):
        encoded = json.dumps(good()).encode()
        for data, code in ((b'{"invalid":false,"invalid":false}', 0),
                           (encoded, 1), (b' ' * 65537, 0), (b'', 0), (b'{malformed', 0)):
            process = unittest.mock.Mock(pid=123)
            process.wait.return_value = code
            def start(*args, **kwargs):
                kwargs['stdout'].write(data)
                return process
            with tempfile.TemporaryDirectory() as directory, \
                 patch.object(m.subprocess, 'Popen', side_effect=start), \
                 patch.object(m.os, 'killpg'):
                with self.assertRaises((m.helper.Invalid, json.JSONDecodeError)):
                    m.run_snapshot(Path(directory))

    def test_stale_artifact_cannot_emit_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'safe-artifacts').mkdir()
            target = root / 'safe-artifacts' / m.ARTIFACT
            target.write_text('stale')
            output = io.StringIO()
            with patch.object(m, 'ROOT', root), \
                 patch.object(m.sys, 'argv', ['reporter']), \
                 patch.object(m.sys, 'flags', SimpleNamespace(isolated=1, dont_write_bytecode=1)), \
                 patch.object(m, 'report', return_value=({'outcome': 'PASS'}, None)), \
                 contextlib.redirect_stdout(output):
                self.assertEqual(m.main(), 1)
            self.assertEqual(target.read_text(), 'stale')
            self.assertEqual(output.getvalue(), 'DNS_LIFECYCLE_EVIDENCE_REJECTED: ARTIFACT_REJECTED\n')

    def test_source_verifies_committed_bytes_modes_and_no_symlinks(self):
        paths = [m.RUNNER, m.HELPER, m.TEST, m.WORKFLOW, m.helper.POLICY,
                 'agent/__init__.py', 'agent/outbound.py', 'agent/app.py',
                 'agent/requirements.txt', 'agent/requirements-dev.txt']
        data = b'synthetic committed bytes'
        head, tree, oid = 'a' * 40, 'b' * 40, 'c' * 40
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in paths:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o644)
            def git(actual_root, *args):
                self.assertEqual(actual_root, root)
                if args == ('rev-parse', '--show-toplevel'): return str(root).encode()
                if args == ('rev-parse', '--verify', 'HEAD'): return head.encode()
                if args == ('rev-parse', 'HEAD^{tree}'): return tree.encode()
                if args[0] == 'ls-tree':
                    return b''.join(('100644 blob ' + oid + '\t' + p + '\0').encode() for p in paths)
                if args == ('cat-file', 'blob', oid): return data
                self.fail('unexpected Git operation')
            with patch.object(m.helper, 'git', side_effect=git):
                self.assertEqual(m.source(root, head)[2], tree)
                target = root / m.TEST
                target.write_bytes(b'changed')
                with self.assertRaises(m.helper.Invalid): m.source(root, head)
                target.write_bytes(data)
                target.chmod(0o755)
                with self.assertRaises(m.helper.Invalid): m.source(root, head)
                target.unlink()
                target.symlink_to(root / m.RUNNER)
                with self.assertRaises((m.helper.Invalid, OSError)): m.source(root, head)

    def test_deadline_kills_group_and_reaps(self):
        process = unittest.mock.Mock(pid=123)
        process.wait.side_effect = [subprocess.TimeoutExpired('private', 45), 0]
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(m.subprocess, 'Popen', return_value=process), \
             patch.object(m.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                m.run_snapshot(Path(directory))
            process.wait.assert_any_call(timeout=45)
            kill.assert_called_once_with(123, m.signal.SIGKILL)
            self.assertEqual(process.wait.call_count, 2)


if __name__ == '__main__':
    unittest.main()
