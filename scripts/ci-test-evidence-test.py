#!/usr/bin/env python3
"""Synthetic, offline integrity and privacy regression tests."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('ci-test-evidence.py')
spec = importlib.util.spec_from_file_location('evidence', SCRIPT)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)
CANARY = 'PRIVATE_CANARY_DO_NOT_PRINT_778891'


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.artifacts = self.base / 'repo', self.base / 'artifacts'
        self.root.mkdir()
        self.artifacts.mkdir()
        self.source = self.root / 'backend/src/test/java/com/finsec/fuse/ExampleTest.java'
        self.source.parent.mkdir(parents=True)
        self.source.write_text('package com.finsec.fuse;\nimport org.junit.jupiter.api.Test;\nclass ExampleTest { @Test void works() {} }\n')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic Test')
        self.git('config', 'user.email', 'synthetic@example.invalid')
        self.git('add', '.')
        self.git('commit', '-qm', 'synthetic fixture')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.summary = {'schemaVersion': 'FUSE-TEST-COUNTS-1', 'scope': evidence.SCOPE,
                        'tasks': {name: {'status': 'PASS', 'tests': 1, 'failures': 0, 'errors': 0, 'skipped': 0,
                                         'failureIds': [], 'unknownFailureIds': 0, 'omittedFailureIds': 0}
                                  for name in sorted(evidence.TASKS)}}
        self.inventory = {'schemaVersion': 'FUSE-TEST-INVENTORY-1', 'tasks': {}}
        for name in sorted(evidence.TASKS):
            counts = {'passed': 1, 'failed': 0, 'error': 0, 'skipped': 0}
            self.inventory['tasks'][name] = {'status': 'VALID', 'complete': True, 'counts': counts,
                'mapped': dict(counts), 'unmapped': dict.fromkeys(counts, 0),
                'rows': [{'class': 'com.finsec.fuse.ExampleTest', 'method': 'works', 'status': 'passed', 'count': 1}],
                'diagnostics': []}
        self.save()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL).decode()

    def save(self):
        (self.artifacts / evidence.PAYLOADS[0]).write_text(json.dumps(self.inventory))
        (self.artifacts / evidence.PAYLOADS[1]).write_text(json.dumps(self.summary))

    def execute(self, command='bind', **changes):
        args = dict(command=command, root=self.root, artifacts=self.artifacts, head=self.head, run_id='123', attempt='1')
        args.update(changes)
        return evidence.execute(**args)

    def reject(self, **changes):
        with self.assertRaises((ValueError, OSError, TypeError)):
            self.execute(**changes)

    def test_complete_round_trip_and_manifest(self):
        self.assertTrue(self.execute())
        self.assertTrue(self.execute('verify'))
        data = json.loads((self.artifacts / evidence.EVIDENCE).read_text())
        self.assertEqual(data['revision']['tree'], self.git('rev-parse', 'HEAD^{tree}').strip())
        self.assertEqual(data['revision']['files'], [{'path': self.source.relative_to(self.root).as_posix(), **evidence.digest(self.source.read_bytes())}])
        self.assertNotIn('package com', json.dumps(data))

    def test_unknown_is_partial_even_when_summary_passes(self):
        for i in self.inventory['tasks'].values():
            i['unmapped'], i['mapped'] = i['mapped'], i['unmapped']
            i.update(rows=[], complete=False, diagnostics=['UNMAPPED_IDENTITIES'])
        self.save()
        self.assertFalse(self.execute())
        self.assertFalse(self.execute('verify'))

    def test_wrong_run_attempt_head(self):
        self.execute()
        for changes in ({'run_id': '124'}, {'attempt': '2'}, {'head': 'a' * 40}):
            self.reject(command='verify', **changes)

    def test_malformed_identity(self):
        for key in ('head', 'run_id', 'attempt'):
            for value in ('', '01', '-1', CANARY, '1\n', True):
                self.reject(**{key: value})

    def test_tampered_payload_bytes(self):
        self.execute()
        path = self.artifacts / evidence.PAYLOADS[0]
        path.write_bytes(path.read_bytes() + b' ')
        self.reject(command='verify')

    def test_tampered_binding(self):
        self.execute()
        path = self.artifacts / evidence.EVIDENCE
        original = json.loads(path.read_text())
        for mutate in (lambda d: d['revision'].update(tree='a' * 40),
                       lambda d: d['revision'].update(files=[]),
                       lambda d: d.update(complete=1),
                       lambda d: d.update(extra=CANARY),
                       lambda d: d['artifacts'][evidence.PAYLOADS[0]].update(bytes=1)):
            data = copy.deepcopy(original)
            mutate(data)
            path.write_text(json.dumps(data))
            self.reject(command='verify')

    def test_extra_missing_artifacts(self):
        extra = self.artifacts / CANARY
        extra.write_text(CANARY)
        self.reject()
        extra.unlink()
        (self.artifacts / evidence.PAYLOADS[0]).unlink()
        self.reject()

    def test_symlink_file_and_ancestor(self):
        original = self.artifacts / evidence.PAYLOADS[0]
        target = self.base / 'secret'
        original.rename(target)
        original.symlink_to(target)
        self.reject()
        original.unlink()
        target.rename(original)
        link = self.base / 'linked'
        link.symlink_to(self.artifacts, target_is_directory=True)
        self.reject(artifacts=link)

    def test_source_symlink_and_submodule_rejected(self):
        self.source.unlink()
        self.source.symlink_to('/dev/null')
        self.git('add', '.')
        self.git('commit', '-qm', 'link')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.reject()
        self.source.unlink()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + self.head + ',submodule')
        self.git('commit', '-qm', 'submodule')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.reject()

    def test_modified_source_even_assume_unchanged(self):
        self.git('update-index', '--assume-unchanged', str(self.source.relative_to(self.root)))
        self.source.write_text(CANARY)
        self.reject()

    def test_parent_repository_never_inferred(self):
        nested = self.root / 'nested'
        nested.mkdir()
        self.reject(root=nested)

    def test_stale_revision(self):
        self.execute()
        (self.root / 'new.txt').write_text('new public source')
        self.git('add', '.')
        self.git('commit', '-qm', 'new tree')
        self.reject(command='verify')

    def test_unknown_fields_at_all_levels(self):
        for container in (self.summary, self.summary['tasks']['test'], self.inventory,
                          self.inventory['tasks']['test'], self.inventory['tasks']['test']['counts'],
                          self.inventory['tasks']['test']['rows'][0]):
            container['extra'] = CANARY
            self.save()
            self.reject()
            del container['extra']

    def test_duplicate_json_keys(self):
        path = self.artifacts / evidence.PAYLOADS[0]
        path.write_text('{"schemaVersion":"bad",' + json.dumps(self.inventory)[1:])
        self.reject()

    def test_forged_or_mismatched_counts(self):
        task = self.inventory['tasks']['test']
        for mapping in (task['counts'], task['mapped'], task['unmapped']):
            mapping['passed'] += 1
            self.save()
            self.reject()
            mapping['passed'] -= 1
        self.summary['tasks']['test']['tests'] = 2
        self.save()
        self.reject()

    def test_unknown_mapping_cannot_claim_complete(self):
        task = self.inventory['tasks']['test']
        task.update(mapped=dict.fromkeys(evidence.STATES, 0), unmapped=dict(task['counts']), rows=[], diagnostics=['UNMAPPED_IDENTITIES'])
        self.save()
        self.reject()

    def test_invalid_or_missing_cannot_claim_complete(self):
        for status in ('INVALID_REPORT', 'NOT_RUN'):
            task = self.inventory['tasks']['test']
            task.update(status=status, counts=dict.fromkeys(evidence.STATES, 0), mapped=dict.fromkeys(evidence.STATES, 0),
                        unmapped=dict.fromkeys(evidence.STATES, 0), rows=[], diagnostics=['REPORT_REJECTED'] if status == 'INVALID_REPORT' else ['REPORTS_MISSING'])
            self.summary['tasks']['test'].update(status=status, tests=0)
            self.save()
            self.reject()
            task['complete'] = False
            self.save()
            self.assertFalse(self.execute())
            (self.artifacts / evidence.EVIDENCE).unlink()
            task['complete'] = True

    def test_untracked_identity_source_rejected(self):
        injected = self.source.with_name('InjectedTest.java')
        injected.write_text('package com.finsec.fuse;\nimport org.junit.jupiter.api.Test;\nclass InjectedTest { @Test void injected() {} }\n')
        row = self.inventory['tasks']['test']['rows'][0]
        row.update({'class': 'com.finsec.fuse.InjectedTest', 'method': 'injected'})
        self.save()
        self.reject()

    def test_tracked_artifact_directory_rejected(self):
        artifact = self.root / 'tracked-artifacts'
        artifact.mkdir()
        for name in evidence.PAYLOADS:
            (artifact / name).write_bytes((self.artifacts / name).read_bytes())
        self.git('add', '.')
        self.git('commit', '-qm', 'tracked artifacts')
        self.head = self.git('rev-parse', 'HEAD').strip()
        self.reject(artifacts=artifact)

    def test_failure_line_must_match_source_method(self):
        s = self.summary['tasks']['test']
        s.update(status='FAIL', failures=1, failureIds=[{'class': 'com.finsec.fuse.ExampleTest', 'method': 'works', 'sourceLine': 99999}])
        i = self.inventory['tasks']['test']
        i['counts'].update(passed=0, failed=1)
        i['mapped'].update(passed=0, failed=1)
        i['rows'][0]['status'] = 'failed'
        self.save()
        self.reject()

    def test_failure_ids_must_reconcile_exactly(self):
        s = self.summary['tasks']['test']
        s.update(status='FAIL', failures=1)
        i = self.inventory['tasks']['test']
        i['counts'].update(passed=0, failed=1)
        i['mapped'].update(passed=0, failed=1)
        i['rows'][0]['status'] = 'failed'
        self.save()
        self.reject()
        s['unknownFailureIds'] = 1
        self.save()
        self.assertTrue(self.execute())

    def test_failure_ids_cannot_name_only_passing_method(self):
        self.source.write_text('package com.finsec.fuse;\nimport org.junit.jupiter.api.Test;\nclass ExampleTest { @Test void works() {} @Test void fails() {} }\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'two methods')
        self.head = self.git('rev-parse', 'HEAD').strip()
        s = self.summary['tasks']['test']
        s.update(status='FAIL', tests=2, failures=1, failureIds=[{'class': 'com.finsec.fuse.ExampleTest', 'method': 'works', 'sourceLine': None}])
        i = self.inventory['tasks']['test']
        i['counts']['failed'] = i['mapped']['failed'] = 1
        i['rows'].insert(0, {'class': 'com.finsec.fuse.ExampleTest', 'method': 'fails', 'status': 'failed', 'count': 1})
        self.save()
        self.reject()
        s['failureIds'][0]['method'] = 'fails'
        self.save()
        self.assertTrue(self.execute())

    def test_bounded_canary_diagnostics(self):
        command = [sys.executable, str(SCRIPT), 'bind', '--repository', str(self.root), '--artifacts', str(self.artifacts),
                   '--head', self.head, '--run-id', '123', '--run-attempt', '1']
        (self.artifacts / evidence.PAYLOADS[0]).write_text('{"private":"' + CANARY + '"}')
        for args in (command, command + ['--' + CANARY]):
            result = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, 'EVIDENCE_REJECTED\n')
            self.assertEqual(result.stderr, '')

    def test_oversized_and_deep_json(self):
        path = self.artifacts / evidence.PAYLOADS[0]
        path.write_bytes(b' ' * (evidence.LIMIT + 1))
        self.reject()
        path.write_text('[' * 1100 + ']' * 1100)
        result = subprocess.run([sys.executable, str(SCRIPT), 'bind', '--repository', str(self.root), '--artifacts', str(self.artifacts),
            '--head', self.head, '--run-id', '123', '--run-attempt', '1'], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (1, 'EVIDENCE_REJECTED\n', ''))


if __name__ == '__main__':
    unittest.main()
