#!/usr/bin/env python3
"""Offline fixed migration projections. Synthetic reports are not Java execution evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch


def deny_external(event, args):
    if event.startswith(('subprocess.', 'socket.')) or event in ('os.system', 'os.posix_spawn', 'os.fork', 'os.exec', 'pty.spawn'):
        raise AssertionError('External execution is forbidden in this offline regression')


sys.addaudithook(deny_external)
SPEC = importlib.util.spec_from_file_location('integrated_fixture', Path(__file__).with_name('ci-recovery-stored-success-evidence-test.py'))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
evidence, inventory, CANARY = fixture.evidence, fixture.inventory, fixture.CANARY


class MigrationEvidenceTests(unittest.TestCase):
    refresh_manifest = fixture.IntegratedSafetyEvidenceTests.refresh_manifest
    refresh_payloads = fixture.IntegratedSafetyEvidenceTests.refresh_payloads
    save = fixture.IntegratedSafetyEvidenceTests.save
    write_report = fixture.IntegratedSafetyEvidenceTests.write_report
    cases = fixture.IntegratedSafetyEvidenceTests.cases
    write_target = fixture.IntegratedSafetyEvidenceTests.write_target
    FLAGS = (*fixture.IntegratedSafetyEvidenceTests.FLAGS, '--require-migration-methods')
    main = fixture.IntegratedSafetyEvidenceTests.main

    def setUp(self):
        fixture.IntegratedSafetyEvidenceTests.setUp(self)
        self.migration_xml = {}
        self.checkout_root = Path(__file__).resolve().parents[1]
        for group in evidence.MIGRATION_CONTRACTS:
            path = self.root / group['source']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.checkout_root / group['source']).read_bytes())
            self.write_group(group)
        self.refresh_manifest(); self.refresh_payloads()

    def group_cases(self, group):
        return [(group['classname'], method + '()', 'passed') for method in group['methods']]

    def write_group(self, group, cases=None, task=None, suite=None):
        cls = group['classname']
        self.migration_xml[cls] = self.write_report(task or group['task'], cls.rsplit('.', 1)[1], suite or cls,
            self.group_cases(group) if cases is None else cases)

    def reject(self, command='bind'):
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main(command))
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def test_ten_groups_and_twenty_required_migration_methods_share_raw_sets(self):
        self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
        status, out, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err)
        self.assertEqual('EVIDENCE_INCOMPLETE', out.splitlines()[-1])
        projections = [json.loads(line) for line in out.splitlines()[:-1]]
        self.assertEqual(10, len(projections))
        self.assertEqual(fixture.IntegratedSafetyEvidenceTests.SCHEMAS,
                         tuple(p['schemaVersion'] for p in projections[:6]))
        self.assertEqual([8, 6, 5, 1], [len(p['methods']) for p in projections[6:]])
        for p in projections:
            self.assertEqual('PASS', p['status']); self.assertEqual('a'*40, p['head'])
            self.assertEqual('b'*40, p['tree']); self.assertEqual({'id': '123', 'attempt': '1'}, p['run'])
            self.assertEqual(projections[0]['rawReportSets'], p['rawReportSets'])
        for p, group in zip(projections[6:], evidence.MIGRATION_CONTRACTS):
            self.assertEqual(group['schema'], p['schemaVersion'])
            self.assertEqual(group['task'], p['task']); self.assertEqual(group['source'], p['source'])
            self.assertEqual(group['classname'], p['class']); self.assertEqual(group['sha256'], p['sourceSha256'])
            self.assertEqual([{'method': m, 'status': 'passed', 'count': 1} for m in group['required']], p['methods'])
        self.assertNotIn(CANARY, out); self.assertNotIn('TEST-', out)
        manifest = inventory.source_manifest(self.source_root)
        self.assertEqual({}, manifest[evidence.MIGRATION_CONTRACTS[1]['classname']])
        self.assertGreater(self.inventory['tasks']['integrationTest']['unmapped']['passed'], 0)

    def test_checked_in_exact_sources_and_literal_method_inventory(self):
        for group in evidence.MIGRATION_CONTRACTS:
            data = (self.checkout_root / group['source']).read_bytes()
            self.assertEqual(group['sha256'], evidence.digest(data)['sha256'])
            self.assertEqual(group['methods'], sorted(re.findall(r'@Test\s+void\s+(\w+)', data.decode())))
            self.assertEqual('test' if group['classname'].endswith('MigrationContractTest') else 'integrationTest', group['task'])

    def test_every_required_method_missing_duplicate_failed_error_skipped_and_alias_rejected(self):
        for group in evidence.MIGRATION_CONTRACTS:
            original = self.group_cases(group)
            for method in group['required']:
                index = next(i for i, row in enumerate(original) if row[1] == method + '()')
                for mutation in ('missing', 'duplicate', 'failed', 'error', 'skipped', 'alias'):
                    with self.subTest(cls=group['classname'], method=method, mutation=mutation):
                        cases = list(original)
                        if mutation == 'missing': cases.pop(index)
                        elif mutation == 'duplicate': cases.append(cases[index])
                        elif mutation == 'alias': cases[index] = (group['classname'], method + '()[1] ' + CANARY, 'passed')
                        else: cases[index] = (*cases[index][:2], mutation)
                        self.write_group(group, cases); self.refresh_payloads(); self.reject()
            self.write_group(group); self.refresh_payloads()

    def test_each_wrong_task_wrong_suite_unknown_and_foreign_case_rejected(self):
        for group in evidence.MIGRATION_CONTRACTS:
            with self.subTest(cls=group['classname']):
                path = self.migration_xml[group['classname']]; path.unlink()
                self.write_group(group, task='test' if group['task'] == 'integrationTest' else 'integrationTest')
                self.refresh_payloads(); self.reject(); self.migration_xml[group['classname']].unlink()
                for suite, cases in [(CANARY, self.group_cases(group)),
                    (None, self.group_cases(group) + [(group['classname'], CANARY, 'passed')]),
                    (None, self.group_cases(group) + [('other.Unknown', CANARY, 'passed')])]:
                    self.write_group(group, cases, suite=suite); self.refresh_payloads(); self.reject()
                self.write_group(group); self.refresh_payloads()

    def test_every_source_absent_untracked_and_hash_mismatch_rejected(self):
        for group in evidence.MIGRATION_CONTRACTS:
            path = self.root / group['source']; original = path.read_bytes()
            with self.subTest(cls=group['classname']):
                path.unlink(); self.reject(); path.write_bytes(original)
                path.write_bytes(original + b'\n'); self.reject()
                self.refresh_manifest(); self.reject()  # Updating checkout digest cannot bypass exact source pin.
                path.write_bytes(original); self.refresh_manifest()
                saved = self.revision['files']; self.revision['files'] = [f for f in saved if f['path'] != group['source']]
                self.reject(); self.revision['files'] = saved

    def test_malformed_duplicate_report_and_missing_report_rejected(self):
        for group in evidence.MIGRATION_CONTRACTS:
            path = self.migration_xml[group['classname']]; original = path.read_bytes()
            for data in (b'<testsuite', original.replace(b'tests="', b'tests="999')):
                path.write_bytes(data); self.reject()
            path.write_bytes(original)
            duplicate = path.with_name('TEST-duplicate.xml'); duplicate.write_bytes(original); self.reject(); duplicate.unlink()
            path.unlink(); self.reject(); path.write_bytes(original)

    def test_verify_identity_payload_and_raw_changes_reject_without_partial_passes(self):
        self.main('bind'); binding = self.artifacts / evidence.EVIDENCE; original = binding.read_bytes()
        for target, key in [('revision', 'head'), ('revision', 'tree'), ('run', 'id'), ('run', 'attempt')]:
            value = json.loads(original); value[target][key] = '9'*40
            binding.write_text(json.dumps(value)); self.reject('verify')
        binding.write_bytes(original)
        for group in evidence.MIGRATION_CONTRACTS:
            cases = self.group_cases(group); method = group['required'][0]
            cases = [(*row[:2], 'failed') if row[1] == method + '()' else row for row in cases]
            self.write_group(group, cases); self.refresh_payloads(); self.reject('verify')
            self.write_group(group); self.refresh_payloads()
        payload = self.artifacts / evidence.PAYLOADS[0]; payload.write_bytes(payload.read_bytes() + b' ')
        self.reject('verify')

    def test_each_migration_raw_set_mismatch_rejects_bind_and_verify(self):
        original = evidence.migration_method_evidence
        for index in range(4):
            def changed(*args):
                result = original(*args); result[index]['rawReportSets']['test']['sha256'] = '0'*64
                return result
            binding = self.artifacts / evidence.EVIDENCE
            if binding.exists(): binding.unlink()
            with patch.object(evidence, 'migration_method_evidence', side_effect=changed): self.reject()
            self.main('bind')
            with patch.object(evidence, 'migration_method_evidence', side_effect=changed): self.reject('verify')

    def test_unrelated_runtime_failure_is_counted_without_expanding_required_scope(self):
        group = evidence.MIGRATION_CONTRACTS[-1]
        method = next(m for m in group['methods'] if m not in group['required'])
        cases = [(cls, name, 'failed' if name == method + '()' else outcome)
                 for cls, name, outcome in self.group_cases(group)]
        self.write_group(group, cases); self.refresh_payloads()
        self.assertEqual('FAIL', self.summary['tasks']['integrationTest']['status'])
        self.assertEqual(1, self.summary['tasks']['integrationTest']['failures'])
        self.assertEqual(0, self.main('bind')[0])
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err)
        self.assertEqual('PASS', json.loads(text.splitlines()[-2])['status'])
        self.assertNotIn(CANARY, text)

    def test_nonrequired_runtime_duplicate_is_not_accepted(self):
        group = evidence.MIGRATION_CONTRACTS[-1]
        cases = self.group_cases(group)
        extra = next(row for row in cases if row[1][:-2] not in group['required'])
        self.write_group(group, cases + [extra]); self.refresh_payloads(); self.reject()

    def test_symlink_source_and_raw_files_rejected(self):
        for group in evidence.MIGRATION_CONTRACTS:
            for path in (self.root / group['source'], self.migration_xml[group['classname']]):
                original = path.read_bytes(); saved = path.with_name(path.name + '.saved')
                saved.write_bytes(original); path.unlink(); path.symlink_to(saved)
                self.reject(); path.unlink(); path.write_bytes(original); saved.unlink()

    def test_default_preserves_six_groups_and_workflow_requires_migration_in_both_commands(self):
        self.FLAGS = fixture.IntegratedSafetyEvidenceTests.FLAGS
        self.main('bind'); status, out, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertEqual(7, len(out.splitlines()))
        workflow = (self.checkout_root / '.github/workflows/ci.yml').read_text()
        commands = [line for line in workflow.splitlines() if 'scripts/ci-test-evidence.py ' in line]
        self.assertEqual(2, len(commands))
        for command in commands:
            for flag in (*self.FLAGS, '--require-migration-methods'): self.assertEqual(1, command.split().count(flag))
        self.assertIn('run: python -B scripts/ci-migration-method-evidence-test.py', workflow)


COMBINED_SPEC = importlib.util.spec_from_file_location('combined_transport_fixture',
    Path(__file__).with_name('ci-http-pool-lifecycle-evidence-test.py'))
combined_fixture = importlib.util.module_from_spec(COMBINED_SPEC)
COMBINED_SPEC.loader.exec_module(combined_fixture)
combined_fixture.evidence = evidence


class AllThirteenEvidenceGroupsTests(unittest.TestCase):
    """Synthetic cross-family parser closure, not execution evidence for Java tests."""
    refresh_manifest = combined_fixture.AllNineEvidenceGroupsTests.refresh_manifest
    refresh_payloads = MigrationEvidenceTests.refresh_payloads
    save = MigrationEvidenceTests.save
    write_report = MigrationEvidenceTests.write_report
    cases = MigrationEvidenceTests.cases
    write_target = MigrationEvidenceTests.write_target
    group_cases = MigrationEvidenceTests.group_cases
    write_group = MigrationEvidenceTests.write_group
    main = MigrationEvidenceTests.main
    reject = MigrationEvidenceTests.reject
    FLAGS = (*combined_fixture.AllNineEvidenceGroupsTests.FLAGS, '--require-migration-methods')
    SCHEMAS = (*combined_fixture.AllNineEvidenceGroupsTests.SCHEMAS,
               *(group['schema'] for group in evidence.MIGRATION_CONTRACTS))

    def setUp(self):
        combined_fixture.AllNineEvidenceGroupsTests.setUp(self)
        self.migration_xml = {}
        self.checkout_root = Path(__file__).resolve().parents[1]
        for group in evidence.MIGRATION_CONTRACTS:
            path = self.root / group['source']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((self.checkout_root / group['source']).read_bytes())
            self.write_group(group)
        self.refresh_manifest(); self.refresh_payloads()

    def require_complete_fixed_groups(self, output):
        lines = output.splitlines()
        self.assertEqual('EVIDENCE_INCOMPLETE', lines[-1])
        projections = [json.loads(line) for line in lines[:-1]]
        self.assertEqual(self.SCHEMAS, tuple(p['schemaVersion'] for p in projections))
        self.assertEqual([7, 2, 1, 5, 2, 4, 5, 1, 1, 8, 6, 5, 1], [len(p['methods']) for p in projections])
        self.assertEqual(48, sum(len(p['methods']) for p in projections))
        for item in projections:
            self.assertEqual('PASS', item['status'])
            self.assertEqual('a'*40, item['head']); self.assertEqual('b'*40, item['tree'])
            self.assertEqual({'id': '123', 'attempt': '1'}, item['run'])
            self.assertEqual(projections[0]['rawReportSets'], item['rawReportSets'])
            self.assertTrue(all(m['status'] == 'passed' and m['count'] == 1 for m in item['methods']))
        for item, group in zip(projections[9:], evidence.MIGRATION_CONTRACTS):
            self.assertEqual(group['task'], item['task']); self.assertEqual(group['source'], item['source'])
            self.assertEqual(group['sha256'], item['sourceSha256'])
            self.assertEqual(group['required'], [x['method'] for x in item['methods']])
        for index, filename in ((4, evidence.RAG_FIXTURE), (6, evidence.RAG_SUPPLIED_FIXTURE)):
            raw = (self.root / filename).read_bytes()
            self.assertEqual({'path': filename, **evidence.digest(raw),
                'canonicalSha256': evidence.hashlib.sha256(json.dumps(json.loads(raw), ensure_ascii=False,
                    sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()},
                projections[index]['fixture'])
        self.assertNotIn(CANARY, output); self.assertNotIn('TEST-', output)
        return projections

    def test_all_flags_bind_and_verify_thirteen_groups_without_claiming_generic_completeness(self):
        self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
        status, output, error = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', error)
        self.require_complete_fixed_groups(output)
        self.assertFalse(json.loads((self.artifacts / evidence.EVIDENCE).read_bytes())['complete'])
        self.assertGreater(self.inventory['tasks']['integrationTest']['unmapped']['passed'], 0)

    def test_every_flag_is_required_once_in_both_real_workflow_commands(self):
        workflow = (self.checkout_root / '.github/workflows/ci.yml').read_text()
        commands = [line for line in workflow.splitlines() if 'scripts/ci-test-evidence.py ' in line]
        self.assertEqual(2, len(commands))
        self.assertIn(' bind ', commands[0]); self.assertIn(' verify ', commands[1])
        for command in commands:
            for flag in self.FLAGS:
                self.assertEqual(1, command.split().count(flag))
                with self.assertRaises(AssertionError):
                    self.assertEqual(1, command.replace(flag, '').split().count(flag))

    def test_omitted_optional_flag_cannot_satisfy_full_composition_oracle(self):
        self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
        original = self.FLAGS
        for omitted in original:
            with self.subTest(flag=omitted):
                self.FLAGS = tuple(flag for flag in original if flag != omitted)
                status, output, error = self.main('verify')
                self.assertEqual(0, status); self.assertEqual('', error)
                with self.assertRaises(AssertionError): self.require_complete_fixed_groups(output)
        self.FLAGS = original
        self.require_complete_fixed_groups(self.main('verify')[1])

    def all_groups(self):
        return [dict(classname=cls, source=source, methods=list(methods), required=list(methods),
                     task='integrationTest') for cls, source, methods in self.groups] + list(evidence.MIGRATION_CONTRACTS)

    def xml_for(self, group):
        return (self.group_xml if group['classname'] in self.group_xml else self.migration_xml)[group['classname']]

    def test_missing_required_case_in_every_selected_testing_or_migration_group_rejects(self):
        for group in self.all_groups():
            with self.subTest(group=group['classname']):
                path = self.xml_for(group); original = path.read_bytes()
                cases = [case for case in self.group_cases(group) if case[1] != group['required'][0] + '()']
                self.write_report(group['task'], group['classname'].rsplit('.', 1)[1], group['classname'], cases)
                self.refresh_payloads(); self.reject()
                path.write_bytes(original); self.refresh_payloads()

    def test_failed_required_case_in_every_selected_testing_or_migration_group_rejects(self):
        for group in self.all_groups():
            with self.subTest(group=group['classname']):
                path = self.xml_for(group); original = path.read_bytes()
                cases = [(cls, name, 'failed' if name == group['required'][0] + '()' else state)
                         for cls, name, state in self.group_cases(group)]
                self.write_report(group['task'], group['classname'].rsplit('.', 1)[1], group['classname'], cases)
                self.refresh_payloads(); self.reject()
                path.write_bytes(original); self.refresh_payloads()

    def test_source_mutation_across_testing_and_migration_rejects(self):
        for group in self.all_groups():
            with self.subTest(group=group['classname']):
                path = self.root / group['source']; original = path.read_bytes()
                method = group['required'][0]
                path.write_bytes(original.replace(method.encode(), (method + 'Changed').encode()))
                self.refresh_manifest(); self.refresh_payloads(); self.reject()
                path.write_bytes(original); self.refresh_manifest(); self.refresh_payloads()

    def test_task_mismatch_across_testing_and_migration_rejects(self):
        for group in self.all_groups():
            with self.subTest(group=group['classname']):
                path = self.xml_for(group); original = path.read_bytes(); path.unlink()
                wrong = 'test' if group['task'] == 'integrationTest' else 'integrationTest'
                misplaced = self.write_report(wrong, group['classname'].rsplit('.', 1)[1],
                                               group['classname'], self.group_cases(group))
                self.refresh_payloads(); self.reject()
                misplaced.unlink(); path.write_bytes(original); self.refresh_payloads()

    def test_duplicate_required_case_across_testing_and_migration_rejects(self):
        for group in self.all_groups():
            with self.subTest(group=group['classname']):
                path = self.xml_for(group); original = path.read_bytes()
                cases = self.group_cases(group)
                cases.append((group['classname'], group['required'][0] + '()', 'passed'))
                self.write_report(group['task'], group['classname'].rsplit('.', 1)[1], group['classname'], cases)
                self.refresh_payloads(); self.reject()
                path.write_bytes(original); self.refresh_payloads()

    def test_cross_family_raw_report_mismatch_rejects_before_any_projection_output(self):
        for name in ('rag_supplied_document_evidence', 'http_pool_lifecycle_evidence', 'migration_method_evidence'):
            with self.subTest(helper=name):
                original = getattr(evidence, name)
                def changed(*args, **kwargs):
                    result = original(*args, **kwargs)
                    item = result[0] if isinstance(result, list) else result
                    item['rawReportSets']['test']['sha256'] = 'f'*64
                    return result
                with patch.object(evidence, name, side_effect=changed): self.reject()
        self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
        for name in ('rag_supplied_document_evidence', 'http_pool_lifecycle_evidence', 'migration_method_evidence'):
            original = getattr(evidence, name)
            def changed(*args, **kwargs):
                result = original(*args, **kwargs)
                item = result[0] if isinstance(result, list) else result
                item['rawReportSets']['test']['sha256'] = 'f'*64
                return result
            with patch.object(evidence, name, side_effect=changed): self.reject('verify')


if __name__ == '__main__':
    unittest.main()
