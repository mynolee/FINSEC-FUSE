#!/usr/bin/env python3
"""Offline recovery source scope evidence contract regressions. No Git, services or network."""
import contextlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import importlib.util


def deny_external(event, args):
    if event.startswith(('subprocess.', 'socket.')) or event in ('os.system', 'os.posix_spawn', 'os.fork', 'os.exec', 'pty.spawn'):
        raise AssertionError('External execution is forbidden in this offline regression')


sys.addaudithook(deny_external)
SPEC = importlib.util.spec_from_file_location('payment_regressions', Path(__file__).with_name('ci-required-method-evidence-test.py'))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
evidence, inventory, CANARY = fixture.evidence, fixture.inventory, fixture.CANARY


class RecoverySourceScopeEvidenceTests(unittest.TestCase):
    refresh_manifest = fixture.RequiredMethodsTests.refresh_manifest
    refresh_payloads = fixture.RequiredMethodsTests.refresh_payloads
    save = fixture.RequiredMethodsTests.save
    write_report = fixture.RequiredMethodsTests.write_report
    cases = fixture.RequiredMethodsTests.cases
    write_target = fixture.RequiredMethodsTests.write_target

    def setUp(self):
        fixture.RequiredMethodsTests.setUp(self)
        self.scope_source = self.root / evidence.RECOVERY_SOURCE_SCOPE_SOURCE
        self.scope_source.parent.mkdir(parents=True)
        self.scope_source.write_text('package com.finsec.fuse.quarantine; import org.junit.jupiter.api.Test;\n'
            'import org.junit.jupiter.api.Timeout; class SecurityScopeIT {\n' + '\n'.join(
                '@Test @Timeout(60) void ' + name + '() {}' for name in evidence.RECOVERY_SOURCE_SCOPE_METHODS) + '\n}\n')
        self.write_scope(); self.refresh_manifest(); self.refresh_payloads()

    def scope_cases(self):
        return [(evidence.RECOVERY_SOURCE_SCOPE_CLASS, name + '()', 'passed') for name in evidence.RECOVERY_SOURCE_SCOPE_METHODS]

    def write_scope(self, cases=None, suite=None):
        self.scope_xml = self.write_report('integrationTest', 'scope', suite or evidence.RECOVERY_SOURCE_SCOPE_CLASS,
                                         self.scope_cases() if cases is None else cases)

    def execute(self, command='bind', flagged=True):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_recovery_source_scope=flagged)
        return result, out.getvalue()

    def reject(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_recovery_source_scope=True)
        self.assertEqual('', out.getvalue(), 'No partial payment PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def main(self, command, flagged=True):
        args = [str(fixture.SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
                '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1']
        if flagged: args.append('--require-recovery-source-scope')
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv', args), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_flagged_bind_silent_verify_two_fixed_projections(self):
        self.assertEqual((True, ''), self.execute())
        result, text = self.execute('verify'); self.assertTrue(result)
        payment, scope = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('FUSE-REQUIRED-METHODS-1', payment['schemaVersion'])
        self.assertEqual('FUSE-RECOVERY-SOURCE-SCOPE-METHODS-1', scope['schemaVersion'])
        self.assertEqual('PASS', scope['status']); self.assertEqual(evidence.RECOVERY_SOURCE_SCOPE_CLASS, scope['class'])
        self.assertEqual('a'*40, scope['head']); self.assertEqual('b'*40, scope['tree'])
        self.assertEqual({'id': '123', 'attempt': '1'}, scope['run'])
        self.assertEqual(evidence.digest(self.scope_source.read_bytes())['sha256'], scope['sourceSha256'])
        self.assertEqual([{'method': n, 'status': 'passed', 'count': 1} for n in evidence.RECOVERY_SOURCE_SCOPE_METHODS], scope['methods'])
        self.assertEqual(payment['rawReportSets'], scope['rawReportSets'])
        self.assertNotIn(CANARY, text); self.assertNotIn('TEST-', text)
        self.assertEqual({'schemaVersion', 'revision', 'run', 'artifacts', 'complete'},
                         set(json.loads((self.artifacts / evidence.EVIDENCE).read_text())))

    def test_cli_flag(self):
        self.assertEqual((0, 'EVIDENCE_COMPLETE\n', ''), self.main('bind'))
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertEqual(3, len(text.splitlines()))

    def test_missing_method(self):
        self.write_scope(self.scope_cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_extra_unknown_target_method(self):
        self.write_scope(self.scope_cases() + [(evidence.RECOVERY_SOURCE_SCOPE_CLASS, CANARY, 'passed')]); self.refresh_payloads(); self.reject()

    def test_duplicate_method(self):
        self.write_scope(self.scope_cases() + self.scope_cases()[:1]); self.reject()

    def test_nonpassing(self):
        for state in ('failed', 'error', 'skipped'):
            with self.subTest(state=state):
                cases = self.scope_cases(); cases[0] = (*cases[0][:2], state)
                self.write_scope(cases); self.refresh_payloads(); self.reject()

    def test_wrong_task(self):
        self.scope_xml.unlink(); self.write_report('test', 'scope', evidence.RECOVERY_SOURCE_SCOPE_CLASS, self.scope_cases())
        self.refresh_payloads(); self.reject()

    def test_missing_source_never_not_applicable(self):
        self.scope_source.unlink(); self.scope_xml.unlink(); self.refresh_manifest(); self.refresh_payloads(); self.reject()

    def test_missing_tracked_source(self):
        self.scope_source.unlink(); self.reject()

    def test_untracked_source(self):
        self.revision['files'] = [f for f in self.revision['files'] if f['path'] != evidence.RECOVERY_SOURCE_SCOPE_SOURCE]; self.reject()

    def test_source_hash_mismatch(self):
        self.scope_source.write_text(self.scope_source.read_text() + '\n'); self.reject()

    def test_source_extra_method(self):
        self.scope_source.write_text(self.scope_source.read_text().replace('\n}', '\n@Test void extra() {}\n}'))
        self.refresh_manifest(); self.reject()

    def test_source_wrong_path(self):
        self.scope_source.rename(self.scope_source.with_name('Renamed.java')); self.refresh_manifest(); self.reject()

    def test_source_parameterized_not_plain(self):
        s = self.scope_source.read_text().replace('import org.junit.jupiter.api.Test;',
            'import org.junit.jupiter.api.Test; import org.junit.jupiter.params.ParameterizedTest;')
        self.scope_source.write_text(s.replace('@Test @Timeout(60) void ' + evidence.RECOVERY_SOURCE_SCOPE_METHODS[0] + '()',
            '@ParameterizedTest void ' + evidence.RECOVERY_SOURCE_SCOPE_METHODS[0] + '(String value)'))
        self.refresh_manifest(); self.reject()

    def test_source_wildcard_rejected(self):
        self.scope_source.write_text(self.scope_source.read_text().replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.*;'))
        self.refresh_manifest(); self.reject()

    def test_class_alias(self):
        self.write_scope([('SecurityScopeIT', n, s) for _, n, s in self.scope_cases()])
        self.refresh_payloads(); self.reject()

    def test_display_and_parameter_aliases(self):
        for name in (CANARY, '[1] value', evidence.RECOVERY_SOURCE_SCOPE_METHODS[0] + '(String)[1]'):
            with self.subTest(name=name):
                cases = self.scope_cases(); cases[0] = (evidence.RECOVERY_SOURCE_SCOPE_CLASS, name, 'passed')
                self.write_scope(cases); self.refresh_payloads(); self.reject()

    def test_target_suite_foreign_case(self):
        self.write_scope(self.scope_cases() + [(self.other_class, 'works()', 'passed')]); self.refresh_payloads(); self.reject()

    def test_foreign_suite_target_case(self):
        self.write_scope(suite='foreign.Suite'); self.refresh_payloads(); self.reject()

    def test_duplicate_report(self):
        (self.scope_xml.parent / 'TEST-copy.xml').write_bytes(self.scope_xml.read_bytes()); self.reject()

    def test_duplicate_suite_different_bytes(self):
        (self.scope_xml.parent / 'TEST-copy.xml').write_bytes(self.scope_xml.read_bytes() + b'\n'); self.reject()

    def test_malformed_xml_privacy(self):
        self.scope_xml.write_bytes(('<testsuite ' + CANARY).encode())
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))

    def test_xml_entity(self):
        self.scope_xml.write_bytes(b'<!DOCTYPE x [<!ENTITY leak "PRIVATE">]><testsuite/>'); self.reject()

    def test_raw_inventory_mismatch(self):
        self.write_scope(self.scope_cases()[:-1]); self.reject()

    def test_inventory_boolean_count(self):
        row = next(r for r in self.inventory['tasks']['integrationTest']['rows'] if r['class'] == evidence.RECOVERY_SOURCE_SCOPE_CLASS)
        row['count'] = True; self.save(); self.reject()

    def test_stale_binding_and_bool_int_emit_neither_projection(self):
        self.execute(); path = self.artifacts / evidence.EVIDENCE; original = path.read_text()
        for mutation in ('run', 'bool', 'hash'):
            with self.subTest(mutation=mutation):
                data = json.loads(original)
                if mutation == 'run': data['run']['attempt'] = '2'
                elif mutation == 'bool': data['complete'] = 1
                else: data['artifacts'][evidence.PAYLOADS[0]]['sha256'] = '0'*64
                path.write_text(json.dumps(data)); self.reject('verify')

    def test_scope_failure_after_bind_no_partial_payment_pass(self):
        self.execute(); self.write_scope(self.scope_cases()[:-1]); self.refresh_payloads(); self.reject('verify')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_different_raw_sets_between_projections_reject_before_write_or_output(self):
        original = evidence.recovery_source_scope_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'recovery_source_scope_evidence', side_effect=changed):
            self.reject()
        self.execute()
        with patch.object(evidence, 'recovery_source_scope_evidence', side_effect=changed):
            self.reject('verify')

    def test_flagged_preserves_legacy_payment_not_applicable(self):
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        self.assertEqual((True, ''), self.execute())
        _, text = self.execute('verify')
        payment, scope = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('NOT_APPLICABLE', payment['status'])
        self.assertEqual('SOURCE_ABSENT', payment['reason'])
        self.assertEqual('PASS', scope['status'])

    def test_payment_failure_still_rejected(self):
        self.write_target(self.cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_unflagged_preserves_one_payment_projection(self):
        self.assertEqual((True, ''), self.execute(flagged=False))
        _, text = self.execute('verify', flagged=False)
        self.assertEqual('FUSE-REQUIRED-METHODS-1', json.loads(text)['schemaVersion'])
        self.assertNotIn('FUSE-RECOVERY-SOURCE-SCOPE-METHODS-1', text)

    def test_unflagged_absent_scope_preserves_old_caller(self):
        self.scope_source.unlink(); self.scope_xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(evidence.execute('bind', self.root, self.artifacts, 'a'*40, '123', '1'))
            self.assertTrue(evidence.execute('verify', self.root, self.artifacts, 'a'*40, '123', '1'))
        self.assertEqual('FUSE-REQUIRED-METHODS-1', json.loads(out.getvalue())['schemaVersion'])

    def test_unrelated_unmapped_keeps_incomplete(self):
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads(); self.assertEqual((False, ''), self.execute())
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertNotIn(CANARY, text)
        self.assertEqual('EVIDENCE_INCOMPLETE', text.splitlines()[-1])
        self.assertEqual(['PASS', 'PASS'], [json.loads(x)['status'] for x in text.splitlines()[:2]])

    def test_raw_leaf_symlink(self):
        self.scope_xml.unlink(); self.scope_xml.symlink_to(self.base / 'missing'); self.reject()

    def test_raw_parent_symlink(self):
        parent = self.scope_xml.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_source_leaf_symlink(self):
        self.scope_source.unlink(); self.scope_source.symlink_to(self.base / 'missing'); self.reject()

    def test_source_parent_symlink(self):
        parent = self.scope_source.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_byte_limit(self):
        self.scope_xml.write_bytes(b'x'*(inventory.MAX_FILE_BYTES + 1)); self.reject()

    def test_depth_limit(self):
        self.scope_xml.write_bytes(b'<testsuite>' + b'<x>'*20 + b'</x>'*20 + b'</testsuite>'); self.reject()


    def add_rate_contract(self):
        source = self.root / evidence.RATE_SOURCE
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class PublicReadAnonymousRateBoundaryIT {' + ''.join(
                '@Test void ' + name + '() {}' for name in evidence.RATE_METHODS) + '}')
        self.write_report('integrationTest', 'rate', evidence.RATE_CLASS,
                          [(evidence.RATE_CLASS, name + '()', 'passed') for name in evidence.RATE_METHODS])
        self.refresh_manifest(); self.refresh_payloads()

    def execute_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_recovery_source_scope=True)
        return result, out.getvalue()

    def reject_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_recovery_source_scope=True)
        self.assertEqual('', out.getvalue(), 'No partial Java PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def test_all_three_contracts_share_exact_raw_sets(self):
        self.add_rate_contract()
        self.assertEqual((True, ''), self.execute_all())
        result, text = self.execute_all('verify'); self.assertTrue(result)
        payment, rate, scope = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([7, 2, 6], [len(p['methods']) for p in (payment, rate, scope)])
        self.assertEqual(payment['rawReportSets'], rate['rawReportSets'])
        self.assertEqual(rate['rawReportSets'], scope['rawReportSets'])
        self.assertEqual('FUSE-RECOVERY-SOURCE-SCOPE-METHODS-1', scope['schemaVersion'])
        self.assertNotIn(CANARY, text)

    def test_all_three_scope_failure_never_emits_prior_passes(self):
        self.add_rate_contract(); self.execute_all()
        self.write_scope([]); self.refresh_payloads(); self.reject_all('verify')

    def test_all_three_rate_failure_never_writes(self):
        self.add_rate_contract()
        (self.root / evidence.RATE_SOURCE).unlink()
        self.reject_all()

    def test_absent_payment_still_compares_rate_and_scope_raw_sets(self):
        self.add_rate_contract()
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        original = evidence.recovery_source_scope_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'recovery_source_scope_evidence', side_effect=changed):
            self.reject_all()
        self.execute_all()
        with patch.object(evidence, 'recovery_source_scope_evidence', side_effect=changed):
            self.reject_all('verify')

    def test_all_three_unrelated_unknown_remains_incomplete(self):
        self.add_rate_contract()
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads(); self.assertEqual((False, ''), self.execute_all())
        complete, text = self.execute_all('verify'); self.assertFalse(complete)
        self.assertEqual(['PASS'] * 3, [json.loads(line)['status'] for line in text.splitlines()])
        self.assertNotIn(CANARY, text)

    def test_untrusted_composed_annotation_rejected(self):
        self.scope_source.write_text(self.scope_source.read_text().replace(
            'import org.junit.jupiter.api.Timeout;', 'import untrusted.Timeout;'))
        self.refresh_manifest(); self.reject()

    def test_source_shadowing_annotation_rejected(self):
        self.scope_source.write_text(self.scope_source.read_text() + '\n@interface Timeout {}\n')
        self.refresh_manifest(); self.reject()

    def test_xml_aggregate_counters_must_match(self):
        self.scope_xml.write_bytes(self.scope_xml.read_bytes().replace(b'tests="6"', b'tests="7"'))
        self.reject()

    def test_missing_raw_report_rejects(self):
        self.scope_xml.unlink(); self.reject()

    def test_checked_in_scope_source_maps_exact_method(self):
        # Source parsing only: this does not compile Java or claim a JUnit execution.
        root = Path(__file__).resolve().parents[1]
        manifest = inventory.source_manifest(root / 'backend/src/test/java')
        self.assertEqual(dict.fromkeys(evidence.RECOVERY_SOURCE_SCOPE_METHODS), manifest[evidence.RECOVERY_SOURCE_SCOPE_CLASS])


MIGRATION_SPEC = importlib.util.spec_from_file_location('migration_fixture',
    Path(__file__).with_name('ci-migration-method-evidence-test.py'))
migration = importlib.util.module_from_spec(MIGRATION_SPEC)
MIGRATION_SPEC.loader.exec_module(migration)
migration.evidence = evidence
migration.fixture.evidence = evidence
migration.combined_fixture.evidence = evidence


class AllFourteenEvidenceGroupsTests(unittest.TestCase):
    """Exact synthetic reporter composition; no Java execution is claimed here."""
    parent_fixture_class = migration.AllThirteenEvidenceGroupsTests
    refresh_manifest = parent_fixture_class.refresh_manifest
    refresh_payloads = parent_fixture_class.refresh_payloads
    save = parent_fixture_class.save
    write_report = parent_fixture_class.write_report
    cases = parent_fixture_class.cases
    write_target = parent_fixture_class.write_target
    group_cases = parent_fixture_class.group_cases
    write_group = parent_fixture_class.write_group
    main = parent_fixture_class.main
    reject = parent_fixture_class.reject
    xml_for = parent_fixture_class.xml_for
    SCHEMAS = parent_fixture_class.SCHEMAS
    FLAGS = (*parent_fixture_class.FLAGS, '--require-recovery-source-scope')
    test_every_flag_is_required_once_in_both_real_workflow_commands = parent_fixture_class.test_every_flag_is_required_once_in_both_real_workflow_commands
    test_omitted_optional_flag_cannot_satisfy_full_composition_oracle = parent_fixture_class.test_omitted_optional_flag_cannot_satisfy_full_composition_oracle
    test_missing_required_case_in_every_selected_testing_or_migration_group_rejects = parent_fixture_class.test_missing_required_case_in_every_selected_testing_or_migration_group_rejects
    test_failed_required_case_in_every_selected_testing_or_migration_group_rejects = parent_fixture_class.test_failed_required_case_in_every_selected_testing_or_migration_group_rejects
    test_source_mutation_across_testing_and_migration_rejects = parent_fixture_class.test_source_mutation_across_testing_and_migration_rejects
    test_task_mismatch_across_testing_and_migration_rejects = parent_fixture_class.test_task_mismatch_across_testing_and_migration_rejects
    test_duplicate_required_case_across_testing_and_migration_rejects = parent_fixture_class.test_duplicate_required_case_across_testing_and_migration_rejects

    def setUp(self):
        self.parent_fixture_class.setUp(self)
        self.scope_source = self.root / evidence.RECOVERY_SOURCE_SCOPE_SOURCE
        self.scope_source.parent.mkdir(parents=True, exist_ok=True)
        self.scope_source.write_bytes((self.checkout_root / evidence.RECOVERY_SOURCE_SCOPE_SOURCE).read_bytes())
        self.group_xml[evidence.RECOVERY_SOURCE_SCOPE_CLASS] = self.write_report('integrationTest', 'SecurityScopeIT',
            evidence.RECOVERY_SOURCE_SCOPE_CLASS,
            [(evidence.RECOVERY_SOURCE_SCOPE_CLASS, method + '()', 'passed') for method in evidence.RECOVERY_SOURCE_SCOPE_METHODS])
        self.refresh_manifest(); self.refresh_payloads()

    def all_groups(self):
        return self.parent_fixture_class.all_groups(self) + [dict(classname=evidence.RECOVERY_SOURCE_SCOPE_CLASS,
            source=evidence.RECOVERY_SOURCE_SCOPE_SOURCE, methods=list(evidence.RECOVERY_SOURCE_SCOPE_METHODS),
            required=list(evidence.RECOVERY_SOURCE_SCOPE_METHODS), task='integrationTest')]

    def require_complete_fixed_groups(self, output):
        lines = output.splitlines()
        self.assertEqual(15, len(lines))
        projections = self.parent_fixture_class.require_complete_fixed_groups(self, '\n'.join(lines[:13] + [lines[-1]]))
        scope = json.loads(lines[13]); projections.append(scope)
        self.assertEqual('FUSE-RECOVERY-SOURCE-SCOPE-METHODS-1', scope['schemaVersion'])
        self.assertEqual(evidence.RECOVERY_SOURCE_SCOPE_CLASS, scope['class'])
        self.assertEqual('PASS', scope['status'])
        self.assertEqual('a'*40, scope['head']); self.assertEqual('b'*40, scope['tree'])
        self.assertEqual({'id': '123', 'attempt': '1'}, scope['run'])
        self.assertEqual(evidence.digest(self.scope_source.read_bytes())['sha256'], scope['sourceSha256'])
        self.assertEqual([{'method': name, 'status': 'passed', 'count': 1}
                          for name in evidence.RECOVERY_SOURCE_SCOPE_METHODS], scope['methods'])
        self.assertEqual(projections[0]['rawReportSets'], scope['rawReportSets'])
        self.assertEqual(54, sum(len(item['methods']) for item in projections))
        self.assertNotIn(CANARY, output); self.assertNotIn('TEST-', output)
        return projections

    def test_fourteen_groups_preserve_incomplete_and_all_fifty_four_method_identities(self):
        self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
        status, output, error = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', error)
        self.require_complete_fixed_groups(output)
        self.assertFalse(json.loads((self.artifacts / evidence.EVIDENCE).read_bytes())['complete'])
        self.assertGreater(self.inventory['tasks']['integrationTest']['unmapped']['passed'], 0)
        workflow = (self.checkout_root / '.github/workflows/ci.yml').read_text()
        self.assertIn('run: python -B scripts/ci-recovery-source-scope-evidence-test.py', workflow)

    def test_every_new_method_missing_nonpassing_duplicate_or_aliased_rejects(self):
        path = self.group_xml[evidence.RECOVERY_SOURCE_SCOPE_CLASS]
        original = path.read_bytes()
        initial = [(evidence.RECOVERY_SOURCE_SCOPE_CLASS, name + '()', 'passed')
                   for name in evidence.RECOVERY_SOURCE_SCOPE_METHODS]
        for index, method in enumerate(evidence.RECOVERY_SOURCE_SCOPE_METHODS):
            for mutation in ('missing', 'failed', 'error', 'skipped', 'duplicate', 'alias'):
                with self.subTest(method=method, mutation=mutation):
                    cases = list(initial)
                    if mutation == 'missing': cases.pop(index)
                    elif mutation == 'duplicate': cases.append(cases[index])
                    elif mutation == 'alias': cases[index] = (cases[index][0], method + '()[1] ' + CANARY, 'passed')
                    else: cases[index] = (*cases[index][:2], mutation)
                    self.write_report('integrationTest', 'SecurityScopeIT', evidence.RECOVERY_SOURCE_SCOPE_CLASS, cases)
                    self.refresh_payloads(); self.reject()
                    path.write_bytes(original); self.refresh_payloads()

    def test_each_family_raw_mismatch_rejects_before_binding_or_any_pass(self):
        names = ('required_method_evidence', 'public_read_rate_evidence', 'default_kyc_deadline_evidence',
                 'api_path_guard_evidence', 'rag_nonexistent_evidence', 'recovery_stored_success_evidence',
                 'rag_supplied_document_evidence', 'scheduled_kyc_capacity_evidence',
                 'http_pool_lifecycle_evidence', 'migration_method_evidence', 'recovery_source_scope_evidence')
        binding = self.artifacts / evidence.EVIDENCE
        for name in names:
            original = getattr(evidence, name)
            for index in range(4 if name == 'migration_method_evidence' else 1):
                with self.subTest(helper=name, index=index):
                    if binding.exists(): binding.unlink()
                    def changed(*args, **kwargs):
                        result = original(*args, **kwargs)
                        selected = result[index] if isinstance(result, list) else result
                        selected['rawReportSets']['integrationTest']['sha256'] = '0'*64
                        return result
                    with patch.object(evidence, name, side_effect=changed): self.reject()
                    self.assertEqual((0, 'EVIDENCE_INCOMPLETE\n', ''), self.main('bind'))
                    with patch.object(evidence, name, side_effect=changed): self.reject('verify')


if __name__ == '__main__':
    unittest.main()
