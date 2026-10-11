#!/usr/bin/env python3
"""Offline saved recovery success evidence contract regressions. No Git, services or network."""
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


class RecoveryStoredSuccessTests(unittest.TestCase):
    refresh_manifest = fixture.RequiredMethodsTests.refresh_manifest
    refresh_payloads = fixture.RequiredMethodsTests.refresh_payloads
    save = fixture.RequiredMethodsTests.save
    write_report = fixture.RequiredMethodsTests.write_report
    cases = fixture.RequiredMethodsTests.cases
    write_target = fixture.RequiredMethodsTests.write_target

    def setUp(self):
        fixture.RequiredMethodsTests.setUp(self)
        self.recovery_source = self.root / evidence.RECOVERY_STORED_SUCCESS_SOURCE
        self.recovery_source.parent.mkdir(parents=True)
        self.recovery_source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test;\n'
            'import org.junit.jupiter.api.Timeout; class PublicRecoveryStoredSuccessAuthorityIT {\n' + '\n'.join(
                '@Test @Timeout(60) void ' + name + '() {}' for name in evidence.RECOVERY_STORED_SUCCESS_METHODS) + '\n}\n')
        self.write_recovery(); self.refresh_manifest(); self.refresh_payloads()

    def recovery_cases(self):
        return [(evidence.RECOVERY_STORED_SUCCESS_CLASS, name + '()', 'passed') for name in evidence.RECOVERY_STORED_SUCCESS_METHODS]

    def write_recovery(self, cases=None, suite=None):
        self.recovery_xml = self.write_report('integrationTest', 'recovery', suite or evidence.RECOVERY_STORED_SUCCESS_CLASS,
                                         self.recovery_cases() if cases is None else cases)

    def execute(self, command='bind', flagged=True):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', False, False, False, flagged)
        return result, out.getvalue()

    def reject(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', False, False, False, True)
        self.assertEqual('', out.getvalue(), 'No partial payment PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def main(self, command, flagged=True):
        args = [str(fixture.SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
                '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1']
        if flagged: args.append('--require-recovery-stored-success')
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv', args), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_flagged_bind_silent_verify_two_fixed_projections(self):
        self.assertEqual((True, ''), self.execute())
        result, text = self.execute('verify'); self.assertTrue(result)
        payment, recovery = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('FUSE-REQUIRED-METHODS-1', payment['schemaVersion'])
        self.assertEqual('FUSE-RECOVERY-STORED-SUCCESS-METHODS-1', recovery['schemaVersion'])
        self.assertEqual('PASS', recovery['status']); self.assertEqual(evidence.RECOVERY_STORED_SUCCESS_CLASS, recovery['class'])
        self.assertEqual('a'*40, recovery['head']); self.assertEqual('b'*40, recovery['tree'])
        self.assertEqual({'id': '123', 'attempt': '1'}, recovery['run'])
        self.assertEqual(evidence.digest(self.recovery_source.read_bytes())['sha256'], recovery['sourceSha256'])
        self.assertEqual([{'method': n, 'status': 'passed', 'count': 1} for n in evidence.RECOVERY_STORED_SUCCESS_METHODS], recovery['methods'])
        self.assertEqual(payment['rawReportSets'], recovery['rawReportSets'])
        self.assertNotIn(CANARY, text); self.assertNotIn('TEST-', text)
        self.assertEqual({'schemaVersion', 'revision', 'run', 'artifacts', 'complete'},
                         set(json.loads((self.artifacts / evidence.EVIDENCE).read_text())))

    def test_cli_flag(self):
        self.assertEqual((0, 'EVIDENCE_COMPLETE\n', ''), self.main('bind'))
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertEqual(3, len(text.splitlines()))

    def test_missing_method(self):
        self.write_recovery(self.recovery_cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_extra_unknown_target_method(self):
        self.write_recovery(self.recovery_cases() + [(evidence.RECOVERY_STORED_SUCCESS_CLASS, CANARY, 'passed')]); self.refresh_payloads(); self.reject()

    def test_duplicate_method(self):
        self.write_recovery(self.recovery_cases() + self.recovery_cases()[:1]); self.reject()

    def test_nonpassing(self):
        for state in ('failed', 'error', 'skipped'):
            with self.subTest(state=state):
                cases = self.recovery_cases(); cases[0] = (*cases[0][:2], state)
                self.write_recovery(cases); self.refresh_payloads(); self.reject()

    def test_wrong_task(self):
        self.recovery_xml.unlink(); self.write_report('test', 'recovery', evidence.RECOVERY_STORED_SUCCESS_CLASS, self.recovery_cases())
        self.refresh_payloads(); self.reject()

    def test_missing_source_never_not_applicable(self):
        self.recovery_source.unlink(); self.recovery_xml.unlink(); self.refresh_manifest(); self.refresh_payloads(); self.reject()

    def test_missing_tracked_source(self):
        self.recovery_source.unlink(); self.reject()

    def test_untracked_source(self):
        self.revision['files'] = [f for f in self.revision['files'] if f['path'] != evidence.RECOVERY_STORED_SUCCESS_SOURCE]; self.reject()

    def test_source_hash_mismatch(self):
        self.recovery_source.write_text(self.recovery_source.read_text() + '\n'); self.reject()

    def test_source_extra_method(self):
        self.recovery_source.write_text(self.recovery_source.read_text().replace('\n}', '\n@Test void extra() {}\n}'))
        self.refresh_manifest(); self.reject()

    def test_source_wrong_path(self):
        self.recovery_source.rename(self.recovery_source.with_name('Renamed.java')); self.refresh_manifest(); self.reject()

    def test_source_parameterized_not_plain(self):
        s = self.recovery_source.read_text().replace('import org.junit.jupiter.api.Test;',
            'import org.junit.jupiter.api.Test; import org.junit.jupiter.params.ParameterizedTest;')
        self.recovery_source.write_text(s.replace('@Test @Timeout(60) void ' + evidence.RECOVERY_STORED_SUCCESS_METHODS[0] + '()',
            '@ParameterizedTest void ' + evidence.RECOVERY_STORED_SUCCESS_METHODS[0] + '(String value)'))
        self.refresh_manifest(); self.reject()

    def test_source_wildcard_rejected(self):
        self.recovery_source.write_text(self.recovery_source.read_text().replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.*;'))
        self.refresh_manifest(); self.reject()

    def test_class_alias(self):
        self.write_recovery([('PublicRecoveryStoredSuccessAuthorityIT', n, s) for _, n, s in self.recovery_cases()])
        self.refresh_payloads(); self.reject()

    def test_display_and_parameter_aliases(self):
        for name in (CANARY, '[1] value', evidence.RECOVERY_STORED_SUCCESS_METHODS[0] + '(String)[1]'):
            with self.subTest(name=name):
                cases = self.recovery_cases(); cases[0] = (evidence.RECOVERY_STORED_SUCCESS_CLASS, name, 'passed')
                self.write_recovery(cases); self.refresh_payloads(); self.reject()

    def test_target_suite_foreign_case(self):
        self.write_recovery(self.recovery_cases() + [(self.other_class, 'works()', 'passed')]); self.refresh_payloads(); self.reject()

    def test_foreign_suite_target_case(self):
        self.write_recovery(suite='foreign.Suite'); self.refresh_payloads(); self.reject()

    def test_duplicate_report(self):
        (self.recovery_xml.parent / 'TEST-copy.xml').write_bytes(self.recovery_xml.read_bytes()); self.reject()

    def test_duplicate_suite_different_bytes(self):
        (self.recovery_xml.parent / 'TEST-copy.xml').write_bytes(self.recovery_xml.read_bytes() + b'\n'); self.reject()

    def test_malformed_xml_privacy(self):
        self.recovery_xml.write_bytes(('<testsuite ' + CANARY).encode())
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))

    def test_xml_entity(self):
        self.recovery_xml.write_bytes(b'<!DOCTYPE x [<!ENTITY leak "PRIVATE">]><testsuite/>'); self.reject()

    def test_raw_inventory_mismatch(self):
        self.write_recovery(self.recovery_cases()[:-1]); self.reject()

    def test_inventory_boolean_count(self):
        row = next(r for r in self.inventory['tasks']['integrationTest']['rows'] if r['class'] == evidence.RECOVERY_STORED_SUCCESS_CLASS)
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

    def test_recovery_failure_after_bind_no_partial_payment_pass(self):
        self.execute(); self.write_recovery(self.recovery_cases()[:-1]); self.refresh_payloads(); self.reject('verify')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_different_raw_sets_between_projections_reject_before_write_or_output(self):
        original = evidence.recovery_stored_success_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'recovery_stored_success_evidence', side_effect=changed):
            self.reject()
        self.execute()
        with patch.object(evidence, 'recovery_stored_success_evidence', side_effect=changed):
            self.reject('verify')

    def test_flagged_preserves_legacy_payment_not_applicable(self):
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        self.assertEqual((True, ''), self.execute())
        _, text = self.execute('verify')
        payment, recovery = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('NOT_APPLICABLE', payment['status'])
        self.assertEqual('SOURCE_ABSENT', payment['reason'])
        self.assertEqual('PASS', recovery['status'])

    def test_payment_failure_still_rejected(self):
        self.write_target(self.cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_unflagged_preserves_one_payment_projection(self):
        self.assertEqual((True, ''), self.execute(flagged=False))
        _, text = self.execute('verify', flagged=False)
        self.assertEqual('FUSE-REQUIRED-METHODS-1', json.loads(text)['schemaVersion'])
        self.assertNotIn('FUSE-RECOVERY-STORED-SUCCESS-METHODS-1', text)

    def test_unflagged_absent_recovery_preserves_old_caller(self):
        self.recovery_source.unlink(); self.recovery_xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
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
        self.recovery_xml.unlink(); self.recovery_xml.symlink_to(self.base / 'missing'); self.reject()

    def test_raw_parent_symlink(self):
        parent = self.recovery_xml.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_source_leaf_symlink(self):
        self.recovery_source.unlink(); self.recovery_source.symlink_to(self.base / 'missing'); self.reject()

    def test_source_parent_symlink(self):
        parent = self.recovery_source.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_byte_limit(self):
        self.recovery_xml.write_bytes(b'x'*(inventory.MAX_FILE_BYTES + 1)); self.reject()

    def test_depth_limit(self):
        self.recovery_xml.write_bytes(b'<testsuite>' + b'<x>'*20 + b'</x>'*20 + b'</testsuite>'); self.reject()


    def add_rate_contract(self):
        source = self.root / evidence.RATE_SOURCE
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class PublicReadAnonymousRateBoundaryIT {' + ''.join(
                '@Test void ' + name + '() {}' for name in evidence.RATE_METHODS) + '}')
        self.write_report('integrationTest', 'rate', evidence.RATE_CLASS,
                          [(evidence.RATE_CLASS, name + '()', 'passed') for name in evidence.RATE_METHODS])
        self.refresh_manifest(); self.refresh_payloads()

    def add_deadline_contract(self):
        source = self.root / evidence.DEADLINE_SOURCE
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class DefaultKycHttpTimeoutLifecycleIT { @Test void ' + evidence.DEADLINE_METHODS[0] + '() {} }')
        self.write_report('integrationTest', 'deadline', evidence.DEADLINE_CLASS,
            [(evidence.DEADLINE_CLASS, evidence.DEADLINE_METHODS[0] + '()', 'passed')])
        self.refresh_manifest(); self.refresh_payloads()

    def add_api_path_contract(self):
        source = self.root / evidence.API_PATH_GUARD_SOURCE
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class PublicApiCanonicalPathGuardIT {' + ''.join(
                '@Test void ' + name + '() {}' for name in evidence.API_PATH_GUARD_METHODS) + '}')
        self.write_report('integrationTest', 'api-path', evidence.API_PATH_GUARD_CLASS,
                          [(evidence.API_PATH_GUARD_CLASS, name + '()', 'passed') for name in evidence.API_PATH_GUARD_METHODS])
        self.refresh_manifest(); self.refresh_payloads()

    def execute_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', True, True, True, True)
        return result, out.getvalue()

    def reject_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', True, True, True, True)
        self.assertEqual('', out.getvalue(), 'No partial Java PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def test_all_five_contracts_share_exact_raw_sets(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        self.assertEqual((True, ''), self.execute_all())
        result, text = self.execute_all('verify'); self.assertTrue(result)
        payment, rate, deadline, api_path, recovery = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([7, 2, 1, 5, 4], [len(p['methods']) for p in (payment, rate, deadline, api_path, recovery)])
        self.assertEqual(payment['rawReportSets'], rate['rawReportSets'])
        self.assertEqual(rate['rawReportSets'], deadline['rawReportSets'])
        self.assertEqual(deadline['rawReportSets'], api_path['rawReportSets'])
        self.assertEqual(api_path['rawReportSets'], recovery['rawReportSets'])
        self.assertEqual('FUSE-RECOVERY-STORED-SUCCESS-METHODS-1', recovery['schemaVersion'])
        self.assertNotIn(CANARY, text)

    def test_all_five_recovery_failure_never_emits_prior_passes(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract(); self.execute_all()
        self.write_recovery([]); self.refresh_payloads(); self.reject_all('verify')

    def test_all_five_rate_failure_never_writes(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        (self.root / evidence.RATE_SOURCE).unlink()
        self.reject_all()

    def test_absent_payment_still_compares_rate_and_recovery_raw_sets(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        original = evidence.recovery_stored_success_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'recovery_stored_success_evidence', side_effect=changed):
            self.reject_all()
        self.execute_all()
        with patch.object(evidence, 'recovery_stored_success_evidence', side_effect=changed):
            self.reject_all('verify')

    def test_all_five_unrelated_unknown_remains_incomplete(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads(); self.assertEqual((False, ''), self.execute_all())
        complete, text = self.execute_all('verify'); self.assertFalse(complete)
        self.assertEqual(['PASS'] * 5, [json.loads(line)['status'] for line in text.splitlines()])
        self.assertNotIn(CANARY, text)

    def test_each_five_projection_raw_mismatch_rejects_before_write_and_markers(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        names = ('required_method_evidence', 'public_read_rate_evidence',
                 'default_kyc_deadline_evidence', 'api_path_guard_evidence', 'recovery_stored_success_evidence')
        for name in names:
            with self.subTest(projection=name):
                original = getattr(evidence, name)
                def changed(*args):
                    result = original(*args)
                    result['rawReportSets']['integrationTest']['sha256'] = '0'*64
                    return result
                with patch.object(evidence, name, side_effect=changed):
                    self.reject_all()
        self.execute_all()
        for name in names:
            with self.subTest(projection=name):
                original = getattr(evidence, name)
                def changed(*args):
                    result = original(*args)
                    result['rawReportSets']['integrationTest']['sha256'] = '0'*64
                    return result
                with patch.object(evidence, name, side_effect=changed):
                    self.reject_all('verify')

    def test_all_five_deadline_failure_never_writes(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        (self.root / evidence.DEADLINE_SOURCE).unlink()
        self.reject_all()

    def test_all_five_api_path_failure_never_writes(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.add_api_path_contract()
        (self.root / evidence.API_PATH_GUARD_SOURCE).unlink()
        self.reject_all()

    def test_expected_head_and_tree_mismatch_rejected_without_projection(self):
        self.execute()
        path = self.artifacts / evidence.EVIDENCE
        original = path.read_text()
        for field in ('head', 'tree'):
            with self.subTest(field=field):
                bound = json.loads(original)
                bound['revision'][field] = 'c' * 40
                path.write_text(json.dumps(bound))
                self.reject('verify')

    def test_raw_outcome_change_after_bind_emits_no_prior_pass(self):
        self.execute()
        cases = self.recovery_cases(); cases[0] = (*cases[0][:2], 'failed')
        self.write_recovery(cases); self.refresh_payloads()
        self.reject('verify')

    def test_untrusted_composed_annotation_rejected(self):
        self.recovery_source.write_text(self.recovery_source.read_text().replace(
            'import org.junit.jupiter.api.Timeout;', 'import untrusted.Timeout;'))
        self.refresh_manifest(); self.reject()

    def test_source_shadowing_annotation_rejected(self):
        self.recovery_source.write_text(self.recovery_source.read_text() + '\n@interface Timeout {}\n')
        self.refresh_manifest(); self.reject()

    def test_xml_aggregate_counters_must_match(self):
        self.recovery_xml.write_bytes(self.recovery_xml.read_bytes().replace(b'tests="4"', b'tests="5"'))
        self.reject()

    def test_missing_raw_report_rejects(self):
        self.recovery_xml.unlink(); self.reject()

    def test_checked_in_recovery_source_maps_exact_method(self):
        # Source parsing only: this does not compile Java or claim a JUnit execution.
        root = Path(__file__).resolve().parents[1]
        manifest = inventory.source_manifest(root / 'backend/src/test/java')
        self.assertEqual(dict.fromkeys(evidence.RECOVERY_STORED_SUCCESS_METHODS), manifest[evidence.RECOVERY_STORED_SUCCESS_CLASS])


if __name__ == '__main__':
    unittest.main()
