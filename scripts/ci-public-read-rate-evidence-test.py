#!/usr/bin/env python3
"""Offline HTTP-rate evidence contract regressions. No Git, services or network."""
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


class PublicReadRateTests(unittest.TestCase):
    refresh_manifest = fixture.RequiredMethodsTests.refresh_manifest
    refresh_payloads = fixture.RequiredMethodsTests.refresh_payloads
    save = fixture.RequiredMethodsTests.save
    write_report = fixture.RequiredMethodsTests.write_report
    cases = fixture.RequiredMethodsTests.cases
    write_target = fixture.RequiredMethodsTests.write_target

    def setUp(self):
        fixture.RequiredMethodsTests.setUp(self)
        self.rate_source = self.root / evidence.RATE_SOURCE
        self.rate_source.parent.mkdir(parents=True)
        self.rate_source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test;\n'
            'class PublicReadAnonymousRateBoundaryIT {\n' + '\n'.join(
                '@Test void ' + name + '() {}' for name in evidence.RATE_METHODS) + '\n}\n')
        self.write_rate(); self.refresh_manifest(); self.refresh_payloads()

    def rate_cases(self):
        return [(evidence.RATE_CLASS, name + '()', 'passed') for name in evidence.RATE_METHODS]

    def write_rate(self, cases=None, suite=None):
        self.rate_xml = self.write_report('integrationTest', 'rate', suite or evidence.RATE_CLASS,
                                         self.rate_cases() if cases is None else cases)

    def execute(self, command='bind', flagged=True):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', flagged)
        return result, out.getvalue()

    def reject(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', True)
        self.assertEqual('', out.getvalue(), 'No partial payment PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def main(self, command, flagged=True):
        args = [str(fixture.SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
                '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1']
        if flagged: args.append('--require-public-read-rate')
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv', args), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_flagged_bind_silent_verify_two_fixed_projections(self):
        self.assertEqual((True, ''), self.execute())
        result, text = self.execute('verify'); self.assertTrue(result)
        payment, rate = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('FUSE-REQUIRED-METHODS-1', payment['schemaVersion'])
        self.assertEqual('FUSE-PUBLIC-READ-RATE-METHODS-1', rate['schemaVersion'])
        self.assertEqual('PASS', rate['status']); self.assertEqual(evidence.RATE_CLASS, rate['class'])
        self.assertEqual('a'*40, rate['head']); self.assertEqual('b'*40, rate['tree'])
        self.assertEqual({'id': '123', 'attempt': '1'}, rate['run'])
        self.assertEqual(evidence.digest(self.rate_source.read_bytes())['sha256'], rate['sourceSha256'])
        self.assertEqual([{'method': n, 'status': 'passed', 'count': 1} for n in evidence.RATE_METHODS], rate['methods'])
        self.assertEqual(payment['rawReportSets'], rate['rawReportSets'])
        self.assertNotIn(CANARY, text); self.assertNotIn('TEST-', text)
        self.assertEqual({'schemaVersion', 'revision', 'run', 'artifacts', 'complete'},
                         set(json.loads((self.artifacts / evidence.EVIDENCE).read_text())))

    def test_cli_flag(self):
        self.assertEqual((0, 'EVIDENCE_COMPLETE\n', ''), self.main('bind'))
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertEqual(3, len(text.splitlines()))

    def test_missing_method(self):
        self.write_rate(self.rate_cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_extra_unknown_target_method(self):
        self.write_rate(self.rate_cases() + [(evidence.RATE_CLASS, CANARY, 'passed')]); self.refresh_payloads(); self.reject()

    def test_duplicate_method(self):
        self.write_rate(self.rate_cases() + self.rate_cases()[:1]); self.reject()

    def test_nonpassing(self):
        for state in ('failed', 'error', 'skipped'):
            with self.subTest(state=state):
                cases = self.rate_cases(); cases[0] = (*cases[0][:2], state)
                self.write_rate(cases); self.refresh_payloads(); self.reject()

    def test_wrong_task(self):
        self.rate_xml.unlink(); self.write_report('test', 'rate', evidence.RATE_CLASS, self.rate_cases())
        self.refresh_payloads(); self.reject()

    def test_missing_source_never_not_applicable(self):
        self.rate_source.unlink(); self.rate_xml.unlink(); self.refresh_manifest(); self.refresh_payloads(); self.reject()

    def test_missing_tracked_source(self):
        self.rate_source.unlink(); self.reject()

    def test_untracked_source(self):
        self.revision['files'] = [f for f in self.revision['files'] if f['path'] != evidence.RATE_SOURCE]; self.reject()

    def test_source_hash_mismatch(self):
        self.rate_source.write_text(self.rate_source.read_text() + '\n'); self.reject()

    def test_source_extra_method(self):
        self.rate_source.write_text(self.rate_source.read_text().replace('\n}', '\n@Test void extra() {}\n}'))
        self.refresh_manifest(); self.reject()

    def test_source_wrong_path(self):
        self.rate_source.rename(self.rate_source.with_name('Renamed.java')); self.refresh_manifest(); self.reject()

    def test_source_parameterized_not_plain(self):
        s = self.rate_source.read_text().replace('import org.junit.jupiter.api.Test;',
            'import org.junit.jupiter.api.Test; import org.junit.jupiter.params.ParameterizedTest;')
        self.rate_source.write_text(s.replace('@Test void ' + evidence.RATE_METHODS[0] + '()',
            '@ParameterizedTest void ' + evidence.RATE_METHODS[0] + '(String value)'))
        self.refresh_manifest(); self.reject()

    def test_source_wildcard_rejected(self):
        self.rate_source.write_text(self.rate_source.read_text().replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.*;'))
        self.refresh_manifest(); self.reject()

    def test_class_alias(self):
        self.write_rate([('PublicReadAnonymousRateBoundaryIT', n, s) for _, n, s in self.rate_cases()])
        self.refresh_payloads(); self.reject()

    def test_display_and_parameter_aliases(self):
        for name in (CANARY, '[1] value', evidence.RATE_METHODS[0] + '(String)[1]'):
            with self.subTest(name=name):
                cases = self.rate_cases(); cases[0] = (evidence.RATE_CLASS, name, 'passed')
                self.write_rate(cases); self.refresh_payloads(); self.reject()

    def test_target_suite_foreign_case(self):
        self.write_rate(self.rate_cases() + [(self.other_class, 'works()', 'passed')]); self.refresh_payloads(); self.reject()

    def test_foreign_suite_target_case(self):
        self.write_rate(suite='foreign.Suite'); self.refresh_payloads(); self.reject()

    def test_duplicate_report(self):
        (self.rate_xml.parent / 'TEST-copy.xml').write_bytes(self.rate_xml.read_bytes()); self.reject()

    def test_duplicate_suite_different_bytes(self):
        (self.rate_xml.parent / 'TEST-copy.xml').write_bytes(self.rate_xml.read_bytes() + b'\n'); self.reject()

    def test_malformed_xml_privacy(self):
        self.rate_xml.write_bytes(('<testsuite ' + CANARY).encode())
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))

    def test_xml_entity(self):
        self.rate_xml.write_bytes(b'<!DOCTYPE x [<!ENTITY leak "PRIVATE">]><testsuite/>'); self.reject()

    def test_raw_inventory_mismatch(self):
        self.write_rate(self.rate_cases()[:-1]); self.reject()

    def test_inventory_boolean_count(self):
        row = next(r for r in self.inventory['tasks']['integrationTest']['rows'] if r['class'] == evidence.RATE_CLASS)
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

    def test_rate_failure_after_bind_no_partial_payment_pass(self):
        self.execute(); self.write_rate(self.rate_cases()[:-1]); self.refresh_payloads(); self.reject('verify')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_different_raw_sets_between_projections_reject_before_write_or_output(self):
        original = evidence.public_read_rate_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'public_read_rate_evidence', side_effect=changed):
            self.reject()
        self.execute()
        with patch.object(evidence, 'public_read_rate_evidence', side_effect=changed):
            self.reject('verify')

    def test_flagged_preserves_legacy_payment_not_applicable(self):
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        self.assertEqual((True, ''), self.execute())
        _, text = self.execute('verify')
        payment, rate = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('NOT_APPLICABLE', payment['status'])
        self.assertEqual('SOURCE_ABSENT', payment['reason'])
        self.assertEqual('PASS', rate['status'])

    def test_payment_failure_still_rejected(self):
        self.write_target(self.cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_unflagged_preserves_one_payment_projection(self):
        self.assertEqual((True, ''), self.execute(flagged=False))
        _, text = self.execute('verify', flagged=False)
        self.assertEqual('FUSE-REQUIRED-METHODS-1', json.loads(text)['schemaVersion'])
        self.assertNotIn('FUSE-PUBLIC-READ-RATE-METHODS-1', text)

    def test_unflagged_absent_rate_preserves_old_caller(self):
        self.rate_source.unlink(); self.rate_xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
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
        self.rate_xml.unlink(); self.rate_xml.symlink_to(self.base / 'missing'); self.reject()

    def test_raw_parent_symlink(self):
        parent = self.rate_xml.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_source_leaf_symlink(self):
        self.rate_source.unlink(); self.rate_source.symlink_to(self.base / 'missing'); self.reject()

    def test_source_parent_symlink(self):
        parent = self.rate_source.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_byte_limit(self):
        self.rate_xml.write_bytes(b'x'*(inventory.MAX_FILE_BYTES + 1)); self.reject()

    def test_depth_limit(self):
        self.rate_xml.write_bytes(b'<testsuite>' + b'<x>'*20 + b'</x>'*20 + b'</testsuite>'); self.reject()


if __name__ == '__main__':
    unittest.main()
