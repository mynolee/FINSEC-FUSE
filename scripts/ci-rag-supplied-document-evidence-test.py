#!/usr/bin/env python3
"""Offline synthetic RAG evidence contract regressions. No Git, services or network."""
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


class RagSuppliedDocumentEvidenceTests(unittest.TestCase):
    refresh_payloads = fixture.RequiredMethodsTests.refresh_payloads
    save = fixture.RequiredMethodsTests.save
    write_report = fixture.RequiredMethodsTests.write_report
    cases = fixture.RequiredMethodsTests.cases
    write_target = fixture.RequiredMethodsTests.write_target

    def setUp(self):
        fixture.RequiredMethodsTests.setUp(self)
        self.rag_source = self.root / evidence.RAG_SUPPLIED_SOURCE
        self.rag_source.parent.mkdir(parents=True)
        self.rag_source.write_text('package com.finsec.fuse.experiments; import org.junit.jupiter.api.Test;\n'
            'import org.junit.jupiter.api.Timeout; class RagSuppliedDocumentStimulusReplayIT {\n' + '\n'.join(
                '@Test @Timeout(60) void ' + name + '() {}' for name in evidence.RAG_SUPPLIED_METHODS) + '\n}\n')
        self.rag_fixture = self.root / evidence.RAG_SUPPLIED_FIXTURE
        self.rag_fixture.parent.mkdir(parents=True)
        self.rag_fixture.write_text(json.dumps({'fixtureSetId': 'rag-supplied-document-stimulus-v1',
                                                'syntheticFixtureText': CANARY}))
        self.write_rag(); self.refresh_manifest(); self.refresh_payloads()

    def refresh_manifest(self):
        fixture.RequiredMethodsTests.refresh_manifest(self)
        path = self.root / evidence.RAG_SUPPLIED_FIXTURE
        if path.is_file():
            self.revision['files'].append({'path': evidence.RAG_SUPPLIED_FIXTURE, **evidence.digest(path.read_bytes())})

    def rag_cases(self):
        return [(evidence.RAG_SUPPLIED_CLASS, name + '()', 'passed') for name in evidence.RAG_SUPPLIED_METHODS]

    def write_rag(self, cases=None, suite=None):
        self.rag_xml = self.write_report('integrationTest', 'rag', suite or evidence.RAG_SUPPLIED_CLASS,
                                         self.rag_cases() if cases is None else cases)

    def execute(self, command='bind', flagged=True):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_rag_supplied_document=flagged)
        return result, out.getvalue()

    def reject(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_rag_supplied_document=True)
        self.assertEqual('', out.getvalue(), 'No partial payment PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def main(self, command, flagged=True):
        args = [str(fixture.SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
                '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1']
        if flagged: args.append('--require-rag-supplied-document')
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv', args), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_flagged_bind_silent_verify_two_fixed_projections(self):
        self.assertEqual((True, ''), self.execute())
        result, text = self.execute('verify'); self.assertTrue(result)
        payment, rag = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('FUSE-REQUIRED-METHODS-1', payment['schemaVersion'])
        self.assertEqual('FUSE-RAG-SUPPLIED-DOCUMENT-METHODS-1', rag['schemaVersion'])
        self.assertEqual('PASS', rag['status']); self.assertEqual(evidence.RAG_SUPPLIED_CLASS, rag['class'])
        self.assertEqual({'path': evidence.RAG_SUPPLIED_FIXTURE, **evidence.digest(self.rag_fixture.read_bytes()),
            'canonicalSha256': evidence.hashlib.sha256(json.dumps(json.loads(self.rag_fixture.read_bytes()),
                ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}, rag['fixture'])
        self.assertEqual('a'*40, rag['head']); self.assertEqual('b'*40, rag['tree'])
        self.assertEqual({'id': '123', 'attempt': '1'}, rag['run'])
        self.assertEqual(evidence.digest(self.rag_source.read_bytes())['sha256'], rag['sourceSha256'])
        self.assertEqual([{'method': n, 'status': 'passed', 'count': 1} for n in evidence.RAG_SUPPLIED_METHODS], rag['methods'])
        self.assertEqual(payment['rawReportSets'], rag['rawReportSets'])
        self.assertNotIn(CANARY, text); self.assertNotIn('TEST-', text)
        self.assertEqual({'schemaVersion', 'revision', 'run', 'artifacts', 'complete'},
                         set(json.loads((self.artifacts / evidence.EVIDENCE).read_text())))

    def test_cli_flag(self):
        self.assertEqual((0, 'EVIDENCE_COMPLETE\n', ''), self.main('bind'))
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err); self.assertEqual(3, len(text.splitlines()))

    def test_missing_method(self):
        self.write_rag(self.rag_cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_extra_unknown_target_method(self):
        self.write_rag(self.rag_cases() + [(evidence.RAG_SUPPLIED_CLASS, CANARY, 'passed')]); self.refresh_payloads(); self.reject()

    def test_duplicate_method(self):
        self.write_rag(self.rag_cases() + self.rag_cases()[:1]); self.reject()

    def test_nonpassing(self):
        for state in ('failed', 'error', 'skipped'):
            with self.subTest(state=state):
                cases = self.rag_cases(); cases[0] = (*cases[0][:2], state)
                self.write_rag(cases); self.refresh_payloads(); self.reject()

    def test_wrong_task(self):
        self.rag_xml.unlink(); self.write_report('test', 'rag', evidence.RAG_SUPPLIED_CLASS, self.rag_cases())
        self.refresh_payloads(); self.reject()

    def test_missing_source_never_not_applicable(self):
        self.rag_source.unlink(); self.rag_xml.unlink(); self.refresh_manifest(); self.refresh_payloads(); self.reject()

    def test_missing_tracked_source(self):
        self.rag_source.unlink(); self.reject()

    def test_untracked_source(self):
        self.revision['files'] = [f for f in self.revision['files'] if f['path'] != evidence.RAG_SUPPLIED_SOURCE]; self.reject()

    def test_source_hash_mismatch(self):
        self.rag_source.write_text(self.rag_source.read_text() + '\n'); self.reject()

    def test_source_extra_method(self):
        self.rag_source.write_text(self.rag_source.read_text().replace('\n}', '\n@Test void extra() {}\n}'))
        self.refresh_manifest(); self.reject()

    def test_source_wrong_path(self):
        self.rag_source.rename(self.rag_source.with_name('Renamed.java')); self.refresh_manifest(); self.reject()

    def test_source_parameterized_not_plain(self):
        s = self.rag_source.read_text().replace('import org.junit.jupiter.api.Test;',
            'import org.junit.jupiter.api.Test; import org.junit.jupiter.params.ParameterizedTest;')
        self.rag_source.write_text(s.replace('@Test @Timeout(60) void ' + evidence.RAG_SUPPLIED_METHODS[0] + '()',
            '@ParameterizedTest void ' + evidence.RAG_SUPPLIED_METHODS[0] + '(String value)'))
        self.refresh_manifest(); self.reject()

    def test_source_wildcard_rejected(self):
        self.rag_source.write_text(self.rag_source.read_text().replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.*;'))
        self.refresh_manifest(); self.reject()

    def test_class_alias(self):
        self.write_rag([('RagSuppliedDocumentStimulusReplayIT', n, s) for _, n, s in self.rag_cases()])
        self.refresh_payloads(); self.reject()

    def test_display_and_parameter_aliases(self):
        for name in (CANARY, '[1] value', evidence.RAG_SUPPLIED_METHODS[0] + '(String)[1]'):
            with self.subTest(name=name):
                cases = self.rag_cases(); cases[0] = (evidence.RAG_SUPPLIED_CLASS, name, 'passed')
                self.write_rag(cases); self.refresh_payloads(); self.reject()

    def test_target_suite_foreign_case(self):
        self.write_rag(self.rag_cases() + [(self.other_class, 'works()', 'passed')]); self.refresh_payloads(); self.reject()

    def test_foreign_suite_target_case(self):
        self.write_rag(suite='foreign.Suite'); self.refresh_payloads(); self.reject()

    def test_duplicate_report(self):
        (self.rag_xml.parent / 'TEST-copy.xml').write_bytes(self.rag_xml.read_bytes()); self.reject()

    def test_duplicate_suite_different_bytes(self):
        (self.rag_xml.parent / 'TEST-copy.xml').write_bytes(self.rag_xml.read_bytes() + b'\n'); self.reject()

    def test_malformed_xml_privacy(self):
        self.rag_xml.write_bytes(('<testsuite ' + CANARY).encode())
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))

    def test_xml_entity(self):
        self.rag_xml.write_bytes(b'<!DOCTYPE x [<!ENTITY leak "PRIVATE">]><testsuite/>'); self.reject()

    def test_raw_inventory_mismatch(self):
        self.write_rag(self.rag_cases()[:-1]); self.reject()

    def test_inventory_boolean_count(self):
        row = next(r for r in self.inventory['tasks']['integrationTest']['rows'] if r['class'] == evidence.RAG_SUPPLIED_CLASS)
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

    def test_rag_failure_after_bind_no_partial_payment_pass(self):
        self.execute(); self.write_rag(self.rag_cases()[:-1]); self.refresh_payloads(); self.reject('verify')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_different_raw_sets_between_projections_reject_before_write_or_output(self):
        original = evidence.rag_supplied_document_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'rag_supplied_document_evidence', side_effect=changed):
            self.reject()
        self.execute()
        with patch.object(evidence, 'rag_supplied_document_evidence', side_effect=changed):
            self.reject('verify')

    def test_flagged_preserves_legacy_payment_not_applicable(self):
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        self.assertEqual((True, ''), self.execute())
        _, text = self.execute('verify')
        payment, rag = [json.loads(line) for line in text.splitlines()]
        self.assertEqual('NOT_APPLICABLE', payment['status'])
        self.assertEqual('SOURCE_ABSENT', payment['reason'])
        self.assertEqual('PASS', rag['status'])

    def test_payment_failure_still_rejected(self):
        self.write_target(self.cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_unflagged_preserves_one_payment_projection(self):
        self.assertEqual((True, ''), self.execute(flagged=False))
        _, text = self.execute('verify', flagged=False)
        self.assertEqual('FUSE-REQUIRED-METHODS-1', json.loads(text)['schemaVersion'])
        self.assertNotIn('FUSE-RAG-SUPPLIED-DOCUMENT-METHODS-1', text)

    def test_unflagged_absent_rag_preserves_old_caller(self):
        self.rag_source.unlink(); self.rag_xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
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
        self.rag_xml.unlink(); self.rag_xml.symlink_to(self.base / 'missing'); self.reject()

    def test_raw_parent_symlink(self):
        parent = self.rag_xml.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_source_leaf_symlink(self):
        self.rag_source.unlink(); self.rag_source.symlink_to(self.base / 'missing'); self.reject()

    def test_source_parent_symlink(self):
        parent = self.rag_source.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_byte_limit(self):
        self.rag_xml.write_bytes(b'x'*(inventory.MAX_FILE_BYTES + 1)); self.reject()

    def test_depth_limit(self):
        self.rag_xml.write_bytes(b'<testsuite>' + b'<x>'*20 + b'</x>'*20 + b'</testsuite>'); self.reject()


    def add_rate_contract(self):
        source = self.root / evidence.RATE_SOURCE
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class PublicReadAnonymousRateBoundaryIT {' + ''.join(
                '@Test void ' + name + '() {}' for name in evidence.RATE_METHODS) + '}')
        self.write_report('integrationTest', 'rate', evidence.RATE_CLASS,
                          [(evidence.RATE_CLASS, name + '()', 'passed') for name in evidence.RATE_METHODS])
        self.refresh_manifest(); self.refresh_payloads()

    def add_deadline_contract(self):
        source = self.root / evidence.DEADLINE_SOURCE
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class DefaultKycHttpTimeoutLifecycleIT { @Test void ' + evidence.DEADLINE_METHODS[0] + '() {} }')
        self.write_report('integrationTest', 'deadline', evidence.DEADLINE_CLASS,
            [(evidence.DEADLINE_CLASS, evidence.DEADLINE_METHODS[0] + '()', 'passed')])
        self.refresh_manifest(); self.refresh_payloads()

    def execute_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_default_kyc_deadline=True, require_rag_supplied_document=True)
        return result, out.getvalue()

    def reject_all(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_default_kyc_deadline=True, require_rag_supplied_document=True)
        self.assertEqual('', out.getvalue(), 'No partial Java PASS may escape')
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def test_all_four_contracts_share_exact_raw_sets(self):
        self.add_rate_contract(); self.add_deadline_contract()
        self.assertEqual((True, ''), self.execute_all())
        result, text = self.execute_all('verify'); self.assertTrue(result)
        payment, rate, deadline, rag = [json.loads(line) for line in text.splitlines()]
        self.assertEqual([7, 2, 1, 5], [len(p['methods']) for p in (payment, rate, deadline, rag)])
        self.assertEqual(payment['rawReportSets'], rate['rawReportSets'])
        self.assertEqual(rate['rawReportSets'], deadline['rawReportSets'])
        self.assertEqual(deadline['rawReportSets'], rag['rawReportSets'])
        self.assertEqual('FUSE-RAG-SUPPLIED-DOCUMENT-METHODS-1', rag['schemaVersion'])
        self.assertNotIn(CANARY, text)

    def test_all_four_rag_failure_never_emits_prior_passes(self):
        self.add_rate_contract(); self.add_deadline_contract(); self.execute_all()
        self.write_rag([]); self.refresh_payloads(); self.reject_all('verify')

    def test_all_four_rate_failure_never_writes(self):
        self.add_rate_contract(); self.add_deadline_contract()
        (self.root / evidence.RATE_SOURCE).unlink()
        self.reject_all()

    def test_absent_payment_still_compares_rate_and_rag_raw_sets(self):
        self.add_rate_contract(); self.add_deadline_contract()
        self.target.unlink(); self.xml.unlink(); self.refresh_manifest(); self.refresh_payloads()
        original = evidence.rag_supplied_document_evidence
        def changed(*args):
            result = original(*args)
            result['rawReportSets']['integrationTest']['sha256'] = '0'*64
            return result
        with patch.object(evidence, 'rag_supplied_document_evidence', side_effect=changed):
            self.reject_all()
        self.execute_all()
        with patch.object(evidence, 'rag_supplied_document_evidence', side_effect=changed):
            self.reject_all('verify')

    def test_all_four_unrelated_unknown_remains_incomplete(self):
        self.add_rate_contract(); self.add_deadline_contract()
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads(); self.assertEqual((False, ''), self.execute_all())
        complete, text = self.execute_all('verify'); self.assertFalse(complete)
        self.assertEqual(['PASS'] * 4, [json.loads(line)['status'] for line in text.splitlines()])
        self.assertNotIn(CANARY, text)

    def test_each_four_projection_raw_mismatch_rejects_before_write_and_markers(self):
        self.add_rate_contract(); self.add_deadline_contract()
        names = ('required_method_evidence', 'public_read_rate_evidence',
                 'default_kyc_deadline_evidence', 'rag_supplied_document_evidence')
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

    def test_all_four_deadline_failure_never_writes(self):
        self.add_rate_contract(); self.add_deadline_contract()
        (self.root / evidence.DEADLINE_SOURCE).unlink()
        self.reject_all()

    def test_untrusted_composed_annotation_rejected(self):
        self.rag_source.write_text(self.rag_source.read_text().replace(
            'import org.junit.jupiter.api.Timeout;', 'import untrusted.Timeout;'))
        self.refresh_manifest(); self.reject()

    def test_source_shadowing_annotation_rejected(self):
        self.rag_source.write_text(self.rag_source.read_text() + '\n@interface Timeout {}\n')
        self.refresh_manifest(); self.reject()

    def test_xml_aggregate_counters_must_match(self):
        self.rag_xml.write_bytes(self.rag_xml.read_bytes().replace(b'tests="5"', b'tests="6"'))
        self.reject()

    def test_missing_raw_report_rejects(self):
        self.rag_xml.unlink(); self.reject()

    def test_checked_in_rag_source_maps_exact_method(self):
        # Source parsing only: this does not compile Java or claim a JUnit execution.
        root = Path(__file__).resolve().parents[1]
        manifest = inventory.source_manifest(root / 'backend/src/test/java')
        self.assertEqual(dict.fromkeys(evidence.RAG_SUPPLIED_METHODS), manifest[evidence.RAG_SUPPLIED_CLASS])


    def test_fixture_missing_tracked_or_untracked(self):
        self.rag_fixture.unlink(); self.reject()
        self.refresh_manifest(); self.reject()

    def test_fixture_untracked(self):
        self.revision['files'] = [row for row in self.revision['files'] if row['path'] != evidence.RAG_SUPPLIED_FIXTURE]
        self.reject()

    def test_fixture_digest_mismatch(self):
        self.rag_fixture.write_text(self.rag_fixture.read_text() + '\n'); self.reject()

    def test_duplicate_fixture_manifest_record(self):
        self.revision['files'].extend(row.copy() for row in list(self.revision['files']) if row['path'] == evidence.RAG_SUPPLIED_FIXTURE)
        self.reject()

    def test_fixture_invalid_json_and_identity(self):
        for text in ('[]', '{}', '{"fixtureSetId":"other"}',
                     '{"fixtureSetId":"rag-supplied-document-stimulus-v1","fixtureSetId":"other"}',
                     '{"fixtureSetId":"rag-supplied-document-stimulus-v1","value":NaN}', CANARY):
            with self.subTest(text=text):
                self.rag_fixture.write_text(text); self.refresh_manifest(); self.reject()

    def test_fixture_leaf_symlink(self):
        copy = self.base / 'synthetic.json'; copy.write_bytes(self.rag_fixture.read_bytes())
        self.rag_fixture.unlink(); self.rag_fixture.symlink_to(copy); self.reject()

    def test_fixture_parent_symlink(self):
        parent = self.rag_fixture.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_fixture_oversize(self):
        self.rag_fixture.write_bytes(b' ' * (evidence.LIMIT + 1)); self.refresh_manifest(); self.reject()

    def test_changed_fixture_after_binding_rejected_without_partial_pass(self):
        self.execute()
        self.rag_fixture.write_text(json.dumps({'fixtureSetId':'rag-supplied-document-stimulus-v1', 'changed':True}))
        self.reject('verify')
        self.refresh_manifest(); self.reject('verify')

    def test_run_head_tree_and_attempt_binding_rejected_without_partial_pass(self):
        self.execute(); path = self.artifacts / evidence.EVIDENCE; original = path.read_text()
        for area, key, replacement in (('run','id','124'), ('run','attempt','2'),
                                       ('revision','head','c'*40), ('revision','tree','c'*40)):
            with self.subTest(area=area, key=key):
                value = json.loads(original); value[area][key] = replacement
                path.write_text(json.dumps(value)); self.reject('verify')

    def test_all_five_projections_share_run_source_and_raw_report_sets(self):
        self.add_rate_contract(); self.add_deadline_contract()
        source = self.root / evidence.API_PATH_GUARD_SOURCE
        source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
            'class PublicApiCanonicalPathGuardIT {' + ''.join(
                '@Test void ' + name + '() {}' for name in evidence.API_PATH_GUARD_METHODS) + '}')
        self.write_report('integrationTest', 'api', evidence.API_PATH_GUARD_CLASS,
                          [(evidence.API_PATH_GUARD_CLASS, name + '()', 'passed') for name in evidence.API_PATH_GUARD_METHODS])
        self.refresh_manifest(); self.refresh_payloads()
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(evidence.execute('bind', self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_default_kyc_deadline=True, require_api_path_guard=True, require_rag_supplied_document=True))
            self.assertEqual('', out.getvalue())
            self.assertTrue(evidence.execute('verify', self.root, self.artifacts, 'a'*40, '123', '1', require_public_read_rate=True, require_default_kyc_deadline=True, require_api_path_guard=True, require_rag_supplied_document=True))
        projections = [json.loads(row) for row in out.getvalue().splitlines()]
        self.assertEqual([7, 2, 1, 5, 5], [len(row['methods']) for row in projections])
        for row in projections:
            self.assertEqual('a'*40, row['head']); self.assertEqual('b'*40, row['tree'])
            self.assertEqual({'id':'123','attempt':'1'}, row['run'])
            self.assertEqual(projections[0]['rawReportSets'], row['rawReportSets'])
        self.assertNotIn(CANARY, out.getvalue())

    def test_ci_requires_new_projection_in_both_bind_and_verify(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / '.github/workflows/ci.yml').read_text()
        lines = [line for line in workflow.splitlines() if 'scripts/ci-test-evidence.py' in line]
        self.assertEqual(2, len(lines))
        for line in lines:
            for flag in ('--require-public-read-rate', '--require-default-kyc-deadline',
                         '--require-api-path-guard', '--require-rag-supplied-document'):
                self.assertIn(flag, line)
        self.assertIn('python -B scripts/ci-rag-supplied-document-evidence-test.py', workflow)
        self.assertIn('python -m pytest -q agent/tests evaluation/tests', workflow)


class AllSevenEvidenceGroupsTests(unittest.TestCase):
    """All fixed groups share one raw report set; synthetic parser data is not runtime evidence."""
    refresh_payloads = fixture.RequiredMethodsTests.refresh_payloads
    save = fixture.RequiredMethodsTests.save
    write_report = fixture.RequiredMethodsTests.write_report
    cases = fixture.RequiredMethodsTests.cases
    write_target = fixture.RequiredMethodsTests.write_target
    FLAGS = (
        '--require-public-read-rate', '--require-default-kyc-deadline',
        '--require-api-path-guard', '--require-rag-nonexistent-evidence',
        '--require-recovery-stored-success', '--require-rag-supplied-document',
    )
    SCHEMAS = (
        'FUSE-REQUIRED-METHODS-1', 'FUSE-PUBLIC-READ-RATE-METHODS-1',
        'FUSE-DEFAULT-KYC-DEADLINE-METHODS-1', 'FUSE-API-PATH-GUARD-METHODS-1',
        'FUSE-RAG-NONEXISTENT-EVIDENCE-METHODS-1', 'FUSE-RECOVERY-STORED-SUCCESS-METHODS-1',
        'FUSE-RAG-SUPPLIED-DOCUMENT-METHODS-1',
    )

    def refresh_manifest(self):
        fixture.RequiredMethodsTests.refresh_manifest(self)
        for fixture_path in (evidence.RAG_FIXTURE, evidence.RAG_SUPPLIED_FIXTURE):
            path = self.root / fixture_path
            if path.is_file():
                self.revision['files'].append({'path': fixture_path, **evidence.digest(path.read_bytes())})

    def setUp(self):
        fixture.RequiredMethodsTests.setUp(self)
        self.groups = (
            (evidence.RATE_CLASS, evidence.RATE_SOURCE, evidence.RATE_METHODS),
            (evidence.DEADLINE_CLASS, evidence.DEADLINE_SOURCE, evidence.DEADLINE_METHODS),
            (evidence.API_PATH_GUARD_CLASS, evidence.API_PATH_GUARD_SOURCE, evidence.API_PATH_GUARD_METHODS),
            (evidence.RAG_CLASS, evidence.RAG_SOURCE, evidence.RAG_METHODS),
            (evidence.RECOVERY_STORED_SUCCESS_CLASS, evidence.RECOVERY_STORED_SUCCESS_SOURCE,
             evidence.RECOVERY_STORED_SUCCESS_METHODS),
            (evidence.RAG_SUPPLIED_CLASS, evidence.RAG_SUPPLIED_SOURCE, evidence.RAG_SUPPLIED_METHODS),
        )
        self.group_xml = {}
        for cls, source, methods in self.groups:
            path = self.root / source; path.parent.mkdir(parents=True, exist_ok=True)
            package, name = cls.rsplit('.', 1)
            path.write_text('package ' + package + '; import org.junit.jupiter.api.Test;\n'
                'import org.junit.jupiter.api.Timeout; class ' + name + ' {\n' + '\n'.join(
                    '@Test @Timeout(60) void ' + method + '() {}' for method in methods) + '\n}\n')
            self.group_xml[cls] = self.write_report('integrationTest', name, cls,
                [(cls, method + '()', 'passed') for method in methods])
        self.rag_fixture = self.root / evidence.RAG_FIXTURE
        self.rag_fixture.parent.mkdir(parents=True, exist_ok=True)
        self.rag_fixture.write_text(json.dumps({'fixtureSetId': 'rag-nonexistent-evidence-v1',
                                               'syntheticFixtureText': CANARY}))
        self.supplied_fixture = self.root / evidence.RAG_SUPPLIED_FIXTURE
        self.supplied_fixture.write_text(json.dumps({'fixtureSetId':'rag-supplied-document-stimulus-v1', 'syntheticFixtureText': CANARY}))
        self.refresh_manifest(); self.refresh_payloads()

    def execute(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1',
                require_public_read_rate=True, require_default_kyc_deadline=True,
                require_api_path_guard=True, require_rag_nonexistent_evidence=True,
                require_recovery_stored_success=True, require_rag_supplied_document=True)
        return result, out.getvalue()

    def main(self, command):
        args = [str(fixture.SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
                '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1', *self.FLAGS]
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv', args), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_all_seven_groups_bind_silently_and_verify_identical_raw_sets(self):
        self.assertEqual((True, ''), self.execute())
        complete, text = self.execute('verify'); self.assertTrue(complete)
        projections = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(self.SCHEMAS, tuple(item['schemaVersion'] for item in projections))
        self.assertEqual([7, 2, 1, 5, 2, 4, 5], [len(item['methods']) for item in projections])
        for item in projections:
            self.assertEqual('PASS', item['status'])
            self.assertEqual('a'*40, item['head']); self.assertEqual('b'*40, item['tree'])
            self.assertEqual({'id': '123', 'attempt': '1'}, item['run'])
            self.assertEqual(projections[0]['rawReportSets'], item['rawReportSets'])
        for item, (cls, source, methods) in zip(projections[1:], self.groups):
            self.assertEqual(cls, item['class'])
            self.assertEqual(evidence.digest((self.root/source).read_bytes())['sha256'], item['sourceSha256'])
            self.assertEqual([{'method': method, 'status': 'passed', 'count': 1} for method in methods], item['methods'])
        rag = projections[4]
        self.assertEqual(evidence.RAG_FIXTURE, rag['fixture']['path'])
        self.assertEqual(evidence.digest(self.rag_fixture.read_bytes())['sha256'], rag['fixture']['sha256'])
        canonical = json.dumps(json.loads(self.rag_fixture.read_bytes()), ensure_ascii=False,
                               sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(evidence.hashlib.sha256(canonical).hexdigest(), rag['fixture']['canonicalSha256'])
        supplied = projections[-1]
        self.assertEqual(evidence.RAG_SUPPLIED_FIXTURE, supplied['fixture']['path'])
        self.assertEqual(evidence.digest(self.supplied_fixture.read_bytes())['sha256'], supplied['fixture']['sha256'])
        canonical = json.dumps(json.loads(self.supplied_fixture.read_bytes()), ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(evidence.hashlib.sha256(canonical).hexdigest(), supplied['fixture']['canonicalSha256'])
        self.assertNotIn(CANARY, text); self.assertNotIn('TEST-', text)

    def test_all_cli_flags_and_workflow_bind_verify_preserve_every_group(self):
        self.assertEqual((0, 'EVIDENCE_COMPLETE\n', ''), self.main('bind'))
        status, text, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err)
        self.assertEqual(self.SCHEMAS, tuple(json.loads(line)['schemaVersion'] for line in text.splitlines()[:-1]))
        self.assertEqual('EVIDENCE_COMPLETE', text.splitlines()[-1])
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        commands = [line for line in workflow.splitlines() if 'scripts/ci-test-evidence.py ' in line]
        self.assertEqual(2, len(commands))
        self.assertIn(' bind ', commands[0]); self.assertIn(' verify ', commands[1])
        for command in commands:
            for flag in self.FLAGS: self.assertEqual(1, command.split().count(flag))
        self.assertIn('run: python -B scripts/ci-recovery-stored-success-evidence-test.py', workflow)
        self.assertIn('run: python -B scripts/ci-rag-nonexistent-evidence-test.py', workflow)

    def test_each_cross_group_raw_set_mismatch_rejects_without_partial_pass(self):
        names = ('required_method_evidence', 'public_read_rate_evidence', 'default_kyc_deadline_evidence',
                 'api_path_guard_evidence', 'rag_nonexistent_evidence', 'recovery_stored_success_evidence', 'rag_supplied_document_evidence')
        binding = self.artifacts / evidence.EVIDENCE
        for name in names:
            with self.subTest(group=name):
                if binding.exists(): binding.unlink()
                original = getattr(evidence, name)
                def changed(*args):
                    result = original(*args)
                    result['rawReportSets']['integrationTest']['sha256'] = '0'*64
                    return result
                with patch.object(evidence, name, side_effect=changed):
                    self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))
                self.assertFalse(binding.exists(), 'A partial binding must not be written')
                self.assertEqual((True, ''), self.execute())
                with patch.object(evidence, name, side_effect=changed):
                    self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_late_rag_or_recovery_failure_never_emits_earlier_group_passes(self):
        for cls in (evidence.RAG_CLASS, evidence.RECOVERY_STORED_SUCCESS_CLASS):
            with self.subTest(group=cls):
                path = self.group_xml[cls]; original = path.read_bytes()
                binding = self.artifacts / evidence.EVIDENCE
                if binding.exists(): binding.unlink()
                self.assertEqual((True, ''), self.execute())
                path.unlink()
                self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))
                path.write_bytes(original)

    def test_fixture_mutation_with_all_groups_rejects_prior_binding(self):
        self.assertEqual((True, ''), self.execute())
        self.rag_fixture.write_text(self.rag_fixture.read_text() + '\n')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_all_seven_keep_global_unknown_identity_incomplete(self):
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads()
        self.assertEqual((False, ''), self.execute())
        complete, text = self.execute('verify'); self.assertFalse(complete)
        self.assertEqual(['PASS'] * 7, [json.loads(line)['status'] for line in text.splitlines()])
        self.assertNotIn(CANARY, text)

    def test_new_final_group_failure_emits_no_earlier_pass(self):
        self.execute()
        self.group_xml[evidence.RAG_SUPPLIED_CLASS].unlink()
        with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
            self.execute('verify')
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))

    def test_new_fixture_change_after_all_group_binding_rejects(self):
        self.execute()
        self.supplied_fixture.write_text(self.supplied_fixture.read_text() + '\n')
        self.refresh_manifest()
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('verify'))


if __name__ == '__main__':
    unittest.main()
