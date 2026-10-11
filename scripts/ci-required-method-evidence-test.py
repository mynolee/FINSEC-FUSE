#!/usr/bin/env python3
"""Pure-Python fixed-method regressions; no services, Java, Git or network."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SCRIPT = Path(__file__).with_name('ci-test-evidence.py')
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
evidence = load('evidence', SCRIPT)
inventory = load('inventory', SCRIPT.with_name('ci-test-inventory.py'))
CANARY = 'PRIVATE_XML_CANARY_628459'


class RequiredMethodsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.artifacts = self.base / 'repo', self.base / 'artifacts'
        self.root.mkdir(); self.artifacts.mkdir()
        self.source_root = self.root / 'backend/src/test/java'
        self.target = self.root / evidence.REQUIRED_SOURCE; self.target.parent.mkdir(parents=True)
        self.target.write_text('package com.finsec.fuse.payment; import org.junit.jupiter.api.Test;\n'
            'class PaymentAgentAvailabilityIT extends PaymentFixture {\n' + '\n'.join(
                '@Test void ' + name + '() {}' for name in evidence.REQUIRED_METHODS) + '\n}\n')
        self.fixture = self.target.with_name('PaymentFixture.java')
        self.fixture.write_text('package com.finsec.fuse.payment; class PaymentFixture {}')
        self.other = self.target.with_name('OtherTest.java')
        self.other.write_text('package com.finsec.fuse.payment; import org.junit.jupiter.api.Test; '
                              'class OtherTest { @Test void works() {} }')
        self.other_class = 'com.finsec.fuse.payment.OtherTest'
        self.reports = self.root / 'backend/build/test-results'
        self.write_report('test', 'other', self.other_class, [(self.other_class, 'works()', 'passed')])
        self.write_target(); self.refresh_manifest(); self.refresh_payloads()

    def refresh_manifest(self):
        self.revision = {'head': 'a'*40, 'tree': 'b'*40, 'files': [
            {'path': f.relative_to(self.root).as_posix(), **evidence.digest(f.read_bytes())}
            for f in sorted(self.source_root.rglob('*.java'))]}

    def cases(self):
        return [(evidence.REQUIRED_CLASS, name + '()', 'passed') for name in evidence.REQUIRED_METHODS]

    def write_report(self, task, filename, suite, cases):
        directory = self.reports / task; directory.mkdir(parents=True, exist_ok=True)
        counts = {state: sum(row[2] == state for row in cases) for state in evidence.STATES}
        root = ET.Element('testsuite', name=suite, tests=str(len(cases)), failures=str(counts['failed']),
                          errors=str(counts['error']), skipped=str(counts['skipped']))
        for cls, name, state in cases:
            case = ET.SubElement(root, 'testcase', classname=cls, name=name)
            if state != 'passed':
                ET.SubElement(case, {'failed': 'failure', 'error': 'error', 'skipped': 'skipped'}[state], message=CANARY)
        path = directory / ('TEST-' + filename + '.xml'); path.write_bytes(ET.tostring(root))
        return path

    def write_target(self, cases=None, suite=None):
        self.xml = self.write_report('integrationTest', 'target', suite or evidence.REQUIRED_CLASS,
                                     self.cases() if cases is None else cases)

    def refresh_payloads(self):
        self.inventory = inventory.summarize(self.reports, self.source_root)
        self.summary = {'schemaVersion': 'FUSE-TEST-COUNTS-1', 'scope': evidence.SCOPE, 'tasks': {}}
        for name, task in self.inventory['tasks'].items():
            c = task['counts']
            self.summary['tasks'][name] = {'status': 'FAIL' if c['failed'] + c['error'] else 'PASS',
                'tests': sum(c.values()), 'failures': c['failed'], 'errors': c['error'], 'skipped': c['skipped'],
                'failureIds': [], 'unknownFailureIds': c['failed'] + c['error'], 'omittedFailureIds': 0}
        self.save()

    def save(self):
        (self.artifacts / evidence.PAYLOADS[0]).write_text(json.dumps(self.inventory))
        (self.artifacts / evidence.PAYLOADS[1]).write_text(json.dumps(self.summary))

    def execute(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            result = evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1')
        return result, out.getvalue()

    def reject(self, command='bind'):
        with patch.object(evidence, 'checkout', return_value=self.revision), contextlib.redirect_stdout(io.StringIO()) as out:
            with self.assertRaises((ValueError, OSError, TypeError, KeyError)):
                evidence.execute(command, self.root, self.artifacts, 'a'*40, '123', '1')
        self.assertEqual('', out.getvalue())
        if command == 'bind': self.assertFalse((self.artifacts / evidence.EVIDENCE).exists())

    def helper(self):
        return evidence.required_method_evidence(self.root, self.inventory, self.revision, '123', '1')

    def main(self, command):
        with patch.object(evidence, 'checkout', return_value=self.revision), patch('sys.argv',
            [str(SCRIPT), command, '--repository', str(self.root), '--artifacts', str(self.artifacts),
             '--head', 'a'*40, '--run-id', '123', '--run-attempt', '1']), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            status = evidence.main()
        return status, out.getvalue(), err.getvalue()

    def test_bound_seven_passes_only_emitted_on_verify(self):
        self.assertEqual((True, ''), self.execute())
        result, text = self.execute('verify'); self.assertTrue(result); projection = json.loads(text)
        self.assertEqual('PASS', projection['status']); self.assertEqual('a'*40, projection['head'])
        self.assertEqual('b'*40, projection['tree']); self.assertEqual({'id': '123', 'attempt': '1'}, projection['run'])
        self.assertEqual(evidence.digest(self.target.read_bytes())['sha256'], projection['sourceSha256'])
        self.assertEqual([{'method': name, 'status': 'passed', 'count': 1} for name in evidence.REQUIRED_METHODS], projection['methods'])
        self.assertEqual({'test', 'integrationTest'}, set(projection['rawReportSets']))
        self.assertNotIn('TEST-', text); self.assertNotIn(CANARY, text)
        self.assertEqual({'schemaVersion', 'revision', 'run', 'artifacts', 'complete'},
                         set(json.loads((self.artifacts / evidence.EVIDENCE).read_text())))

    def test_unrelated_unknown_preserves_global_incomplete(self):
        self.write_report('integrationTest', 'unknown', 'other.Unknown', [('other.Unknown', CANARY, 'passed')])
        self.refresh_payloads(); self.assertEqual((False, ''), self.execute())
        status, out, err = self.main('verify')
        self.assertEqual(0, status); self.assertEqual('', err)
        self.assertTrue(out.endswith('EVIDENCE_INCOMPLETE\n')); self.assertNotIn(CANARY, out)
        self.assertEqual('PASS', json.loads(out.splitlines()[0])['status'])

    def test_eighth_unmapped_target_with_seven_mapped_rejects(self):
        self.write_target(self.cases() + [(evidence.REQUIRED_CLASS, CANARY, 'passed')]); self.refresh_payloads()
        self.assertEqual(7, len(self.inventory['tasks']['integrationTest']['rows'])); self.reject()

    def test_missing_case(self):
        self.write_target(self.cases()[:-1]); self.refresh_payloads(); self.reject()

    def test_duplicate_case(self):
        self.write_target(self.cases() + self.cases()[:1]); self.reject()

    def test_nonpassing_cases(self):
        for state in ('failed', 'error', 'skipped'):
            with self.subTest(state=state):
                cases = self.cases(); cases[0] = (*cases[0][:2], state)
                self.write_target(cases); self.refresh_payloads(); self.reject()

    def test_unit_leakage(self):
        self.write_report('test', 'leak', evidence.REQUIRED_CLASS, self.cases()); self.refresh_payloads(); self.reject()

    def test_target_suite_foreign_case(self):
        self.write_target(self.cases() + [(self.other_class, 'works()', 'passed')]); self.refresh_payloads(); self.reject()

    def test_target_case_foreign_suite(self):
        self.write_target(suite=self.other_class); self.refresh_payloads(); self.reject()

    def test_custom_display_or_parameterized_names(self):
        for name in ('[1] value', evidence.REQUIRED_METHODS[0] + '(String)[1]', CANARY):
            with self.subTest(name=name):
                cases = self.cases(); cases[0] = (evidence.REQUIRED_CLASS, name, 'passed')
                self.write_target(cases); self.refresh_payloads(); self.reject()

    def test_noncanonical_class(self):
        self.write_target([('PaymentAgentAvailabilityIT', name, state) for _, name, state in self.cases()])
        self.refresh_payloads(); self.reject()

    def test_missing_reports(self):
        self.xml.unlink(); self.reject()

    def test_raw_inventory_mismatch(self):
        self.write_report('integrationTest', 'other', self.other_class, [(self.other_class, 'works()', 'passed')]); self.reject()

    def test_duplicate_suite(self):
        (self.xml.parent / 'TEST-copy.xml').write_bytes(self.xml.read_bytes()); self.reject()

    def test_xml_entity_rejects(self):
        self.xml.write_bytes(b'<!DOCTYPE x [<!ENTITY leak "PRIVATE">]><testsuite/>'); self.reject()

    def test_malformed_xml_cli_fixed_output(self):
        self.xml.write_bytes(('<testsuite ' + CANARY).encode())
        self.assertEqual((1, 'EVIDENCE_REJECTED\n', ''), self.main('bind'))

    def test_digest_mismatch(self):
        self.target.write_text(self.target.read_text() + '\n'); self.reject()

    def test_missing_tracked_source(self):
        self.target.unlink(); self.reject()

    def test_untracked_target(self):
        self.revision['files'] = [item for item in self.revision['files'] if item['path'] != evidence.REQUIRED_SOURCE]
        self.reject()

    def test_malformed_inventory(self):
        self.inventory['tasks']['integrationTest']['rows'][0]['count'] = True; self.save(); self.reject()

    def test_source_extra_method(self):
        self.target.write_text(self.target.read_text().replace('\n}', '\n@Test void extra() {}\n}'))
        self.refresh_manifest(); self.reject()

    def test_source_parser_failure_not_absence(self):
        self.target.write_text(self.target.read_text().replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.*;'))
        self.refresh_manifest(); self.reject()

    def test_parameterized_signature_not_plain_test(self):
        source = self.target.read_text().replace('import org.junit.jupiter.api.Test;',
            'import org.junit.jupiter.api.Test; import org.junit.jupiter.params.ParameterizedTest;')
        source = source.replace('@Test void ' + evidence.REQUIRED_METHODS[0] + '()',
            '@ParameterizedTest void ' + evidence.REQUIRED_METHODS[0] + '(String value)')
        self.target.write_text(source); self.refresh_manifest(); self.reject()

    def test_unsupported_ancestry(self):
        self.fixture.write_text('package com.finsec.fuse.payment; class PaymentFixture extends Unknown {}')
        self.refresh_manifest(); self.reject()

    def test_legacy_absence_is_not_applicable(self):
        self.target.unlink(); self.refresh_manifest()
        self.write_target([(self.other_class, 'works()', 'passed')], self.other_class); self.refresh_payloads()
        self.assertEqual((True, ''), self.execute())
        _, text = self.execute('verify'); projection = json.loads(text)
        self.assertEqual('NOT_APPLICABLE', projection['status']); self.assertEqual('SOURCE_ABSENT', projection['reason'])
        self.assertNotIn('methods', projection)

    def test_partial_tree_absence(self):
        root = self.base / 'partial'; root.mkdir()
        source = {'head': 'a'*40, 'tree': 'b'*40, 'files': []}
        tasks = {'tasks': {name: {'rows': []} for name in evidence.TASKS}}
        self.assertEqual('NOT_APPLICABLE', evidence.required_method_evidence(root, tasks, source, '123', '1')['status'])

    def test_absence_with_observed_target_rejects(self):
        self.target.unlink(); self.refresh_manifest()
        with self.assertRaises(ValueError): self.helper()

    def test_symlinks_cannot_prove_absence(self):
        self.target.unlink(); self.refresh_manifest(); self.target.symlink_to(self.base / 'missing')
        with self.assertRaises(OSError): self.helper()
        self.target.unlink(); parent = self.target.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(self.base / 'missing', target_is_directory=True)
        with self.assertRaises(OSError): self.helper()

    def test_raw_leaf_symlink(self):
        self.xml.unlink(); self.xml.symlink_to(self.base / 'missing'); self.reject()

    def test_raw_parent_symlink(self):
        parent = self.xml.parent; parent.rename(parent.with_name('saved'))
        parent.symlink_to(parent.with_name('saved'), target_is_directory=True); self.reject()

    def test_byte_limit(self):
        self.xml.write_bytes(b'x' * (inventory.MAX_FILE_BYTES + 1)); self.reject()

    def test_depth_limit(self):
        self.xml.write_bytes(b'<testsuite>' + b'<x>'*20 + b'</x>'*20 + b'</testsuite>'); self.reject()

    def test_binding_tamper_and_bool_int_equality_emit_nothing(self):
        self.execute(); path = self.artifacts / evidence.EVIDENCE; original = path.read_text()
        for mutation in ('run', 'bool'):
            with self.subTest(mutation=mutation):
                data = json.loads(original)
                if mutation == 'run': data['run']['attempt'] = '2'
                else: data['complete'] = 1
                path.write_text(json.dumps(data)); self.reject('verify')


if __name__ == '__main__':
    unittest.main()
