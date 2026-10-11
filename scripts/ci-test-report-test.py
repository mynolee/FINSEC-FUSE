#!/usr/bin/env python3
"""Offline mutation checks for bounded backend failure identifiers."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SPEC = importlib.util.spec_from_file_location('report', Path(__file__).with_name('ci-test-report.py'))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)
INVENTORY = report.inventory_module()
EVIDENCE_SPEC = importlib.util.spec_from_file_location('evidence', Path(__file__).with_name('ci-test-evidence.py'))
evidence = importlib.util.module_from_spec(EVIDENCE_SPEC)
EVIDENCE_SPEC.loader.exec_module(evidence)
CLASS = 'com.finsec.fuse.integration.WorkflowHappyPathIT'
METHOD = 't01NormalPaymentAndStartApprovalReplay'
SECRET = 'CANARY_PRIVATE_REQUEST_TOKEN_90210'


class SafeFailureTests(unittest.TestCase):
    def setUp(self):
        # Keep direct parser checks and CLI subprocesses on the same synthetic
        # source tree, independent of whichever feature sources are checked out.
        directory = tempfile.TemporaryDirectory(prefix='fuse-report-sources-')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        self.repository = root
        self.source_root = root / 'backend/src/test/java'
        folder = self.source_root / 'com/finsec/fuse/integration'
        folder.mkdir(parents=True)
        (folder / 'WorkflowHappyPathIT.java').write_text(
            'package com.finsec.fuse.integration;\n'
            'import org.junit.jupiter.api.Test;\n'
            'class WorkflowHappyPathIT {\n'
            ' @Test void ' + METHOD + '() {\n'
            '  // synthetic body preserves a valid in-method stack line\n'
            ' }\n}\n')
        (folder / 'TransactionRetryBoundariesIT.java').write_text(
            'package com.finsec.fuse.integration;\n'
            'import org.junit.jupiter.params.ParameterizedTest;\n'
            'import org.junit.jupiter.params.provider.ValueSource;\n'
            'class TransactionRetryBoundariesIT {\n'
            ' @ParameterizedTest @ValueSource(ints={1, 2})\n'
            ' void kycLateWritesRollBackThenSucceedWithinTwoRetries(int retries) {}\n'
            '}\n')
        self.report_script = root / 'scripts/ci-test-report.py'
        self.report_script.parent.mkdir()
        # Copy unchanged production bytes: the CLI resolves its default source
        # root relative to this file, without a new production override or flag.
        self.report_script.write_bytes(Path(report.__file__).read_bytes())
        self.report_script.with_name('ci-test-inventory.py').write_bytes(Path(INVENTORY.__file__).read_bytes())
        source_patch = patch.object(report, 'SOURCE_ROOT', self.source_root)
        source_patch.start()
        self.addCleanup(source_patch.stop)

    def payload(self, classname=CLASS, name=METHOD + '()', stack=None, count=1):
        suite = ET.Element('testsuite', name=CLASS, tests=str(count), failures=str(count), errors='0', skipped='0')
        for _ in range(count):
            case = ET.SubElement(suite, 'testcase', classname=classname, name=name)
            ET.SubElement(case, 'failure', message=SECRET, type=SECRET).text = stack or SECRET
            ET.SubElement(case, 'system-out').text = SECRET
            ET.SubElement(case, 'system-err').text = SECRET
        ET.SubElement(suite, 'system-out').text = SECRET
        return ET.tostring(suite)

    def run_report(self, payload):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'test').mkdir()
            (root / 'test' / ('TEST-' + SECRET + '.xml')).write_bytes(payload)
            output = root / 'summary.json'
            run = subprocess.run([sys.executable, str(self.report_script), '--input', str(root),
                                  '--output', str(output)], capture_output=True, text=True)
            self.assertNotIn(SECRET, run.stdout + run.stderr + output.read_text())
            self.assertEqual(run.stderr, '')
            self.assertNotEqual(run.returncode, 0)  # integrationTest absent; never a false pass
            result = json.loads(output.read_text())
            self.assertEqual(json.loads(run.stdout), result)
            return result['tasks']['test']

    def test_synthetic_source_id_and_stack_line(self):
        low, high, _ = report.source_manifest()[CLASS][METHOD]
        row = self.run_report(self.payload(stack=f'{SECRET}\n\tat {CLASS}.{METHOD}(WorkflowHappyPathIT.java:{low + 1})\n{SECRET}'))
        self.assertEqual(row['failureIds'], [{'class': CLASS, 'method': METHOD, 'sourceLine': low + 1}])
        self.assertEqual((row['tests'], row['failures'], row['status']), (1, 1, 'FAIL'))

    def test_missing_source_never_admits_report_claimed_identity(self):
        source = self.source_root / 'com/finsec/fuse/integration/WorkflowHappyPathIT.java'
        source.unlink()
        self.assertNotIn(CLASS, report.source_manifest())
        row = self.run_report(self.payload())
        self.assertEqual(row['failureIds'], [])
        self.assertEqual(row['unknownFailureIds'], 1)
        self.assertEqual(row['status'], 'FAIL')

    def test_forged_classes_names_and_parameterized_values_are_unknown(self):
        for classname, name in ((SECRET, METHOD), (CLASS + SECRET, METHOD),
                                (CLASS, SECRET), (CLASS, METHOD + '(' + SECRET + ')'),
                                (CLASS, METHOD + '()[' + SECRET + ']'),
                                (CLASS, 'request'), (CLASS, METHOD + '\n' + SECRET)):
            with self.subTest(kind='untrusted-id'):
                row = self.run_report(self.payload(classname, name))
                self.assertEqual(row['failureIds'], [])
                self.assertEqual(row['unknownFailureIds'], 1)
                self.assertEqual(row['status'], 'FAIL')

    def test_forged_stack_and_exception_content_is_never_published(self):
        low, high, _ = report.source_manifest()[CLASS][METHOD]
        for frame in (f'at {SECRET}.{METHOD}(WorkflowHappyPathIT.java:{low})',
                      f'at {CLASS}.{SECRET}(WorkflowHappyPathIT.java:{low})',
                      f'at {CLASS}.{METHOD}({SECRET}:{low})',
                      f'at {CLASS}.{METHOD}(WorkflowHappyPathIT.java:999999)',
                      f'at {CLASS}.{METHOD}(WorkflowHappyPathIT.java:{low}) {SECRET}',
                      f'at {CLASS}.{METHOD}(/{SECRET}/WorkflowHappyPathIT.java:{low})'):
            row = self.run_report(self.payload(stack=frame))
            self.assertIsNone(row['failureIds'][0]['sourceLine'])

    def test_malformed_xml_counts_entities_and_false_pass_fail_closed(self):
        for payload in (f'<{SECRET}'.encode(),
                        f'<!DOCTYPE testsuite [<!ENTITY x "{SECRET}">]><testsuite tests="1"/>'.encode(),
                        f'<testsuite tests="{SECRET}"/>'.encode(),
                        b'<testsuite tests="-1"/>', b'<testsuite tests="1000001"/>',
                        b'<testsuite tests="1" failures="0"><testcase><failure/></testcase></testsuite>',
                        f'<{SECRET} tests="1"/>'.encode(), b'\xff\xfe\x00',
                        self.payload().replace(b'failures="1"', b'failures="-1"')):
            row = self.run_report(payload)
            self.assertEqual(row['status'], 'INVALID_REPORT')
            self.assertEqual(row['failureIds'], [])

    def test_known_failure_ids_are_capped_without_changing_counts(self):
        row = self.run_report(self.payload(count=report.MAX_FAILURE_IDS + 5))
        self.assertEqual(len(row['failureIds']), report.MAX_FAILURE_IDS)
        self.assertEqual(row['omittedFailureIds'], 5)
        self.assertEqual(row['failures'], report.MAX_FAILURE_IDS + 5)

    def test_source_comments_literals_nested_and_unicode_are_not_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            folder = root / 'com/finsec/fuse/integration'
            folder.mkdir(parents=True)
            source = folder / 'ExampleIT.java'
            with patch.object(report, 'SOURCE_ROOT', root):
                source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; class ExampleIT {\n'
                                  '// @Test void commentLeak() {}\n'
                                  'String x = "@Test void literalLeak() {}";\n'
                                  '@Test void known() {}\n}')
                self.assertEqual(list(report.source_manifest()['com.finsec.fuse.integration.ExampleIT']), ['known'])
                source.write_text(source.read_text() + '\n// \\u0041')
                self.assertEqual(report.source_manifest(), {})
                source.write_text('package com.finsec.fuse.integration; import org.junit.jupiter.api.Test; '
                                  'class ExampleIT { class Inner { @Test void nested() {} } }')
                self.assertEqual(report.source_manifest(), {'com.finsec.fuse.integration.ExampleIT': {}})

    def test_parameterized_signatures_allow_only_exact_known_prefixes(self):
        classname = 'com.finsec.fuse.integration.TransactionRetryBoundariesIT'
        method = 'kycLateWritesRollBackThenSucceedWithinTwoRetries'
        self.assertIn(method, report.source_manifest()[classname])
        for name in (method + '(int)[1]', method + '(int)[2] ' + SECRET):
            row = self.run_report(self.payload(classname, name))
            self.assertEqual(row['failureIds'][0]['method'], method)
        for name in (method + '(int)', method + SECRET + '(int)[1]', method + '(int)' + SECRET,
                     method + '(' + SECRET + ')[1]', method + '(int)[0]',
                     method + '(int)[1]\n' + SECRET):
            row = self.run_report(self.payload(classname, name))
            self.assertEqual(row['unknownFailureIds'], 1)
            self.assertEqual(row['failureIds'], [])

    def test_duplicate_simple_class_names_remain_package_scoped(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for package, method in (('first', 'firstTest'), ('second', 'secondTest')):
                folder = root / 'com/finsec/fuse' / package
                folder.mkdir(parents=True)
                (folder / 'SameIT.java').write_text('package com.finsec.fuse.' + package +
                                                  '; import org.junit.jupiter.api.Test; '
                                                  'class SameIT { @Test void ' + method + '() {} }')
            with patch.object(report, 'SOURCE_ROOT', root):
                manifest = report.source_manifest()
            case = ET.Element('testcase', classname='com.finsec.fuse.first.SameIT', name='secondTest()')
            self.assertIsNone(report.failure_id(case, manifest))
            case.set('name', 'firstTest()')
            self.assertEqual(report.failure_id(case, manifest)['class'], 'com.finsec.fuse.first.SameIT')

    def test_limits_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / 'test'
            task.mkdir()
            path = task / 'TEST-one.xml'
            path.write_bytes(self.payload())
            with patch.object(report, 'MAX_XML_BYTES', 1):
                self.assertEqual(report.summarize(root)['tasks']['test']['status'], 'INVALID_REPORT')
            with patch.object(report, 'MAX_FILES', 0):
                self.assertEqual(report.summarize(root)['tasks']['test']['status'], 'INVALID_REPORT')
            path.unlink()
            path.symlink_to(root / SECRET)
            self.assertEqual(report.summarize(root)['tasks']['test']['status'], 'INVALID_REPORT')

    def test_original_counts_only_input_and_skip_gate_preserved(self):
        row = self.run_report(b'<testsuite tests="7" failures="2" errors="1" skipped="3"/>')
        self.assertEqual({key: row[key] for key in ('tests', 'failures', 'errors', 'skipped')},
                         dict(tests=7, failures=2, errors=1, skipped=3))
        self.assertEqual(row['status'], 'FAIL')

    def write_source(self, name, body, imports='import org.junit.jupiter.api.Test;', annotations=''):
        classname = 'com.finsec.fuse.integration.' + name
        path = self.source_root / (classname.replace('.', '/') + '.java')
        path.write_text('package com.finsec.fuse.integration;\n' + imports + '\n' + annotations +
                        '\nclass ' + name + ' {\n' + body + '\n}\n')
        return classname

    def unsupported_sources(self):
        return [
            (self.write_source('SuppressedIT', '@SuppressWarnings("unchecked") @Test void rejected() {}'), 'rejected()'),
            (self.write_source('CustomNamedIT', '@ParameterizedTest(name="{index}") '
                               '@ValueSource(ints={1, 2}) void rejected(int value) {}',
                               'import org.junit.jupiter.params.ParameterizedTest;\n'
                               'import org.junit.jupiter.params.provider.ValueSource;'), 'rejected(int)[1]'),
            (self.write_source('ArrayAnnotatedIT', '@Test void rejected() {}',
                               'import org.junit.jupiter.api.Test;\n'
                               'import org.springframework.boot.test.context.SpringBootTest;',
                               '@SpringBootTest(classes={ArrayAnnotatedIT.class})'), 'rejected()'),
            (self.write_source('NestedHelperIT', '@Test void rejected() {}\n'
                               'class Helper { @Override public String toString() { return "helper"; } }'), 'rejected()'),
        ]

    def test_strict_source_rejections_remain_unknown_in_both_producers(self):
        rejected = self.unsupported_sources()
        strict = INVENTORY.source_manifest(self.source_root)
        manifest = report.source_manifest()
        self.assertEqual({name: {method: row[2] for method, row in methods.items()}
                          for name, methods in manifest.items()}, strict)
        for classname, name in rejected:
            with self.subTest(classname=classname):
                self.assertEqual(strict[classname], {})
                self.assertIsNone(INVENTORY.identity(classname, name, strict))
                row = self.run_report(self.payload(classname, name))
                self.assertEqual(row['failureIds'], [])
                self.assertEqual(row['unknownFailureIds'], 1)
                self.assertEqual((row['tests'], row['failures'], row['status']), (1, 1, 'FAIL'))

    def test_missing_optional_line_location_keeps_strict_known_identity(self):
        classname = self.write_source('ProtectedIT', '@Test protected void known() {}')
        self.assertEqual(INVENTORY.source_manifest(self.source_root)[classname], {'known': None})
        row = self.run_report(self.payload(classname, 'known()',
                                           stack=f'at {classname}.known(ProtectedIT.java:5)'))
        self.assertEqual(row['failureIds'], [{'class': classname, 'method': 'known', 'sourceLine': None}])
        self.assertEqual(row['unknownFailureIds'], 0)
        with patch.object(report, 'source_locations', side_effect=OSError()):
            manifest = report.source_manifest()
        case = ET.Element('testcase', classname=CLASS, name=METHOD + '()')
        self.assertEqual(report.failure_id(case, manifest), {'class': CLASS, 'method': METHOD, 'sourceLine': None})

    def test_shared_resolver_controls_parameterized_identity(self):
        classname = 'com.finsec.fuse.integration.TransactionRetryBoundariesIT'
        method = 'kycLateWritesRollBackThenSucceedWithinTwoRetries'
        manifest = report.source_manifest()
        strict = INVENTORY.source_manifest(self.source_root)
        for suffix in ('', '[0]', '[01]', '[1]', '[999999]', '[1000000]',
                       '[2] ' + SECRET, '[2]\n' + SECRET, '[2] ' + 'x' * 1025):
            name = method + '(int)' + suffix
            with self.subTest(suffix=suffix):
                case = ET.Element('testcase', classname=classname, name=name)
                resolved = INVENTORY.identity(classname, name, strict)
                actual = report.failure_id(case, manifest)
                self.assertEqual(actual is not None, resolved is not None)
                if resolved:
                    self.assertEqual((actual['class'], actual['method']), resolved[:2])
                    self.assertNotIn(SECRET, json.dumps(actual))

    def test_mixed_outcomes_capped_ids_bind_without_losing_unknowns_or_totals(self):
        rejected = self.unsupported_sources()
        protected = self.write_source('ProtectedIT', '@Test protected void known() {}')
        passed = self.write_source('PassIT', '@Test void passed() {}')
        skipped = self.write_source('SkipIT', '@Test void skipped() {}')
        parameter_class = 'com.finsec.fuse.integration.TransactionRetryBoundariesIT'
        parameter_method = 'kycLateWritesRollBackThenSucceedWithinTwoRetries'
        low, _, _ = report.source_manifest()[CLASS][METHOD]
        cases = [(CLASS, METHOD + '()', 'failure'), (protected, 'known()', 'failure')]
        cases += [(parameter_class, parameter_method + '(int)[' + str(index) + '] ' + SECRET,
                   'error' if index == 2 else 'failure') for index in range(1, 34)]
        cases += [(classname, name, 'failure') for classname, name in rejected]
        cases += [(parameter_class, parameter_method + '(int)', 'error'),
                  (SECRET, SECRET, 'failure'), (CLASS, SECRET, 'failure'),
                  (passed, 'passed()', None), (skipped, 'skipped()', 'skipped')]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for task in ('test', 'integrationTest'):
                folder = root / task
                folder.mkdir()
                suite = ET.Element('testsuite', name=CLASS, tests=str(len(cases)), failures='40', errors='2', skipped='1')
                for classname, name, marker in cases:
                    case = ET.SubElement(suite, 'testcase', classname=classname, name=name)
                    if marker:
                        ET.SubElement(case, marker, message=SECRET, type=SECRET).text = (
                            f'{SECRET}\n\tat {CLASS}.{METHOD}(WorkflowHappyPathIT.java:{low + 1})\n{SECRET}')
                    ET.SubElement(case, 'system-out').text = SECRET
                ET.SubElement(suite, 'system-err').text = SECRET
                (folder / ('TEST-' + SECRET + '.xml')).write_bytes(ET.tostring(suite))
            summary = report.summarize(root)
            inventory = INVENTORY.summarize(root, self.source_root)
            for task in ('test', 'integrationTest'):
                row, item = summary['tasks'][task], inventory['tasks'][task]
                self.assertEqual((row['tests'], row['failures'], row['errors'], row['skipped'], row['status']),
                                 (44, 40, 2, 1, 'FAIL'))
                self.assertEqual((len(row['failureIds']), row['unknownFailureIds'], row['omittedFailureIds']), (32, 7, 3))
                self.assertEqual(row['failureIds'][0]['sourceLine'], low + 1)
                self.assertEqual(item['counts'], dict(passed=1, failed=40, error=2, skipped=1))
                self.assertEqual(item['unmapped'], dict(passed=0, failed=6, error=1, skipped=0))
                self.assertEqual(item['status'], 'VALID')
                self.assertFalse(item['complete'])
            tracked = {path.relative_to(self.repository).as_posix() for path in self.source_root.rglob('*.java')}
            self.assertFalse(evidence.reports(summary, inventory, self.repository, tracked))
            # Exercise binding and verification with a synthetic checkout result;
            # no Git repository, commits, application, JUnit or database is used.
            revision = {'head': 'a' * 40, 'tree': 'b' * 40,
                        'files': [{'path': name, **evidence.digest((self.repository / name).read_bytes())}
                                  for name in sorted(tracked)]}
            artifacts = root / 'artifacts'
            artifacts.mkdir()
            (artifacts / evidence.PAYLOADS[0]).write_text(json.dumps(inventory))
            (artifacts / evidence.PAYLOADS[1]).write_text(json.dumps(summary))
            with patch.object(evidence, 'checkout', return_value=revision):
                for command in ('bind', 'verify'):
                    self.assertFalse(evidence.execute(command, self.repository, artifacts, revision['head'], '123', '1'))
            for path in artifacts.iterdir():
                self.assertNotIn(SECRET, path.read_text())
                self.assertNotIn(str(root), path.read_text())
            # Strict binder policy still rejects an identifier from an unmapped
            # source; unknown accounting is not permission to admit its name.
            forged = copy.deepcopy(summary)
            forged['tasks']['test']['failureIds'][0] = {'class': rejected[0][0], 'method': 'rejected', 'sourceLine': None}
            with self.assertRaises(evidence.Invalid):
                evidence.reports(forged, inventory, self.repository, tracked)

    def test_source_unavailable_keeps_failure_counts_and_unknown_accounting(self):
        with patch.object(INVENTORY, 'source_manifest', side_effect=OSError()):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'test').mkdir()
                (root / 'test/TEST-one.xml').write_bytes(self.payload(count=3))
                row = report.summarize(root)['tasks']['test']
        self.assertEqual((row['tests'], row['failures'], row['status']), (3, 3, 'FAIL'))
        self.assertEqual((row['failureIds'], row['unknownFailureIds'], row['omittedFailureIds']), ([], 3, 0))


if __name__ == '__main__':
    unittest.main()
