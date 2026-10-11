#!/usr/bin/env python3
"""Offline mutation checks for bounded backend failure identifiers."""
import copy
import contextlib
import io
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


class ApiGuardDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.method = report.API_DIAGNOSTIC_METHODS[0]
        self.manifest = {report.API_DIAGNOSTIC_CLASS: {m: (None, None, None) for m in report.API_DIAGNOSTIC_METHODS}}
        self.original_source = report.SOURCE_ROOT / (report.API_DIAGNOSTIC_CLASS.replace('.', '/') + '.java')
        self.source_bytes = self.original_source.read_bytes()
        directory = tempfile.TemporaryDirectory(prefix='fuse-api-diagnostic-')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / (report.API_DIAGNOSTIC_CLASS.replace('.', '/') + '.java')
        self.source.parent.mkdir(parents=True)
        self.source.write_bytes(self.source_bytes)
        patcher = patch.object(report, 'SOURCE_ROOT', self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def frame(self, helper='prepare', line='228', classname=None, filename='PublicApiCanonicalPathGuardIT.java'):
        return '\tat ' + (classname or report.API_DIAGNOSTIC_CLASS) + '.' + helper + '(' + filename + ':' + line + ')'

    def case(self, stack=None, classname=None, name=None):
        case = ET.Element('testcase', classname=classname or report.API_DIAGNOSTIC_CLASS, name=name or self.method + '()')
        ET.SubElement(case, 'failure', message=SECRET, type=SECRET).text = stack if stack is not None else self.frame()
        ET.SubElement(case, 'system-out').text = SECRET
        return case

    def diagnostic(self, case):
        result = report.api_guard_diagnostic(case, self.manifest)
        self.assertNotIn(SECRET, json.dumps(result))
        return result

    def test_pinned_source_and_each_exact_stage(self):
        import hashlib
        self.assertEqual(hashlib.sha256(self.source_bytes).hexdigest(), report.API_DIAGNOSTIC_SOURCE_SHA256)
        for (helper, line), stage in report.API_DIAGNOSTIC_STAGES.items():
            with self.subTest(stage=stage):
                self.assertEqual(self.diagnostic(self.case(self.frame(helper, str(line)))), {'method': self.method, 'stage': stage, 'reason': 'MATCHED_FRAME'})

    def test_each_known_method_is_canonical(self):
        for method in report.API_DIAGNOSTIC_METHODS:
            self.assertEqual(self.diagnostic(self.case(name=method+'()'))['method'], method)

    def test_wrong_class_is_not_projected(self):
        self.assertIsNone(self.diagnostic(self.case(classname='com.finsec.fuse.OtherIT')))

    def test_unknown_and_noncanonical_method_are_not_projected(self):
        for name in [SECRET, self.method+'('+SECRET+')', self.method+'[1]', self.method+'() '+SECRET]:
            self.assertIsNone(self.diagnostic(self.case(name=name)))

    def test_unapproved_manifest_identity_is_not_projected(self):
        self.manifest = {}
        self.assertIsNone(self.diagnostic(self.case()))

    def test_wrong_frame_class_helper_or_file_is_unknown(self):
        for stack in [self.frame(classname='com.finsec.fuse.OtherIT'), self.frame(helper=SECRET),
                      self.frame(filename='Other.java'), self.frame(filename=SECRET),
                      self.frame(helper='prepareExtra')]:
            self.assertEqual(self.diagnostic(self.case(stack))['stage'], 'UNKNOWN')

    def test_malformed_oversized_and_unmapped_line_are_unknown(self):
        for line in ['0', '-1', '0211', '1.5', 'true', SECRET, '9999999', '999999', '226']:
            self.assertEqual(self.diagnostic(self.case(self.frame(line=line)))['stage'], 'UNKNOWN')

    def test_untrusted_stage_text_and_embedded_frames_never_leak(self):
        for stack in ['PREPARE_TOMCAT_VERSION '+SECRET, SECRET+self.frame(), self.frame()+SECRET,
                      'FUSE_API_GUARD_STAGE:'+SECRET]:
            self.assertEqual(self.diagnostic(self.case(stack))['stage'], 'UNKNOWN')

    def test_duplicate_and_conflicting_frames_are_unknown(self):
        for stack in [self.frame()+'\n'+self.frame(), self.frame()+'\n'+self.frame(line='230')]:
            self.assertEqual(self.diagnostic(self.case(stack))['stage'], 'UNKNOWN')

    def test_canary_surrounding_valid_frame_is_not_emitted(self):
        self.assertEqual(self.diagnostic(self.case(SECRET+'\n'+self.frame()+'\n'+SECRET))['stage'], 'PREPARE_TOMCAT_VERSION')

    def test_missing_source_is_not_projected(self):
        self.source.unlink()
        self.assertIsNone(self.diagnostic(self.case()))

    def test_hash_mismatched_source_is_not_projected(self):
        self.source.write_bytes(self.source_bytes+b'\n')
        self.assertIsNone(self.diagnostic(self.case()))

    def test_symlink_source_is_not_projected(self):
        self.source.unlink()
        self.source.symlink_to(self.original_source.resolve())
        self.assertIsNone(self.diagnostic(self.case()))

    def test_symlink_source_parent_is_not_projected(self):
        original = self.source.parent
        target = original.with_name('actual')
        original.rename(target)
        original.symlink_to(target)
        self.assertIsNone(self.diagnostic(self.case()))

    def test_oversized_source_is_not_projected(self):
        self.source.write_bytes(b'x'*(report.MAX_XML_BYTES+1))
        self.assertIsNone(self.diagnostic(self.case()))

    def report_root(self, cases):
        root = self.root/'reports'
        (root/'integrationTest').mkdir(parents=True)
        suite = ET.Element('testsuite', name=report.API_DIAGNOSTIC_CLASS, tests=str(len(cases)), failures=str(len(cases)), errors='0', skipped='0')
        suite.extend(cases)
        (root/'integrationTest/TEST-api.xml').write_bytes(ET.tostring(suite))
        return root

    def test_summary_schema_counts_and_failure_remain_unchanged(self):
        root=self.report_root([self.case()]); diagnostics=[]
        with patch.object(report, 'source_manifest', return_value=self.manifest):
            before=report.summarize(root)
            after=report.summarize(root, diagnostics)
        self.assertEqual(before, after)
        self.assertEqual(after['tasks']['integrationTest']['status'], 'FAIL')
        self.assertEqual(diagnostics, [{'method':self.method,'stage':'PREPARE_TOMCAT_VERSION','reason':'MATCHED_FRAME'}])

    def test_invalid_report_does_not_emit_partial_diagnostics(self):
        root=self.report_root([self.case()]);diagnostics=[]
        (root/'integrationTest/TEST-z-invalid.xml').write_text('<!DOCTYPE bad>')
        with patch.object(report, 'source_manifest', return_value=self.manifest):
            summary=report.summarize(root,diagnostics)
        self.assertEqual(summary['tasks']['integrationTest']['status'],'INVALID_REPORT')
        self.assertEqual(diagnostics,[])

    def test_diagnostic_rows_are_bounded(self):
        root=self.report_root([self.case() for _ in range(report.MAX_FAILURE_IDS+5)]);diagnostics=[]
        with patch.object(report,'source_manifest',return_value=self.manifest):
            summary=report.summarize(root,diagnostics)
        self.assertEqual(len(diagnostics),report.MAX_FAILURE_IDS)
        self.assertEqual(summary['tasks']['integrationTest']['failures'],report.MAX_FAILURE_IDS+5)

    def test_app_loader_prefix_recovers_exact_fixed_stage(self):
        for (helper, line), stage in report.API_DIAGNOSTIC_STAGES.items():
            frame=self.frame(helper,str(line)).replace('at ', 'at app//')
            self.assertEqual(self.diagnostic(self.case(frame)),{'method':self.method,'stage':stage,'reason':'MATCHED_FRAME'})

    def test_other_loader_and_module_prefixes_are_not_accepted(self):
        for prefix in ['other//','App//','app/','app///','app/module/','java.base/','app//app//',SECRET+'//']:
            row=self.diagnostic(self.case(self.frame().replace('at ','at '+prefix)))
            self.assertEqual((row['stage'],row['reason']),('UNKNOWN','NO_TARGET_FRAME'))

    def test_unknown_reason_separates_absence_unmapped_and_multiple(self):
        cases=[(SECRET,'NO_TARGET_FRAME'),(self.frame(line='226'),'UNMAPPED_LINE'),
               (self.frame()+'\n'+self.frame(),'MULTIPLE_TARGET_FRAMES'),
               (self.frame()+'\n'+self.frame(line='226'),'MULTIPLE_TARGET_FRAMES'),
               (self.frame(line='226')+'\n'+self.frame(line='225'),'MULTIPLE_TARGET_FRAMES')]
        for stack,reason in cases:
            row=self.diagnostic(self.case(stack))
            self.assertEqual((row['stage'],row['reason']),('UNKNOWN',reason))

    def test_mixed_bare_and_app_frames_remain_ambiguous(self):
        row=self.diagnostic(self.case(self.frame()+'\n'+self.frame().replace('at ','at app//')))
        self.assertEqual((row['stage'],row['reason']),('UNKNOWN','MULTIPLE_TARGET_FRAMES'))

    def test_app_prefix_does_not_relax_identity_or_source(self):
        for frame in [self.frame(helper=SECRET),self.frame(filename=SECRET),self.frame(classname=SECRET)]:
            self.assertEqual(self.diagnostic(self.case(frame.replace('at ','at app//')))['reason'],'NO_TARGET_FRAME')
        self.source.write_bytes(self.source_bytes+b'\n')
        self.assertIsNone(self.diagnostic(self.case(self.frame().replace('at ','at app//'))))

    def test_fake_reason_and_frame_embedded_in_message_do_not_leak(self):
        for stack in ['MATCHED_FRAME '+SECRET,'NO_TARGET_FRAME '+SECRET,SECRET+self.frame().replace('at ','at app//')]:
            row=self.diagnostic(self.case(stack))
            self.assertEqual(row['reason'],'NO_TARGET_FRAME')

    def direct_case(self, line='357', prefix='', method=None):
        method=method or report.API_DIAGNOSTIC_DIRECT_METHOD
        stack=self.frame(helper=method,line=line).replace('at ','at '+prefix)
        return self.case(stack,name=report.API_DIAGNOSTIC_DIRECT_METHOD+'()')

    def test_direct_assertions_have_separate_fixed_stages(self):
        for line,stage in report.API_DIAGNOSTIC_DIRECT_STAGES.items():
            for prefix in ['', 'app//']:
                row=self.diagnostic(self.direct_case(str(line),prefix))
                self.assertEqual(row,{'method':report.API_DIAGNOSTIC_DIRECT_METHOD,'stage':stage,'reason':'MATCHED_DIRECT_FRAME'})

    def test_direct_fallback_requires_same_failed_method_identity(self):
        case=self.direct_case();case.set('name',self.method+'()')
        self.assertEqual(self.diagnostic(case)['reason'],'NO_TARGET_FRAME')

    def test_direct_fallback_requires_exact_method_file_and_prefix(self):
        for method in [SECRET,report.API_DIAGNOSTIC_DIRECT_METHOD+'Extra']:
            self.assertEqual(self.diagnostic(self.direct_case(method=method))['reason'],'NO_TARGET_FRAME')
        for prefix in ['other//','app/module/','app///']:
            self.assertEqual(self.diagnostic(self.direct_case(prefix=prefix))['reason'],'NO_TARGET_FRAME')
        case=self.direct_case();case.find('failure').text=case.find('failure').text.replace('.java:', '.txt:')
        self.assertEqual(self.diagnostic(case)['reason'],'NO_TARGET_FRAME')

    def test_direct_fallback_bounds_and_unknown_lines(self):
        for line in ['0','0334','9999999','-1',SECRET]:
            self.assertEqual(self.diagnostic(self.direct_case(line))['reason'],'NO_TARGET_FRAME')
        for line in ['356','361','999999']:
            self.assertEqual(self.diagnostic(self.direct_case(line))['reason'],'UNMAPPED_LINE')

    def test_direct_duplicate_and_conflicting_frames_are_ambiguous(self):
        for line in ['357','358','356']:
            case=self.direct_case();case.find('failure').text+='\n'+self.direct_case(line).find('failure').text
            row=self.diagnostic(case);self.assertEqual((row['stage'],row['reason']),('UNKNOWN','MULTIPLE_TARGET_FRAMES'))

    def test_helper_frames_always_take_precedence(self):
        for helper,stage,reason in [(self.frame(),'PREPARE_TOMCAT_VERSION','MATCHED_FRAME'),
                                   (self.frame(line='226'),'UNKNOWN','UNMAPPED_LINE'),
                                   (self.frame()+'\n'+self.frame(),'UNKNOWN','MULTIPLE_TARGET_FRAMES')]:
            case=self.direct_case();case.find('failure').text+='\n'+helper
            row=self.diagnostic(case);self.assertEqual((row['stage'],row['reason']),(stage,reason))

    def test_direct_canary_content_and_source_mismatch_cannot_escape(self):
        case=self.direct_case();case.find('failure').text=SECRET+'\n'+case.find('failure').text+'\n'+SECRET
        self.assertEqual(self.diagnostic(case)['stage'],'POSITIVE_CONTROL_STATUS')
        self.source.write_bytes(self.source_bytes+b'\n');self.assertIsNone(self.diagnostic(case))

    def test_direct_stage_pins_bind_exact_assertions(self):
        lines=self.source_bytes.decode().splitlines()
        expected={357:'assertEquals(400,binding.response().statusCode());',
                  358:'assertEquals(1,binding.observation().handlers.get());',
                  359:'assertEquals(1,binding.observation().conversions.get());',
                  360:'assertEquals(unknownField.getBytes(StandardCharsets.UTF_8).length,binding.observation().bytes.get());'}
        self.assertEqual(set(expected),set(report.API_DIAGNOSTIC_DIRECT_STAGES))
        for line,text in expected.items():self.assertEqual(lines[line-1].strip(),text)

    def test_cli_stdout_only_projection_never_changes_artifact_or_exit(self):
        root=self.report_root([self.case(SECRET+'\n'+self.frame()+'\n'+SECRET)])
        output=self.root/'safe-summary.json'
        run=subprocess.run([sys.executable,str(Path(report.__file__)), '--input',str(root),'--output',str(output)],capture_output=True,text=True)
        self.assertNotEqual(run.returncode,0)
        self.assertEqual(run.stderr,'')
        self.assertNotIn(SECRET,run.stdout+run.stderr+output.read_text())
        rows=[json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0],json.loads(output.read_text()))
        self.assertEqual(rows[1]['schemaVersion'],'FUSE-API-PATH-GUARD-DIAGNOSTICS-1')
        self.assertEqual(rows[1]['failures'],[{'method':self.method,'stage':'PREPARE_TOMCAT_VERSION','reason':'MATCHED_FRAME'}])
        self.assertNotIn('failures',rows[0])


class MigrationDiagnosticTests(unittest.TestCase):
    classname = 'com.finsec.fuse.migration.DatabaseMigratorIT'
    method = 'freshMigrationLeavesOnlyStructuralRowsAndReadOnlyHistoryPrivileges'

    def case(self, classname=None, method=None, stack=None):
        case = ET.Element('testcase', classname=classname or self.classname, name=(method or self.method) + '()')
        ET.SubElement(case, 'failure', message=SECRET, type=SECRET).text = stack or SECRET
        return case

    def reports(self, directory, cases):
        folder = Path(directory) / 'integrationTest'; folder.mkdir(exist_ok=True)
        suite = ET.Element('testsuite', tests=str(len(cases)), failures=str(sum(c.find('failure') is not None for c in cases)),
                           errors='0', skipped=str(sum(c.find('skipped') is not None for c in cases)))
        suite.extend(cases)
        path = folder / 'TEST-synthetic.xml'; path.write_bytes(ET.tostring(suite)); return path

    def test_exact_pinned_source_methods_are_reviewed_and_frames_are_bounded(self):
        self.assertEqual(4, len(report.MIGRATION_DIAGNOSTIC_SOURCES))
        for classname, (digest, methods) in report.MIGRATION_DIAGNOSTIC_SOURCES.items():
            path = report.SOURCE_ROOT / (classname.replace('.', '/') + '.java')
            self.assertEqual(digest, report.hashlib.sha256(path.read_bytes()).hexdigest())
            declared = set(report.re.findall(r'@Test void ([A-Za-z0-9_]+)\(', path.read_text()))
            self.assertTrue(set(methods) <= declared)
            self.assertEqual(len(methods), len(set(methods)))
        low, high, _ = report.source_locations()[self.classname][self.method]
        case = self.case(stack=f'{SECRET}\n at app//{self.classname}.{self.method}(DatabaseMigratorIT.java:{low + 1})\n{SECRET}')
        row = report.migration_diagnostic(case)
        self.assertEqual((row['class'], row['method'], row['status'], row['count'], row['sourceLine']),
                         (self.classname, self.method, 'failed', 1, low + 1))
        self.assertNotIn(SECRET, json.dumps(row))

    def test_forged_identity_and_skipped_or_mixed_status_never_publish(self):
        for classname, method in ((SECRET, self.method), (self.classname + '/../' + SECRET, self.method),
                                  (self.classname, SECRET), (self.classname, self.method + '\n' + SECRET),
                                  (self.classname, self.method + '(PRIVATE_CANARY)')):
            self.assertIsNone(report.migration_diagnostic(self.case(classname, method)))
        for tag in ('skipped', 'error', 'failure'):
            case = self.case(); ET.SubElement(case, tag)
            self.assertIsNone(report.migration_diagnostic(case))

    def test_unknown_frames_emit_no_report_text_or_out_of_range_line(self):
        for stack in (SECRET, f'at {self.classname}.{self.method}(DatabaseMigratorIT.java:999999)',
                      f'at {self.classname}.{self.method}(/PRIVATE_CANARY/DatabaseMigratorIT.java:127)',
                      f'at {self.classname}.{self.method}(DatabaseMigratorIT.java:127) {SECRET}'):
            row = report.migration_diagnostic(self.case(stack=stack))
            self.assertIsNone(row['sourceLine']); self.assertNotIn(SECRET, json.dumps(row))

    def test_source_change_missing_or_symlinked_path_is_not_authority(self):
        original = report.SOURCE_ROOT / (self.classname.replace('.', '/') + '.java')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / (self.classname.replace('.', '/') + '.java'); path.parent.mkdir(parents=True)
            with patch.object(report, 'SOURCE_ROOT', root):
                self.assertIsNone(report.migration_diagnostic(self.case()))
                path.write_bytes(original.read_bytes() + b'\n// changed\n')
                self.assertIsNone(report.migration_diagnostic(self.case()))
                path.unlink(); path.symlink_to(original)
                self.assertIsNone(report.migration_diagnostic(self.case()))

    def test_duplicate_cases_keep_count_failure_and_suppress_ambiguous_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            self.reports(directory, [self.case(), self.case()])
            rows = []; summary = report.summarize(Path(directory), migration_diagnostics=rows)
            self.assertEqual(rows, [])
            self.assertEqual(summary, report.summarize(Path(directory)))
            self.assertEqual(summary['tasks']['integrationTest']['unknownFailureIds'], 2)
            self.assertEqual(summary['tasks']['integrationTest']['status'], 'FAIL')

    def test_malformed_xml_retains_invalid_gate_without_advisory_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.reports(directory, [self.case()]); path.write_text('<PRIVATE_CANARY')
            rows = []; summary = report.summarize(Path(directory), migration_diagnostics=rows)
            self.assertEqual(rows, []); self.assertEqual(summary['tasks']['integrationTest']['status'], 'INVALID_REPORT')

    def test_inprocess_main_prints_only_safe_projection_and_preserves_unknown_failure_count(self):
        with tempfile.TemporaryDirectory() as directory:
            self.reports(directory, [self.case()]); output = Path(directory) / 'summary.json'
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, 'argv', ['ci-test-report.py', '--input', directory, '--output', str(output)]), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = report.main()
            self.assertNotEqual(0, result); self.assertEqual('', stderr.getvalue())
            rows = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(rows[0], json.loads(output.read_text()))
            self.assertEqual(rows[0]['tasks']['integrationTest']['unknownFailureIds'], 1)
            self.assertEqual(rows[1]['schemaVersion'], 'FUSE-MIGRATION-TEST-DIAGNOSTICS-1')
            self.assertEqual(rows[1]['failures'][0]['method'], self.method)
            self.assertNotIn(SECRET, stdout.getvalue() + stderr.getvalue() + output.read_text())


if __name__ == '__main__':
    unittest.main()
