#!/usr/bin/env python3
"""Offline adversarial tests for the separate, privacy-safe identity artifact."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape, quoteattr

spec = importlib.util.spec_from_file_location('inventory', Path(__file__).with_name('ci-test-inventory.py'))
inv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inv)
CANARY = 'PRIVATE_CANARY_customer_secret_document_token'
CLASS = 'com.finsec.fuse.ExampleTest'
SOURCE = '''package com.finsec.fuse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
class ExampleTest {
 @Test void simple() {}
 @Test void other() {}
 @ParameterizedTest @ValueSource(strings={"private", "other"})
 void parameter(String value) {}
}
'''


def case(name='simple()', outcome='passed', classname=CLASS, extra=''):
    marker = {'passed': '', 'failed': '<failure message="' + CANARY + '" type="' + CANARY + '">' + CANARY + '</failure>',
              'error': '<error>' + CANARY + '</error>', 'skipped': '<skipped message="' + CANARY + '"/>'}[outcome]
    return '<testcase classname=' + quoteattr(classname) + ' name=' + quoteattr(name) + ' time="0.123">' + marker + extra + '</testcase>'


def suite(cases, name=CLASS, **overrides):
    attrs = dict(name=name, tests=str(len(cases)), failures=str(sum('<failure' in c for c in cases)),
                 errors=str(sum('<error' in c for c in cases)), skipped=str(sum('<skipped' in c for c in cases)),
                 timestamp=CANARY, hostname=CANARY, time='12.123')
    attrs.update(overrides)
    return '<testsuite ' + ' '.join(k + '=' + quoteattr(v) for k, v in attrs.items()) + '><properties><property name="' + CANARY + '" value="' + CANARY + '"/></properties>' + ''.join(cases) + '<system-out>' + CANARY + '</system-out><system-err>' + CANARY + '</system-err></testsuite>'


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.java = self.source / 'com/finsec/fuse/ExampleTest.java'
        self.java.parent.mkdir(parents=True)
        self.java.write_text(SOURCE)
        self.reports = self.root / 'reports'
        for task in ('test', 'integrationTest'):
            (self.reports / task).mkdir(parents=True)
            self.write([case()], task=task)

    def write(self, cases=None, payload=None, task='test', name='TEST-example.xml'):
        path = self.reports / task / name
        path.write_text(payload if payload is not None else suite(cases))
        return path

    def result(self):
        result = inv.summarize(self.reports, self.source)
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertNotIn(str(self.root), json.dumps(result))
        self.assertEqual(set(result), {'schemaVersion', 'tasks'})
        self.assertEqual(result['schemaVersion'], 'FUSE-TEST-INVENTORY-1')
        for task in result['tasks'].values():
            self.assertEqual(set(task), {'status', 'complete', 'counts', 'mapped', 'unmapped', 'rows', 'diagnostics'})
            for key in ('counts', 'mapped', 'unmapped'):
                self.assertEqual(set(task[key]), set(inv.STATUSES))
            for outcome in inv.STATUSES:
                self.assertEqual(task['counts'][outcome], task['mapped'][outcome] + task['unmapped'][outcome])
                self.assertEqual(task['mapped'][outcome], sum(row['count'] for row in task['rows'] if row['status'] == outcome))
            for row in task['rows']:
                self.assertEqual(set(row), {'class', 'method', 'status', 'count'})
        return result['tasks']['test']

    def invalid(self, payload):
        self.write(payload=payload)
        result = self.result()
        self.assertEqual(result, inv.empty('INVALID_REPORT', 'REPORT_REJECTED'))

    def test_complete_canonical_pass(self):
        task = self.result()
        self.assertTrue(task['complete'])
        self.assertEqual(task['rows'], [{'class': CLASS, 'method': 'simple', 'status': 'passed', 'count': 1}])

    def test_parameterized_mixed_outcomes_and_privacy(self):
        self.write([case('parameter(String)[%d] %s' % (i, CANARY), outcome) for i, outcome in enumerate(inv.STATUSES, 1)] +
                   [case('simple()', extra='<system-out>' + CANARY + '</system-out>')])
        result = self.result()
        self.assertTrue(result['complete'])
        self.assertEqual(result['counts'], dict(passed=2, failed=1, error=1, skipped=1))
        self.assertEqual(len(result['rows']), 5)

    def test_parameterized_counts_coalesce(self):
        self.write([case('parameter(String)[%d] %s' % (i, CANARY)) for i in (1, 2, 3)])
        self.assertEqual(self.result()['rows'][0]['count'], 3)

    def test_unknown_names_and_class_never_echo(self):
        self.write([case(CANARY), case('simple()', classname=CANARY), case('parameter(String)')])
        result = self.result()
        self.assertFalse(result['complete'])
        self.assertEqual(result['unmapped']['passed'], 3)
        self.assertEqual(result['rows'], [])

    def test_factory_can_impersonate_static_method(self):
        self.java.write_text(SOURCE.replace('@Test void other() {}', '@TestFactory Object factory() { return null; }'))
        self.write([case('simple()'), case('factory()[1] ' + CANARY)])
        self.assertEqual(self.result()['unmapped']['passed'], 2)

    def test_display_name_generation_and_repeat_are_unknown(self):
        for annotation in ('DisplayName', 'DisplayNameGeneration', 'RepeatedTest', 'TestTemplate'):
            with self.subTest(annotation=annotation):
                self.java.write_text(SOURCE.replace('@Test void simple()', '@' + annotation + '("private") @Test void simple()'))
                self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_inherited_and_composed_identities_unknown(self):
        for source in (SOURCE.replace('class ExampleTest {', 'class ExampleTest extends DynamicBase {'),
                       SOURCE.replace('class ExampleTest {', 'class ExampleTest implements DynamicTests {'),
                       SOURCE.replace('@Test void other() {}', '@CustomFactory Object factory() { return null; }'),
                       SOURCE.replace('import org.junit.jupiter.api.Test;', 'import org.junit.jupiter.api.Test; import private.annotation.Tag;').replace('@Test void simple()', '@Tag @Test void simple()'),
                       SOURCE.replace('class ExampleTest {', '@CustomNaming class ExampleTest {')):
            self.java.write_text(source)
            self.assertEqual(self.result()['unmapped']['passed'], 1)

    def fixture(self, classname='com.finsec.fuse.Base', body='', header='', imports=''):
        package, name = classname.rsplit('.', 1)
        path = self.source / (classname.replace('.', '/') + '.java')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('package ' + package + ';\n' + imports + '\npublic abstract class ' +
                        name + header + ' { ' + body + ' }')
        return path

    def inherit(self, parent='Base', imports=''):
        self.java.write_text(SOURCE.replace('class ExampleTest {',
                                           imports + '\nclass ExampleTest extends ' + parent + ' {'))

    def test_same_package_fixture_keeps_child_identities(self):
        self.fixture(body='protected void setup() {}')
        self.inherit()
        self.write([case(), case('parameter(String)[1] ' + CANARY)])
        result = self.result()
        self.assertTrue(result['complete'])
        self.assertEqual(result['mapped']['passed'], 2)
        self.assertEqual({row['class'] for row in result['rows']}, {CLASS})

    def test_explicit_import_fixture_chains(self):
        self.fixture('com.finsec.fuse.testing.Root', body='@BeforeEach void setup() {}',
                     imports='import org.junit.jupiter.api.BeforeEach;')
        self.fixture(header=' extends Root', imports='import com.finsec.fuse.testing.Root;')
        for parent, imports in [('Base', ''), ('Root', 'import com.finsec.fuse.testing.Root;')]:
            with self.subTest(parent=parent):
                self.inherit(parent, imports)
                self.assertTrue(self.result()['complete'])

    def test_qualified_superclass_namespace_is_not_guessed(self):
        self.fixture()
        for imports in ('', 'import custom.com;', 'import custom.*;'):
            self.inherit('com.finsec.fuse.Base', imports)
            self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_bad_ancestor_poisons_descendant_even_without_recognized_methods(self):
        for body, imports in [('@TestFactory Object factory() { return null; }', ''),
                              ('@DisplayName("simple()") void alias() {}', ''),
                              ('@DisplayNameGeneration(Object.class) void alias() {}', ''),
                              ('@CustomFactory Object factory() { return null; }', ''),
                              ('@Test void inherited() {}', 'import org.junit.jupiter.api.Test;'),
                              ('@ParameterizedTest(name="simple()") void alias(String x) {}', ''),
                              ('@org.junit.jupiter.api.Test void inherited() {}', '')]:
            with self.subTest(body=body):
                self.fixture(body=body, imports=imports)
                self.inherit()
                self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_unqualified_java_lang_names_never_authorize_fixture_annotations(self):
        for annotation in ('Override', 'SuppressWarnings', 'Deprecated', 'SafeVarargs', 'FunctionalInterface'):
            for imports in ('', 'import custom.' + annotation + ';', 'import custom.*;',
                            'import java.lang.' + annotation + ';'):
                with self.subTest(annotation=annotation, imports=imports):
                    self.fixture(body='@' + annotation + ' Object factory() { return null; }', imports=imports)
                    self.inherit()
                    self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_local_package_and_inherited_java_lang_annotation_shadows_unknown(self):
        for location in ('local', 'package', 'ancestor'):
            with self.subTest(location=location):
                body = '@Override Object factory() { return null; }'
                header = ''
                if location == 'local':
                    body += ' @interface Override {}'
                elif location == 'package':
                    self.fixture('com.finsec.fuse.Override')
                else:
                    self.fixture('com.finsec.fuse.Root', body='@interface Override {}')
                    header = ' extends Root'
                self.fixture(body=body, header=header)
                self.inherit()
                self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_wildcard_framework_annotations_do_not_hide_custom_factories(self):
        self.fixture(body='@BeforeEach Object factory() { return null; }',
                     imports='import org.junit.jupiter.api.*;')
        self.inherit()
        self.assertEqual(self.result()['unmapped']['passed'], 1)
        self.fixture('com.finsec.fuse.BeforeEach')
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_fixture_member_types_cannot_shadow_descendant_annotations(self):
        self.fixture('com.finsec.fuse.Root', body='class BeforeEach {}')
        self.fixture(header=' extends Root', body='@BeforeEach void helper() {}',
                     imports='import org.junit.jupiter.api.BeforeEach;')
        self.inherit()
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_qualified_annotations_with_unprovable_namespace_stay_unknown(self):
        for annotation in ('java.lang.SuppressWarnings', 'org.junit.jupiter.api.BeforeEach'):
            for imports in ('', 'import custom.java;', 'import custom.org;', 'import custom.*;'):
                with self.subTest(annotation=annotation, imports=imports):
                    self.fixture(body='@' + annotation + ' void helper() {}', imports=imports)
                    self.inherit()
                    self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_unsupported_ancestor_lexing_and_declaration(self):
        for suffix in (' extends Missing', ' implements Missing', '<T>', ' extends Missing<String>'):
            with self.subTest(suffix=suffix):
                self.fixture(header=suffix)
                self.inherit()
                self.assertEqual(self.result()['unmapped']['passed'], 1)
        path = self.fixture()
        path.write_text(path.read_text() + '\\u0061')
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_ambiguous_imports_and_wildcard_only_are_unknown(self):
        self.fixture('com.finsec.fuse.left.Base')
        self.fixture('com.finsec.fuse.right.Base')
        for imports in ('import com.finsec.fuse.left.Base; import com.finsec.fuse.right.Base;',
                        'import com.finsec.fuse.left.*;', 'import external.Base;'):
            with self.subTest(imports=imports):
                self.inherit(imports=imports)
                self.assertEqual(self.result()['unmapped']['passed'], 1)
        self.fixture()
        self.inherit(imports='import com.finsec.fuse.left.Base;')
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_cycles_and_depth_limit_remain_unknown(self):
        self.fixture(header=' extends Other')
        self.fixture('com.finsec.fuse.Other', header=' extends Base')
        self.inherit()
        self.assertEqual(self.result()['unmapped']['passed'], 1)
        self.fixture(header=' extends Base')
        self.assertEqual(self.result()['unmapped']['passed'], 1)
        self.fixture(header=' extends Other')
        self.fixture('com.finsec.fuse.Other')
        # A deep graph in a shallow package is rejected independently of files.
        for index in range(inv.MAX_DEPTH + 1):
            self.fixture('com.finsec.fuse.Chain' + str(index),
                         header=(' extends Chain' + str(index + 1)) if index < inv.MAX_DEPTH else '')
        self.inherit('Chain0')
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_nested_shadow_superclass_is_unknown(self):
        self.fixture()
        self.inherit()
        self.java.write_text(self.java.read_text().replace('@Test void other() {}',
                                                         'class Base { void helper() {} }'))
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_child_alias_and_unresolved_class_names_stay_private(self):
        self.fixture()
        self.inherit()
        self.write([case(CANARY), case('simple()', classname=CANARY),
                    case('inherited()'), case('simple()', outcome='failed')])
        result = self.result()
        self.assertFalse(result['complete'])
        self.assertEqual(result['mapped']['failed'], 1)
        self.assertEqual(result['unmapped']['passed'], 3)

    def test_custom_parameter_name_cannot_impersonate_method(self):
        self.java.write_text(SOURCE.replace('@ParameterizedTest ', '@ParameterizedTest(name="simple()") '))
        self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_wrong_import_and_overload_unknown(self):
        for source in (SOURCE.replace('org.junit.jupiter.api.Test', 'private.secret.Test'),
                       SOURCE.replace('@Test void other()', '@Test void simple()')):
            self.java.write_text(source)
            self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_nested_comment_literal_and_unicode_not_guessed(self):
        for source in (SOURCE.replace('@Test void simple() {}', 'class Nested { @Test void simple() {} }'),
                       SOURCE.replace('@Test void simple() {}', '// @Test void simple() {}\n'),
                       SOURCE.replace('@Test void simple() {}', 'String literal="@Test void simple() {}";'),
                       SOURCE + '\\u0061', SOURCE + '/* unclosed'):
            with self.subTest(source=source):
                self.java.write_text(source)
                self.assertEqual(self.result()['unmapped']['passed'], 1)

    def test_deterministic_case_and_file_order(self):
        first = [case('parameter(String)[2] private', 'failed'), case('other()'), case('parameter(String)[1] private')]
        self.write(first)
        self.write([case()], name='TEST-second.xml', payload=suite([case()], name='second'))
        before = self.result()
        self.write(list(reversed(first)))
        a, b = self.reports / 'test/TEST-example.xml', self.reports / 'test/TEST-second.xml'
        left, right = a.read_text(), b.read_text()
        a.write_text(right)
        b.write_text(left)
        self.assertEqual(before, self.result())

    def test_ambiguous_bare_parameter_collisions_remain_unknown(self):
        self.write([case("[1] " + CANARY), case("[1] " + CANARY, "failed")])
        result = self.result()
        self.assertEqual(result["status"], "VALID")
        self.assertFalse(result["complete"])
        self.assertEqual(result["unmapped"], dict(passed=1, failed=1, error=0, skipped=0))
        self.assertEqual(result["rows"], [])

    def test_missing_cases_and_incorrect_counts(self):
        for changes in ({'tests': '2'}, {'failures': '1'}, {'skipped': '1'}, {'errors': '1'}, {'tests': '-1'},
                        {'tests': '01'}, {'tests': 'NaN'}, {'tests': '1000001'}, {'time': 'NaN'}, {'time': '-1'}):
            with self.subTest(changes=changes):
                self.invalid(suite([case()], **changes))
        self.invalid(suite([], tests='1'))
        self.invalid(suite([case()]).replace(' errors="0"', ''))

    def test_duplicate_invocations_and_ambiguous_markers(self):
        self.invalid(suite([case(), case()]))
        self.invalid(suite([case('simple'), case('simple()')]))
        self.invalid(suite([case('parameter(String)[1] one'), case('parameter(String)[1] two')]))
        self.invalid(suite([case(extra='<failure/><error/>')], failures='1', errors='1'))
        self.invalid(suite([case(extra='<failure/><failure/>')], failures='1'))
        self.invalid(suite([case(extra='<skipped/><failure/>')], failures='1', skipped='1'))

    def test_duplicate_reports_and_duplicate_suite_names(self):
        self.write([case()], name='TEST-duplicate.xml')
        self.assertEqual(self.result()['status'], 'INVALID_REPORT')
        self.write([case('other()')], name='TEST-duplicate.xml')
        self.assertEqual(self.result()['status'], 'INVALID_REPORT')

    def test_malformed_structure_attributes_and_entities(self):
        for payload in ('<bad', '<testsuites/>', '<testsuite/>',
                        '<!DOCTYPE testsuite [<!ENTITY private "' + CANARY + '">]>' + suite([case()]),
                        suite([case()]).replace('<testcase ', '<testcase evil="yes" '),
                        suite([case()]).replace('<properties>', '<properties><testcase/>'),
                        suite([case()]).replace('</testsuite>', '<unknown/></testsuite>'),
                        suite([case()]).replace('</testsuite>', '<!--' + CANARY + '--></testsuite>'),
                        suite([case()]).replace('</testsuite>', '<?private data?></testsuite>'),
                        suite([case()]).replace('<failure', '<error'),
                        suite([case()]).replace('</testcase>', '<system-out/><system-out/></testcase>')):
            # One replacement intentionally does nothing, checked separately.
            if payload == suite([case()]):
                continue
            with self.subTest(payload=payload):
                self.invalid(payload)

    def test_file_total_node_depth_and_number_limits(self):
        for key, limit, payload in (('MAX_FILE_BYTES', 20, suite([case()])),
                                    ('MAX_TOTAL_BYTES', 20, suite([case()])),
                                    ('MAX_NODES', 2, suite([case()])),
                                    ('MAX_DEPTH', 3, '<testsuite>' + '<x>' * 10 + '</x>' * 10 + '</testsuite>')):
            self.write(payload=payload)
            with patch.object(inv, key, limit):
                self.assertEqual(self.result()['status'], 'INVALID_REPORT')
        self.write([case()])
        with patch.object(inv, 'MAX_FILES', 0):
            self.assertEqual(self.result()['status'], 'INVALID_REPORT')

    def test_symlink_report_file_task_parent_and_source(self):
        path = self.reports / 'test/TEST-example.xml'
        original = self.root / 'original.xml'
        path.rename(original)
        path.symlink_to(original)
        self.assertEqual(self.result()['status'], 'INVALID_REPORT')
        path.unlink()
        original.rename(path)
        for target in (self.reports / 'test', self.reports):
            renamed = target.with_name(target.name + '-real')
            target.rename(renamed)
            target.symlink_to(renamed, target_is_directory=True)
            self.assertEqual(self.result()['status'], 'INVALID_REPORT')
            target.unlink()
            renamed.rename(target)
        renamed = self.source.with_name('real-source')
        self.source.rename(renamed)
        self.source.symlink_to(renamed, target_is_directory=True)
        result = self.result()
        self.assertFalse(result['complete'])
        self.assertEqual(result['unmapped']['passed'], 1)
        self.assertIn('SOURCE_UNAVAILABLE', result['diagnostics'])

    def test_missing_reports_and_zero_cases_not_run(self):
        (self.reports / 'test/TEST-example.xml').unlink()
        self.assertEqual(self.result()['status'], 'NOT_RUN')
        self.write([])
        self.assertEqual(self.result()['status'], 'NOT_RUN')

    def test_cli_exit_and_safe_output(self):
        command = [sys.executable, str(Path(inv.__file__)), str(self.reports), '--source-root', str(self.source)]
        completed = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, '')
        invalid = subprocess.run(command + [CANARY], capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertEqual(invalid.stderr, 'INVENTORY_ARGUMENTS_REJECTED\n')
        self.assertNotIn(CANARY, invalid.stdout + invalid.stderr)
        self.assertNotIn(CANARY, completed.stdout)
        self.write([case(CANARY)])
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        (self.reports / 'integrationTest/TEST-example.xml').unlink()
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
        output = self.root / 'out.json'
        completed = subprocess.run(command + ['--output', str(output)], capture_output=True, text=True)
        self.assertEqual(completed.stdout, '')
        self.assertEqual(json.loads(output.read_text())['schemaVersion'], inv.SCHEMA)
        output.unlink()
        output.symlink_to(self.java)
        completed = subprocess.run(command + ['--output', str(output)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, 'INVENTORY_OUTPUT_REJECTED\n')
        self.assertEqual(self.java.read_text(), SOURCE)


if __name__ == '__main__':
    unittest.main()
