#!/usr/bin/env python3
"""Offline regression checks for CI gates and artifact/credential boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gates = module('ci-prerequisites')
checks = module('ci-verify')
reports = module('ci-test-report')
process_reports = module('ci-process-report')


class GateTest(unittest.TestCase):
    def test_empty_feature_tree_reports_skipped(self):
        with tempfile.TemporaryDirectory() as directory:
            observed = gates.inspect(Path(directory))
            self.assertTrue(all(row['status'] == 'SKIPPED' and row['missing'] for row in observed.values()))

    def test_only_present_component_can_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename in gates.COMPONENTS['frontend']:
                path = root / filename
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
            observed = gates.inspect(root)
            self.assertTrue(observed['frontend']['ready'])
            self.assertFalse(observed['combined']['ready'])
            self.assertFalse(observed['backend']['ready'])

    def test_complete_file_tree_is_ready_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for paths in gates.COMPONENTS.values():
                for filename in paths:
                    path = root / filename
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
            self.assertTrue(all(row['status'] == 'READY_TO_RUN' for row in gates.inspect(root).values()))


class WorkflowPresenceTest(unittest.TestCase):
    def job(self, name):
        import re
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        match = re.search(r'^  ' + re.escape(name) + r':\n(.*?)(?=^  [a-z][a-z0-9-]*:|\Z)', workflow, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, 'Required CI job missing')
        return match.group(1)

    def test_supply_chain_requires_same_complete_tree_as_combined_job(self):
        required = ("    needs: prerequisites\n", "    if: needs.prerequisites.outputs.combined == 'true'\n")
        for name in ('supply-chain', 'combined-compose-browser'):
            job = self.job(name)
            for line in required:
                self.assertIn(line, job)
            self.assertNotIn('continue-on-error: true', job)
        # A partial feature tree is explicitly unready, rather than a scanner PASS.
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(gates.inspect(Path(directory))['combined']['status'], 'SKIPPED')

    def test_integration_branch_still_requires_complete_prerequisites(self):
        job = self.job('prerequisites')
        self.assertIn('if [[ "$REVIEW_BRANCH" == chore/integration-verification* ]]; then', job)
        self.assertIn('args+=(--require-complete)', job)
        self.assertIn('python scripts/ci-prerequisites.py "${args[@]}"', job)


class CredentialTest(unittest.TestCase):
    def config(self):
        keys = ['FUSE_DB_PASSWORD', 'FUSE_DB_OWNER_PASSWORD', 'FUSE_EXPERIMENT_DB_PASSWORD',
                'FUSE_SERVICE_TOKEN', 'FUSE_REVIEWER_TOKEN', 'FUSE_SECURITY_TOKEN', 'FUSE_DEVELOPER_TOKEN']
        keys += [f'FUSE_CUSTOMER_{number}_TOKEN' for number in range(101, 105)]
        return {**{key: hashlib.sha256(key.encode()).hexdigest() for key in keys},
                'FUSE_KYC_MODE': 'replay', 'FUSE_EXPERIMENT_LIVE_ENABLED': 'false', 'FUSE_LLM_API_KEY': ''}

    def validate(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text('\n'.join(f'{key}={value}' for key, value in data.items()))
            return checks.credentials(path)

    def test_generated_literal_configuration_is_accepted(self):
        self.assertEqual(self.validate(self.config())['FUSE_KYC_MODE'], 'replay')

    def test_shell_and_reused_credentials_are_rejected(self):
        data = self.config()
        for invalid in ('$(cat private-file)', 'CHANGE_ME', data['FUSE_REVIEWER_TOKEN']):
            with self.subTest(invalid_kind='nonfresh'):
                data['FUSE_SECURITY_TOKEN'] = invalid
                with self.assertRaises(ValueError):
                    self.validate(data)

    def test_live_provider_and_private_assets_are_rejected(self):
        for key, value in [('FUSE_KYC_MODE', 'live'), ('FUSE_EXPERIMENT_LIVE_ENABLED', 'true'),
                           ('FUSE_LLM_API_KEY', 'private-value'), ('FUSE_KYC_PROMPT_PATH', '/private/prompt')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate({**self.config(), key: value})


class ArtifactTest(unittest.TestCase):
    def make(self, directory):
        root = Path(directory)
        files = {}
        for name in ['case_results.csv', 'case_results.json', 'metrics.json']:
            content = b'{}\n'
            (root / name).write_bytes(content)
            files[name] = {'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}
        (root / 'manifest.json').write_text(json.dumps({'files': files}))
        return root

    def test_exact_manifest_payloads_are_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(len(checks.validate_bundle(self.make(directory), [])), 4)

    def test_raw_unlisted_diagnostic_blocks_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make(directory)
            (root / 'raw-java-report.json').write_text('{}')
            with self.assertRaises(ValueError):
                checks.validate_bundle(root, [])

    def test_manifest_traversal_blocks_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.make(directory)
            manifest = json.loads((root / 'manifest.json').read_text())
            manifest['files']['../private.json'] = {'sha256': '0' * 64, 'bytes': 0}
            (root / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                checks.validate_bundle(root, [])

    def test_modified_file_symlink_and_secret_block_upload(self):
        for kind in ('modified', 'symlink', 'secret'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = self.make(directory)
                if kind == 'modified':
                    (root / 'metrics.json').write_text('modified')
                elif kind == 'symlink':
                    (root / 'metrics.json').unlink()
                    (root / 'metrics.json').symlink_to(root / 'case_results.json')
                with self.assertRaises(ValueError):
                    checks.validate_bundle(root, ['{}'] if kind == 'secret' else [])


class CountReportTest(unittest.TestCase):
    def test_absent_reports_cannot_be_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(all(row['status'] == 'NOT_RUN' for row in reports.summarize(Path(directory))['tasks'].values()))

    def test_only_counts_survive_error_and_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'test').mkdir()
            (root / 'test/TEST-one.xml').write_text('<testsuite tests="2" failures="1" errors="0" skipped="0"><testcase name="private"><failure>secret-payload</failure></testcase><system-out>private-output</system-out></testsuite>')
            summary = reports.summarize(root)
            self.assertEqual(summary['tasks']['test']['status'], 'FAIL')
            self.assertEqual(summary['tasks']['test']['tests'], 2)
            self.assertNotIn('private', json.dumps(summary))
            self.assertNotIn('secret', json.dumps(summary))


class ProcessReportTest(unittest.TestCase):
    def report(self):
        return {'status': 'PASS', 'plannedScenarioCount': 5, 'passedScenarioCount': 5,
                'cleanupVerified': True, 'sourceUnchangedDuringRun': True, 'exitCode': 0,
                'sourceHashBefore': 'a' * 64, 'sourceHashAfter': 'a' * 64,
                'resultsSource': 'REAL_POSTGRES_CHILD_JVM_CRASH_AND_OUTAGE',
                'syntheticModelOutputs': True, 'liveRobustnessMeasured': False,
                'scenarios': [{'scenario': name, 'verdict': 'PASS', 'beforeFailure': {'private': 'secret-text'},
                               'outageHttp': {'body': 'Bearer private-value'}} for name in process_reports.SCENARIOS]}

    def test_complete_current_report_passes_without_raw_data(self):
        summary = process_reports.summarize(self.report(), 'a' * 64)
        self.assertEqual(summary['status'], 'PASS')
        self.assertEqual(summary['passedScenarioCount'], 5)
        serialized = json.dumps(summary)
        self.assertNotIn('secret-text', serialized)
        self.assertNotIn('Bearer', serialized)
        self.assertNotIn('beforeFailure', serialized)

    def test_missing_stale_or_changed_source_cannot_pass(self):
        self.assertEqual(process_reports.summarize(None, 'a' * 64)['status'], 'NOT_RUN')
        self.assertEqual(process_reports.summarize(self.report(), 'b' * 64)['status'], 'FAIL')
        for key, value in [('sourceUnchangedDuringRun', False), ('cleanupVerified', False), ('exitCode', 1),
                           ('passedScenarioCount', 4), ('plannedScenarioCount', True), ('status', 'NOT_RUN')]:
            report = self.report()
            report[key] = value
            with self.subTest(key=key):
                self.assertNotEqual(process_reports.summarize(report, 'a' * 64)['status'], 'PASS')

    def test_missing_duplicate_unknown_and_failing_scenarios_rejected(self):
        for kind in ('missing', 'duplicate', 'unknown', 'failed'):
            report = self.report()
            if kind == 'missing':
                report['scenarios'].pop()
            elif kind == 'duplicate':
                report['scenarios'][-1] = report['scenarios'][0]
            elif kind == 'unknown':
                report['scenarios'][-1]['scenario'] = 'private-scenario-text'
            else:
                report['scenarios'][-1]['verdict'] = 'FAIL'
            with self.subTest(kind=kind):
                summary = process_reports.summarize(report, 'a' * 64)
                self.assertEqual(summary['status'], 'FAIL')
                self.assertNotIn('private-scenario-text', json.dumps(summary))


if __name__ == '__main__':
    unittest.main()
