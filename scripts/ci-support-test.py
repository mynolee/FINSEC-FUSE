#!/usr/bin/env python3
"""Offline regression checks for CI gates and artifact/credential boundaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import contextlib
import io
from urllib.error import HTTPError


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

    def test_network_harness_static_tests_are_required_prerequisites(self):
        job = self.job('prerequisites')
        self.assertIn('        run: python scripts/container-network-test.py\n', job)
        self.assertNotIn('continue-on-error:', job)

    def test_actual_network_check_runs_immediately_after_readiness(self):
        import re
        job = self.job('combined-compose-browser')
        self.assertRegex(job, r'run: python scripts/ci-verify\.py ready\n'
                         r'      - name: [^\n]+\n'
                         r'        run: python scripts/container-network-check\.py\n'
                         r'      - name: Real authenticated browser')
        self.assertEqual(job.count('run: python scripts/container-network-check.py'), 1)
        self.assertNotIn('continue-on-error:', job)
        self.assertLess(job.index('python scripts/container-network-check.py'),
                        job.index('python scripts/ci-verify.py diagnostics'))

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


class ReadinessDiagnosticTest(unittest.TestCase):
    class Response:
        def __init__(self, status, body):
            self.status, self.body, self.limit = status, body, None
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, limit):
            self.limit = limit
            return self.body[:limit]

    def process(self, value, code=0):
        return SimpleNamespace(returncode=code, stdout=json.dumps(value).encode(), stderr=b'PRIVATE_PAYLOAD_SENTINEL')

    def agent(self):
        return self.process({'ready': True, 'httpStatus': 200, 'result': 'READY'})

    def test_backend_failure_does_not_hide_frontend_or_agent(self):
        frontend = self.Response(200, b'<div id="root"></div>')
        with patch.object(checks.subprocess, 'run', return_value=self.agent()), patch.object(checks.HTTP, 'open', side_effect=[HTTPError('private', 503, 'PRIVATE_PAYLOAD_SENTINEL', {}, None), frontend]):
            observed = checks.readiness_probes()
        self.assertTrue(observed['agent']['ready'])
        self.assertTrue(observed['frontend']['ready'])
        self.assertEqual(observed['backend']['httpStatus'], 503)
        self.assertFalse(observed['backend']['ready'])
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_replay_required_cannot_be_overridden_by_ready_boolean(self):
        agent = self.process({'ready': True, 'httpStatus': 200, 'result': 'REPLAY_REQUIRED'})
        with patch.object(checks.subprocess, 'run', return_value=agent), patch.object(checks.HTTP, 'open', side_effect=OSError('PRIVATE_PAYLOAD_SENTINEL')):
            observed = checks.readiness_probes()
        self.assertFalse(observed['agent']['ready'])
        self.assertEqual(observed['agent']['result'], 'REPLAY_REQUIRED')

    def test_http_bodies_are_bounded_and_minified_root_is_supported(self):
        backend = self.Response(200, b'{"status":"UP","details":"PRIVATE_PAYLOAD_SENTINEL"}')
        frontend = self.Response(200, b'<div id=root></div>')
        with patch.object(checks.subprocess, 'run', return_value=self.agent()), patch.object(checks.HTTP, 'open', side_effect=[backend, frontend]):
            observed = checks.readiness_probes()
        self.assertTrue(all(row['ready'] for row in observed.values()))
        self.assertEqual(backend.limit, 4097)
        self.assertEqual(frontend.limit, 65537)
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_only_actual_unambiguous_div_id_counts_as_root(self):
        for body in (b'<div id="root"></div>', b"<div id='root'></div>", b'<DIV ID=root></DIV>'):
            with self.subTest(valid=body):
                self.assertTrue(checks.has_root_element(body))
        for body in (b'<div data-id="root"></div>', b'<div aria-id="root"></div>',
                     b'<div data-note=" id=root"></div>', b'<!-- <div id="root"> -->',
                     b'<script>"<div id=\"root\">"</script>', b'<div id="other" id="root"></div>',
                     b'<span id="root"></span>', b'<div id="root-other"></div>'):
            with self.subTest(invalid=body):
                self.assertFalse(checks.has_root_element(body))

    def test_host_and_internal_probes_reject_non_id_root_markers(self):
        for body in (b'<div data-id="root"></div>', b'<div aria-id="root"></div>', b'<div data-note=" id=root"></div>'):
            with self.subTest(body=body):
                backend = self.Response(200, b'{"status":"UP"}')
                with patch.object(checks.subprocess, 'run', return_value=self.agent()), patch.object(checks.HTTP, 'open', side_effect=[backend, self.Response(200, body)]):
                    observed = checks.readiness_probes()
                self.assertFalse(observed['frontend']['ready'])
                internal_backend = SimpleNamespace(returncode=0, stdout=b'HTTP/1.1 200 OK\r\n\r\n{"status":"UP"}', stderr=b'')
                internal_frontend = SimpleNamespace(returncode=0, stdout=body, stderr=b'')
                with patch.object(checks.subprocess, 'run', side_effect=[internal_backend, internal_frontend]):
                    observed = checks.internal_http_probes()
                self.assertFalse(observed['frontend']['ready'])

    def test_oversized_or_unknown_responses_do_not_pass(self):
        agent = self.process({'ready': True, 'httpStatus': '200 PRIVATE_PAYLOAD_SENTINEL', 'result': 'PRIVATE_PAYLOAD_SENTINEL'})
        with patch.object(checks.subprocess, 'run', return_value=agent), patch.object(checks.HTTP, 'open', side_effect=[self.Response(200, b'x' * 4097), self.Response(200, b'<div id="root">' + b'x' * 65536)]):
            observed = checks.readiness_probes()
        self.assertFalse(any(row['ready'] for row in observed.values()))
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_container_fields_are_strictly_projected(self):
        rows = [{'Service': 'backend', 'State': 'exited', 'Health': '', 'ExitCode': 1, 'Command': 'PRIVATE_PAYLOAD_SENTINEL'},
                {'Service': 'agent', 'State': 'PRIVATE_PAYLOAD_SENTINEL', 'Health': 'PRIVATE_PAYLOAD_SENTINEL', 'ExitCode': True},
                {'Service': 'PRIVATE_PAYLOAD_SENTINEL', 'State': 'running'}]
        with patch.object(checks.subprocess, 'run', return_value=self.process(rows)):
            observed = checks.compose_states()
        self.assertEqual(observed['backend'], {'state': 'EXITED', 'health': 'NONE', 'exitCode': 1})
        self.assertEqual(observed['agent'], {'state': 'UNKNOWN', 'health': 'UNKNOWN', 'exitCode': None})
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_startup_logs_only_emit_known_boolean_categories(self):
        process = SimpleNamespace(returncode=0, stdout=b'APPLICATION FAILED TO START BeanCreationException PRIVATE_PAYLOAD_SENTINEL', stderr=b'PRIVATE_PAYLOAD_SENTINEL')
        with patch.object(checks.subprocess, 'run', return_value=process):
            observed = checks.backend_startup_categories()
        self.assertTrue(observed['flags']['APPLICATION_START_FAILED'])
        self.assertTrue(observed['flags']['BEAN_CREATION_FAILED'])
        self.assertFalse(observed['flags']['OUT_OF_MEMORY'])
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_timeout_always_emits_safe_failure_artifact(self):
        services = {name: {'ready': False, 'httpStatus': 503, 'result': 'HTTP_ERROR'} for name in ('agent', 'backend', 'frontend')}
        with patch.object(checks, 'readiness_probes', return_value=services), patch.object(checks, 'compose_states', return_value={}), patch.object(checks, 'backend_startup_categories', return_value={}), patch.object(checks, 'emit') as emitted, contextlib.redirect_stdout(io.StringIO()), self.assertRaises(TimeoutError):
            checks.ready(timeout=0)
        self.assertEqual(emitted.call_args.args[0], 'compose-readiness.json')
        self.assertEqual(emitted.call_args.args[1]['status'], 'TIMEOUT')
        self.assertEqual(set(emitted.call_args.args[1]['services']), {'agent', 'backend', 'frontend'})

    def test_success_requires_all_services_and_emits_pass(self):
        services = {name: {'ready': True, 'httpStatus': 200, 'result': 'READY'} for name in ('agent', 'backend', 'frontend')}
        with patch.object(checks, 'readiness_probes', return_value=services), patch.object(checks, 'compose_states', return_value={}), patch.object(checks, 'emit') as emitted, contextlib.redirect_stdout(io.StringIO()):
            checks.ready(timeout=0)
        self.assertEqual(emitted.call_args.args[1]['status'], 'PASS')

    def test_missing_docker_still_emits_diagnostic_artifact(self):
        with patch.object(checks.subprocess, 'run', side_effect=FileNotFoundError('PRIVATE_PAYLOAD_SENTINEL')), patch.object(checks.HTTP, 'open', side_effect=OSError('PRIVATE_PAYLOAD_SENTINEL')), patch.object(checks, 'emit') as emitted, contextlib.redirect_stdout(io.StringIO()):
            checks.diagnostics()
        self.assertEqual(emitted.call_args.args[0], 'compose-diagnostics.json')
        report = emitted.call_args.args[1]
        self.assertEqual(report['status'], 'OBSERVATION_ONLY')
        self.assertFalse(any(row['ready'] for row in report['services'].values()))
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(report))

    def test_bindings_observe_actual_mapping_not_requested_config(self):
        found = SimpleNamespace(returncode=0, stdout=b'a' * 64, stderr=b'')
        missing = self.process({'8080/tcp': None, 'PRIVATE_PAYLOAD_SENTINEL': 'ignored'})
        present = self.process({'8081/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5173'}]})
        with patch.object(checks.subprocess, 'run', side_effect=[found, missing, found, present]) as invoked:
            observed = checks.published_bindings()
        self.assertFalse(observed['backend']['published'])
        self.assertTrue(observed['backend']['collected'])
        self.assertTrue(observed['frontend']['published'])
        self.assertTrue(observed['frontend']['loopbackOnly'])
        self.assertTrue(observed['frontend']['expectedHostPort'])
        self.assertIn('{{json .NetworkSettings.Ports}}', invoked.call_args_list[1].args[0])
        self.assertEqual(invoked.call_args_list[0].args[0][-1], 'ingress')
        self.assertEqual(invoked.call_args_list[2].args[0][-1], 'ingress')
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_nonloopback_or_wrong_port_are_visible_without_raw_addresses(self):
        found = SimpleNamespace(returncode=0, stdout=b'a' * 64, stderr=b'')
        wrong = self.process({'8080/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '9000'}]})
        with patch.object(checks.subprocess, 'run', side_effect=[found, wrong, found, wrong]):
            observed = checks.published_bindings()
        self.assertTrue(observed['backend']['published'])
        self.assertFalse(observed['backend']['loopbackOnly'])
        self.assertFalse(observed['backend']['expectedHostPort'])
        self.assertNotIn('0.0.0.0', json.dumps(observed))

    def test_internal_http_only_projects_fixed_readiness(self):
        backend = SimpleNamespace(returncode=0, stdout=b'HTTP/1.1 200 OK\r\nX-Debug: PRIVATE_PAYLOAD_SENTINEL\r\n\r\n{"status":"UP"}', stderr=b'')
        frontend = SimpleNamespace(returncode=0, stdout=b'<div id="root">PRIVATE_PAYLOAD_SENTINEL</div>', stderr=b'')
        with patch.object(checks.subprocess, 'run', side_effect=[backend, frontend]):
            observed = checks.internal_http_probes()
        self.assertTrue(all(row['ready'] for row in observed.values()))
        self.assertNotIn('PRIVATE_PAYLOAD_SENTINEL', json.dumps(observed))

    def test_internal_success_never_replaces_failed_host_gate(self):
        services = {name: {'ready': False, 'httpStatus': None, 'result': 'PROBE_ERROR'} for name in ('agent', 'backend', 'frontend')}
        with patch.object(checks, 'readiness_probes', return_value=services), patch.object(checks, 'internal_http_probes', return_value={'backend': {'ready': True}, 'frontend': {'ready': True}}), patch.object(checks, 'compose_states', return_value={}), patch.object(checks, 'backend_startup_categories', return_value={}), patch.object(checks, 'emit'), contextlib.redirect_stdout(io.StringIO()), self.assertRaises(TimeoutError):
            checks.ready(timeout=0)

    def test_workflow_always_diagnoses_before_cleanup(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        self.assertIn('if: always()\n        run: python scripts/ci-verify.py diagnostics', workflow)
        self.assertLess(workflow.index('run: python scripts/ci-verify.py diagnostics'), workflow.index('--label compose-cleanup'))


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
