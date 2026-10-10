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
runner = module('ci-run')
diagnostics = module('ci-diagnostics')


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


class EvidenceFailureDiagnosticTest(unittest.TestCase):
    def test_only_fixed_stage_and_numeric_http_status_survive(self):
        marker = 'PRIVATE_RESPONSE_HEADER_URL_AND_EXCEPTION_SENTINEL'
        error = RuntimeError(marker)
        error.response = SimpleNamespace(status_code=429, text=marker, headers={'private': marker})
        error.request = SimpleNamespace(url=marker, headers={'Authorization': marker})
        result = checks.evidence_failure_summary('EXECUTE_REPLAY', error)
        self.assertEqual(result, {'status': 'FAIL', 'stage': 'EXECUTE_REPLAY', 'httpStatus': 429})
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(checks.evidence_failure_summary(marker, error)['stage'], 'UNKNOWN')

    def test_invalid_status_and_non_http_failure_are_not_exposed(self):
        error = RuntimeError('PRIVATE_SENTINEL')
        self.assertIsNone(checks.evidence_failure_summary('NORMALIZE_REPORT', error)['httpStatus'])
        for status in ('429', 'PRIVATE_SENTINEL', True, 99, 600, None):
            error.response = SimpleNamespace(status_code=status)
            self.assertEqual(checks.evidence_failure_summary('EXPORT_EVIDENCE', error),
                             {'status': 'FAIL', 'stage': 'EXPORT_EVIDENCE', 'httpStatus': None})


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


class ComposeFailureSignalsTest(unittest.TestCase):
    def observe(self, raw):
        with tempfile.TemporaryFile() as diagnostic:
            diagnostic.write(raw)
            return runner.compose_diagnostic_signals(diagnostic)

    def test_fixed_signals_cover_precontainer_failures(self):
        cases = {
            'DAEMON_UNAVAILABLE': b'Cannot connect to the Docker daemon at unix:///private/socket',
            'CONFIGURATION_INVALID': b'error while interpolating services.backend: required variable PRIVATE is missing a value',
            'IMAGE_FETCH_FAILED': b'failed to resolve source metadata for registry.invalid/private/image',
            'BUILD_FAILED': b'failed to solve: private build details',
            'STORAGE_EXHAUSTED': b'no space left on device',
            'RESOURCE_EXHAUSTED': b'cannot allocate memory',
            'PORT_BIND_FAILED': b'failed to bind host port 127.0.0.1:8080',
            'CONTAINER_NOT_READY': b'container private-container is unhealthy',
            'ACCESS_DENIED': b'permission denied: /private/path',
            'NETWORK_FAILED': b'certificate signed by unknown authority',
        }
        for expected, raw in cases.items():
            with self.subTest(expected=expected):
                result = self.observe(raw)
                self.assertTrue(result['signals'][expected])
                self.assertFalse(result['unclassified'])
                self.assertFalse(result['scanTruncated'])
                self.assertEqual(set(result['signals']), set(runner.COMPOSE_SIGNALS))
                self.assertTrue(all(type(v) is bool for v in result['signals'].values()))

    def test_unknown_and_empty_bodies_remain_unclassified(self):
        for raw in (b'', b'Unrecognized private error'):
            result = self.observe(raw)
            self.assertTrue(result['unclassified'])
            self.assertFalse(any(result['signals'].values()))

    def test_adversarial_body_cannot_reflect_secrets_or_inject_fields(self):
        marker = b'PRIVATE_DIAGNOSTIC_SENTINEL'
        raw = (b'permission denied: /' + marker + b'\nBearer ' + marker +
               b'\n::error::' + marker + b'\n{"status":"PASS","leaked":"' + marker +
               b'"}\n\x1b[31m' + marker)
        result = self.observe(raw)
        rendered = json.dumps(result)
        self.assertNotIn(marker.decode(), rendered)
        self.assertNotIn('status', result)
        self.assertNotIn('leaked', result)
        self.assertEqual(set(result), {'signals', 'unclassified', 'scanTruncated', 'registry'})
        self.assertTrue(result['signals']['ACCESS_DENIED'])

    def test_bounded_scan_includes_tail_and_marks_omitted_middle(self):
        raw = b'x' * (3 * runner.DIAGNOSTIC_BYTES) + b' no space left on device'
        result = self.observe(raw)
        self.assertTrue(result['signals']['STORAGE_EXHAUSTED'])
        self.assertTrue(result['scanTruncated'])
        middle = b'x' * runner.DIAGNOSTIC_BYTES + b' permission denied ' + b'x' * runner.DIAGNOSTIC_BYTES
        result = self.observe(middle)
        self.assertTrue(result['scanTruncated'])
        self.assertTrue(result['unclassified'])

    def invoke(self, command, code, raw):
        def fake_run(args, stdout, stderr):
            stdout.write(raw)
            return SimpleNamespace(returncode=code)
        output = io.StringIO()
        with patch.object(runner.sys, 'argv', ['ci-run.py', '--label', 'compose-up', '--'] + command), \
                patch.object(runner.subprocess, 'run', side_effect=fake_run), \
                contextlib.redirect_stdout(output):
            result = runner.main()
        return result, output.getvalue()

    def test_wrapper_preserves_failure_exit_and_never_prints_body(self):
        for code, expected in ((1, 1), (17, 17), (-9, 137)):
            result, output = self.invoke(['docker', 'compose', 'up'], code,
                                        b'Cannot connect to the Docker daemon PRIVATE_DIAGNOSTIC_SENTINEL')
            self.assertEqual(result, expected)
            self.assertIn('compose-failure-observation:', output)
            self.assertIn('FAIL', output)
            self.assertNotIn('PRIVATE_DIAGNOSTIC_SENTINEL', output)

    def test_success_and_noncompose_failures_do_not_publish_signals(self):
        for command, code in ((['docker', 'compose', 'up'], 0), (['private-command'], 1)):
            result, output = self.invoke(command, code, b'permission denied PRIVATE_DIAGNOSTIC_SENTINEL')
            self.assertEqual(result, code)
            self.assertNotIn('compose-failure-observation:', output)
            self.assertNotIn('PRIVATE_DIAGNOSTIC_SENTINEL', output)


class RegistryDiagnosticsTest(unittest.TestCase):
    def observe(self, raw, *, truncated=False, flags=None, images=None):
        return runner.registry_observation([raw], truncated, flags or {},
                                           runner.BASE_IMAGES if images is None else images)

    def test_known_transient_statuses_are_numeric_and_observation_only(self):
        for code, reason in ((429, 'Too Many Requests'), (500, 'Internal Server Error'),
                             (502, 'Bad Gateway'), (503, 'Service Unavailable'), (504, 'Gateway Timeout')):
            raw = (f'failed to solve: node:24-alpine: failed to resolve source metadata: '
                   f'unexpected status from HEAD request to https://private.invalid/v2/library/node/manifests/24-alpine: {code} {reason}').encode()
            result = self.observe(raw)
            self.assertEqual(result['httpStatuses'], [code])
            self.assertTrue(result['transientOnlyObserved'])
            self.assertFalse(result['automaticRetry'])
            self.assertEqual(result['baseImageIds'], ['NODE_BUILD'])
            self.assertNotIn('private.invalid', json.dumps(result))

    def test_denial_codes_and_missing_image_override_transient_statuses(self):
        for code, reason in ((401, 'Unauthorized'), (403, 'Forbidden'), (404, 'Not Found')):
            raw = f'failed to fetch oauth token: unexpected status: {code} {reason}\nHTTP status: 503 Service Unavailable'.encode()
            result = self.observe(raw)
            self.assertEqual(result['httpStatuses'], [code, 503])
            self.assertTrue(result['knownAccessOrImageDenial'])
            self.assertFalse(result['transientOnlyObserved'])
        for phrase in ('pull access denied', 'repository does not exist', 'manifest unknown',
                       'unauthorized: authentication required', 'insufficient_scope'):
            result = self.observe(('HTTP status: 429 Too Many Requests\n' + phrase).encode())
            self.assertTrue(result['knownAccessOrImageDenial'])
            self.assertFalse(result['transientOnlyObserved'])

    def test_unknown_or_nontransient_codes_never_allow_retry_classification(self):
        for raw in (b'', b'private body 429', b'port 503', b'image:500', b'HTTP status: 503PRIVATE',
                    b'HTTP status: 5030', b'build completed 200', b'HTTP status: 501 Not Implemented',
                    b'HTTP status: 418', b'failed to solve: node:24-alpine'):
            self.assertFalse(self.observe(raw)['transientOnlyObserved'])
        self.assertEqual(self.observe(b'HTTP status: 503PRIVATE')['httpStatuses'], [])

    def test_status_tokens_require_whitespace_or_end_and_nonword_prefix(self):
        for raw in (b'HTTP status: 503.5', b'HTTP status: 503/PRIVATE_MARKER',
                    b'failed to solve: PRIVATE503 Service Unavailable'):
            result = self.observe(raw)
            self.assertEqual(result['httpStatuses'], [])
            self.assertFalse(result['transientOnlyObserved'])
            self.assertNotIn('PRIVATE_MARKER', json.dumps(result))

    def test_truncation_overlong_lines_and_conflicting_errors_fail_closed(self):
        raw = b'HTTP status: 503 Service Unavailable'
        self.assertFalse(self.observe(raw, truncated=True)['transientOnlyObserved'])
        long_result = self.observe(raw + b'\n' + b'x' * 9000)
        self.assertFalse(long_result['transientOnlyObserved'])
        self.assertTrue(long_result['statusScanIncomplete'])
        for key in ('ACCESS_DENIED', 'CONFIGURATION_INVALID', 'CLI_INVALID', 'YAML_INVALID',
                    'ENV_FILE_INVALID', 'DEPENDENCY_MISSING', 'STORAGE_EXHAUSTED', 'PORT_BIND_FAILED',
                    'DAEMON_UNAVAILABLE', 'RESOURCE_EXHAUSTED', 'NETWORK_FAILED',
                    'TRANSPORT_INTERRUPTED', 'CONTAINER_NOT_READY'):
            self.assertFalse(self.observe(raw, flags={key: True})['transientOnlyObserved'])

    def test_additional_ambiguous_status_context_prevents_transient_inference(self):
        for suffix in (b'\nfailed to solve: unexpected status PRIVATE_MARKER',
                       b' unexpected status PRIVATE_MARKER', b'\nHTTP status: 503PRIVATE_MARKER'):
            result = self.observe(b'HTTP status: 503 Service Unavailable' + suffix)
            self.assertEqual(result['httpStatuses'], [503])
            self.assertTrue(result['statusScanIncomplete'])
            self.assertFalse(result['transientOnlyObserved'])

    def test_head_tail_boundary_cannot_hide_partial_denial(self):
        prefix = b'HTTP status: 503 Service Unavailable\n'
        raw = prefix + b'x' * (runner.DIAGNOSTIC_BYTES - len(prefix) - 4) + b'unau' + b'thorized: PRIVATE_MARKER'
        with tempfile.TemporaryFile() as private:
            private.write(raw)
            result = runner.compose_diagnostic_signals(private)
        self.assertFalse(result['scanTruncated'])
        self.assertTrue(result['registry']['statusScanIncomplete'])
        self.assertFalse(result['registry']['transientOnlyObserved'])

    def test_images_require_actual_reviewed_from_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'frontend').mkdir()
            (root / 'frontend/Dockerfile').write_text('FROM node:24-alpine AS build\nFROM private.invalid/PRIVATE_MARKER:latest\n')
            (root / 'agent').mkdir()
            (root / 'agent/Dockerfile').write_text('FROM ${PRIVATE_MARKER}\n')
            images = runner.project_base_images(root)
            self.assertEqual(images, {'node:24-alpine': 'NODE_BUILD'})
            result = self.observe(b'failed to solve: python:3.12.15-slim HTTP status: 503', images=images)
            self.assertEqual(result['baseImageIds'], [])
            (root / 'frontend/Dockerfile').unlink()
            (root / 'frontend/Dockerfile').symlink_to(root / 'agent/Dockerfile')
            self.assertEqual(runner.project_base_images(root), {})

    def test_image_identity_does_not_reflect_arbitrary_paths_hosts_or_values(self):
        raw = (b'failed to resolve source metadata for docker.io/library/node:24-alpine: HTTP status: 503\n'
               b'failed to solve private.invalid/PRIVATE_MARKER HTTP status: 503\n'
               b'Bearer PRIVATE_MARKER\n::error::PRIVATE_MARKER\n{"httpStatuses":[200],"leak":"PRIVATE_MARKER"}')
        result = self.observe(raw)
        self.assertEqual(result['baseImageIds'], ['NODE_BUILD'])
        self.assertNotIn('PRIVATE_MARKER', json.dumps(result))
        self.assertNotIn('private.invalid', json.dumps(result))
        injected = self.observe(raw, images={'node:24-alpine': 'PRIVATE_MARKER'})
        self.assertEqual(injected['baseImageIds'], [])
        self.assertNotIn('PRIVATE_MARKER', json.dumps(injected))

    def test_image_token_boundaries_do_not_match_longer_private_tags(self):
        result = self.observe(b'failed to solve: node:24-alpine-PRIVATE_MARKER HTTP status: 503')
        self.assertEqual(result['baseImageIds'], [])
        result = self.observe(b'failed to do request: https://private.invalid/v2/library/node/manifests/24-alpine: 503 Service Unavailable')
        self.assertEqual(result['baseImageIds'], ['NODE_BUILD'])
        result = self.observe(b'failed to do request: https://private.invalid/v2/library/node/manifests/24-alpine HTTP status: 503')
        self.assertEqual(result['baseImageIds'], ['NODE_BUILD'])


class StructuredDiagnosticsTest(unittest.TestCase):
    FRONTEND_TEST_FILES = (
        'frontend/src/App.test.tsx', 'frontend/src/ApprovalHistory.test.tsx',
        'frontend/src/EvidenceTimeStatus.test.tsx',
        'frontend/src/LiveExperiments.test.tsx',
        'frontend/src/Operations.test.tsx', 'frontend/src/PotentialImpact.test.tsx',
        'frontend/src/api.test.ts', 'frontend/src/browserSecurity.test.tsx',
        'frontend/src/experimentExport.test.tsx', 'frontend/src/format.test.ts',
        'frontend/src/hooks.test.tsx', 'frontend/src/safeReporter.test.ts',
    )
    SOURCE_LINES = 20

    def setUp(self):
        # Tooling-only branches do not contain the feature's frontend sources.
        # Exercise real source-line validation against synthetic files instead.
        directory = tempfile.TemporaryDirectory(prefix='fuse-test-sources-')
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for filename in self.FRONTEND_TEST_FILES:
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('// synthetic test source\n' * self.SOURCE_LINES)
        root_patch = patch.object(diagnostics, 'ROOT', root)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def report(self, status='passed'):
        return {'success': status == 'passed', 'numTotalTests': 1,
                'numPassedTests': int(status == 'passed'), 'numFailedTests': int(status == 'failed'),
                'numPendingTests': 0, 'numTodoTests': 0,
                'testResults': [{'name': str(diagnostics.ROOT / 'frontend/src/api.test.ts'),
                                 'status': status, 'message': '', 'assertionResults': [{
                                     'status': status, 'title': 'PRIVATE_MARKER',
                                     'fullName': 'PRIVATE_MARKER', 'meta': {'leak': 'PRIVATE_MARKER'},
                                     'location': {'line': 15, 'file': '/private/PRIVATE_MARKER'},
                                     'failureMessages': ['AssertionError PRIVATE_MARKER'],
                                 }]}]}

    def test_versions_never_reflect_suffix_or_unstructured_output(self):
        self.assertEqual(diagnostics.numeric_version('v2.40.3-desktop.1'), '2.40.3')
        self.assertEqual(diagnostics.numeric_version('28.5.1+PRIVATE_MARKER'), '28.5.1')
        for value in (None, True, {'Version': '28.5.1'}, 'PRIVATE_MARKER',
                      '28.5.1\nPRIVATE_MARKER', 'version 28.5.1', '28.5.1/private'):
            self.assertIsNone(diagnostics.numeric_version(value))

    def test_success_frontend_counts_are_observed_not_assumed(self):
        result = diagnostics.frontend_summary(self.report(), 0)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['counts'], {'total': 1, 'passed': 1, 'failed': 0, 'skipped': 0, 'todo': 0})
        self.assertNotIn('PRIVATE_MARKER', json.dumps(result))

    def test_potential_impact_report_joins_all_reviewed_frontend_suites(self):
        files = self.FRONTEND_TEST_FILES
        report = self.report()
        report['testResults'] = []
        for filename in files:
            suite = self.report()['testResults'][0]
            suite['name'] = str(diagnostics.ROOT / filename)
            report['testResults'].append(suite)
        report['numTotalTests'] = report['numPassedTests'] = len(files)
        result, summary = self.frontend_invoke(report, 0)
        self.assertEqual(result, 0)
        self.assertEqual(summary['reportState'], 'PARSED')
        self.assertEqual(summary['status'], 'PASS')
        self.assertEqual(summary['files'], 12)
        self.assertEqual(summary['counts'], {'total': 12, 'passed': 12, 'failed': 0, 'skipped': 0, 'todo': 0})
        self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_approval_history_exact_paths_preserve_counts_and_redaction(self):
        filename = 'frontend/src/ApprovalHistory.test.tsx'
        for path in (filename, str(diagnostics.ROOT / filename)):
            for status, exit_code in (('passed', 0), ('failed', 1)):
                with self.subTest(path=path, status=status):
                    report = self.report(status)
                    report['testResults'][0]['name'] = path
                    result, summary = self.frontend_invoke(report, exit_code)
                    self.assertEqual(result, exit_code)
                    self.assertEqual(summary['reportState'], 'PARSED')
                    self.assertEqual(summary['status'], 'PASS' if status == 'passed' else 'FAIL')
                    self.assertEqual(summary['counts'], {
                        'total': 1, 'passed': int(status == 'passed'),
                        'failed': int(status == 'failed'), 'skipped': 0, 'todo': 0})
                    self.assertEqual(summary['failedTests'], [] if status == 'passed' else [{
                        'file': filename, 'testOrdinal': 1, 'line': 15, 'code': 'ASSERTION_FAILED',
                    }])
                    self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_approval_history_allowlist_rejects_lookalikes(self):
        for filename in ('frontend/src/ApprovalHistory.test.tsx.private',
                         'frontend/src/ApprovalHistoryExtra.test.tsx',
                         'frontend/src/ApprovalHistory.test.tsx/../PRIVATE_MARKER',
                         '/private/ApprovalHistory.test.tsx',
                         'frontend/src/approvalhistory.test.tsx'):
            with self.subTest(filename=filename):
                report = self.report()
                report['testResults'][0]['name'] = filename
                result, summary = self.frontend_invoke(report, 0)
                self.assertEqual(result, 1)
                self.assertEqual(summary['reportState'], 'INVALID')
                self.assertEqual(summary['status'], 'FAIL')
                self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_evidence_time_status_exact_paths_preserve_counts_and_redaction(self):
        filename = 'frontend/src/EvidenceTimeStatus.test.tsx'
        for path in (filename, str(diagnostics.ROOT / filename)):
            for status, exit_code in (('passed', 0), ('failed', 1)):
                with self.subTest(path=path, status=status):
                    report = self.report(status)
                    report['testResults'][0]['name'] = path
                    result, summary = self.frontend_invoke(report, exit_code)
                    self.assertEqual(result, exit_code)
                    self.assertEqual(summary['reportState'], 'PARSED')
                    self.assertEqual(summary['status'], 'PASS' if status == 'passed' else 'FAIL')
                    self.assertEqual(summary['counts'], {
                        'total': 1, 'passed': int(status == 'passed'),
                        'failed': int(status == 'failed'), 'skipped': 0, 'todo': 0})
                    self.assertEqual(summary['failedTests'], [] if status == 'passed' else [{
                        'file': filename, 'testOrdinal': 1, 'line': 15, 'code': 'ASSERTION_FAILED',
                    }])
                    self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_evidence_time_status_allowlist_rejects_lookalikes(self):
        for filename in ('frontend/src/EvidenceTimeStatus.test.tsx.private',
                         'frontend/src/EvidenceTimeStatusExtra.test.tsx',
                         'frontend/src/EvidenceTimeStatus.test.tsx/../PRIVATE_MARKER',
                         '/private/EvidenceTimeStatus.test.tsx',
                         'frontend/src/evidencetimestatus.test.tsx'):
            with self.subTest(filename=filename):
                report = self.report()
                report['testResults'][0]['name'] = filename
                result, summary = self.frontend_invoke(report, 0)
                self.assertEqual(result, 1)
                self.assertEqual(summary['reportState'], 'INVALID')
                self.assertEqual(summary['status'], 'FAIL')
                self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_potential_impact_failure_preserves_redacted_source_location(self):
        report = self.report('failed')
        report['testResults'][0]['name'] = 'frontend/src/PotentialImpact.test.tsx'
        result, summary = self.frontend_invoke(report, 1)
        self.assertEqual(result, 1)
        self.assertEqual(summary['reportState'], 'PARSED')
        self.assertEqual(summary['status'], 'FAIL')
        self.assertEqual(summary['failedTests'], [{
            'file': 'frontend/src/PotentialImpact.test.tsx',
            'testOrdinal': 1, 'line': 15, 'code': 'ASSERTION_FAILED',
        }])
        self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_potential_impact_allowlist_does_not_admit_lookalike_paths(self):
        for filename in ('frontend/src/PotentialImpact.test.tsx.private',
                         'frontend/src/PotentialImpactExtra.test.tsx',
                         'frontend/src/PotentialImpact.test.tsx/../PRIVATE_MARKER'):
            report = self.report()
            report['testResults'][0]['name'] = filename
            result, summary = self.frontend_invoke(report, 0)
            self.assertEqual(result, 1)
            self.assertEqual(summary['reportState'], 'INVALID')
            self.assertEqual(summary['status'], 'FAIL')
            self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_suite_count_remains_bounded_by_explicit_allowlist(self):
        report = self.report()
        report['testResults'] *= len(diagnostics.TEST_FILES) + 1
        with self.assertRaisesRegex(ValueError, 'Invalid suite list'):
            diagnostics.frontend_summary(report, 0)

    def test_failure_only_emits_allowlisted_file_line_and_fixed_code(self):
        result = diagnostics.frontend_summary(self.report('failed'), 1)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['failedTests'], [{'file': 'frontend/src/api.test.ts',
                         'testOrdinal': 1, 'line': 15, 'code': 'ASSERTION_FAILED'}])
        self.assertNotIn('PRIVATE_MARKER', json.dumps(result))
        self.assertNotIn('"title":', json.dumps(result))

    def test_untrusted_paths_and_duplicate_suites_fail_closed(self):
        for path in ('/private/PRIVATE_MARKER.test.ts', 'frontend/src/../../PRIVATE_MARKER',
                     'frontend/src/api.test.ts\nPRIVATE_MARKER', 'frontend/src/new.test.ts'):
            report = self.report()
            report['testResults'][0]['name'] = path
            with self.assertRaises(ValueError):
                diagnostics.frontend_summary(report, 0)
        report = self.report()
        report['testResults'].append(report['testResults'][0])
        with self.assertRaises(ValueError):
            diagnostics.frontend_summary(report, 0)

    def test_invalid_lines_are_not_reflected(self):
        for line in (-1, 0, True, 'PRIVATE_MARKER', 10000000):
            report = self.report('failed')
            report['testResults'][0]['assertionResults'][0]['location']['line'] = line
            result = diagnostics.frontend_summary(report, 1)
            self.assertIsNone(result['failedTests'][0]['line'])
            self.assertNotIn('PRIVATE_MARKER', json.dumps(result))

    def test_failure_lines_are_bounded_by_actual_source_length(self):
        for line, expected in ((1, 1), (self.SOURCE_LINES, self.SOURCE_LINES),
                               (self.SOURCE_LINES + 1, None)):
            with self.subTest(line=line):
                report = self.report('failed')
                report['testResults'][0]['assertionResults'][0]['location']['line'] = line
                result, summary = self.frontend_invoke(report, 1)
                self.assertEqual(result, 1)
                self.assertEqual(summary['reportState'], 'PARSED')
                self.assertEqual(summary['failedTests'][0]['line'], expected)
                self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_allowlisted_but_missing_source_remains_fail_closed(self):
        for filename in ('frontend/src/api.test.ts', 'frontend/src/PotentialImpact.test.tsx',
                         'frontend/src/ApprovalHistory.test.tsx',
                         'frontend/src/EvidenceTimeStatus.test.tsx'):
            with self.subTest(filename=filename):
                (diagnostics.ROOT / filename).unlink()
                report = self.report()
                report['testResults'][0]['name'] = filename
                with self.assertRaises(OSError):
                    diagnostics.frontend_summary(report, 0)
                result, summary = self.frontend_invoke(report, 0)
                self.assertEqual(result, 1)
                self.assertEqual(summary['reportState'], 'INVALID')
                self.assertEqual(summary['status'], 'FAIL')
                self.assertNotIn('PRIVATE_MARKER', json.dumps(summary))

    def test_inconsistent_counts_unknown_status_and_empty_reports_fail(self):
        for key, value in (('numTotalTests', 2), ('numPassedTests', True), ('numFailedTests', -1)):
            report = self.report()
            report[key] = value
            with self.assertRaises(ValueError):
                diagnostics.frontend_summary(report, 0)
        report = self.report()
        report['testResults'][0]['assertionResults'][0]['status'] = 'PRIVATE_MARKER'
        with self.assertRaises(ValueError):
            diagnostics.frontend_summary(report, 0)
        with self.assertRaises(ValueError):
            diagnostics.frontend_summary({}, 0)

    def test_nonzero_exit_cannot_become_passing_report(self):
        for code in (1, 17, None):
            self.assertEqual(diagnostics.frontend_summary(self.report(), code)['status'], 'FAIL')

    def test_failure_code_is_closed_vocabulary_without_error_reflection(self):
        for raw, code in [('Test timed out PRIVATE_MARKER', 'TIMEOUT'),
                          ('Unhandled rejection PRIVATE_MARKER', 'UNHANDLED_ERROR'),
                          ('expected PRIVATE_MARKER to match', 'ASSERTION_FAILED'),
                          ('PRIVATE_MARKER', 'UNKNOWN')]:
            self.assertEqual(diagnostics.failure_code([raw]), code)
        self.assertEqual(diagnostics.failure_code([{'message': 'PRIVATE_MARKER'}]), 'UNKNOWN')

    def frontend_invoke(self, report, code, missing=False):
        paths = []
        def fake_capture(command, **kwargs):
            self.assertEqual(command[:7], ['npm', '--prefix', 'frontend', 'test', '--', '--run', '--includeTaskLocation'])
            self.assertIn('--reporter=json', command)
            path = Path(command[-1].split('=', 1)[1])
            paths.append(path)
            if not missing:
                path.write_text(json.dumps(report))
            return {'exitCode': code}, b'PRIVATE_MARKER'
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, patch.object(diagnostics, 'SAFE', Path(directory)), \
                patch.object(diagnostics, 'captured', side_effect=fake_capture), contextlib.redirect_stdout(output):
            result = diagnostics.frontend_tests()
            artifact = json.loads((Path(directory) / 'frontend-test-summary.json').read_text())
        self.assertTrue(all(not path.exists() for path in paths))
        self.assertNotIn('PRIVATE_MARKER', output.getvalue())
        return result, artifact

    def test_private_json_report_is_removed_after_success_or_failure(self):
        self.assertEqual(self.frontend_invoke(self.report(), 0)[0], 0)
        result, summary = self.frontend_invoke(self.report('failed'), 7)
        self.assertEqual(result, 7)
        self.assertEqual(summary['status'], 'FAIL')

    def test_missing_and_malformed_private_reports_remain_failures(self):
        for report, missing, expected in (({}, False, 'INVALID'), ({}, True, 'MISSING')):
            result, summary = self.frontend_invoke(report, 0, missing)
            self.assertEqual(result, 1)
            self.assertEqual(summary['reportState'], expected)

    def test_preflight_is_read_only_and_all_checks_are_required(self):
        for failure in (None, 0, 1, 2):
            commands = []
            def fake_capture(command, **kwargs):
                index = len(commands)
                commands.append(command)
                raw = [json.dumps({'Client': {'Version': '28.5.1'}, 'Server': {'Version': '28.5.1'},
                                   'private': 'PRIVATE_MARKER'}).encode(), b'v2.40.3', b'PRIVATE_MARKER'][index]
                meta = {'exitCode': int(index == failure), 'invocation': 'COMPLETED',
                        'signals': {'unclassified': True, 'scanTruncated': False, 'signals': {}}}
                return meta, raw
            output = io.StringIO()
            with tempfile.TemporaryDirectory() as directory, patch.object(diagnostics, 'SAFE', Path(directory)), \
                    patch.object(diagnostics, 'captured', side_effect=fake_capture), contextlib.redirect_stdout(output):
                result = diagnostics.compose_preflight()
                self.assertEqual(result, int(failure is not None))
            self.assertEqual(commands, [['docker', 'version', '--format', '{{json .}}'],
                                       ['docker', 'compose', 'version', '--short'],
                                       ['docker', 'compose', 'config', '--quiet']])
            self.assertNotIn('PRIVATE_MARKER', output.getvalue())

    def test_new_compose_categories_do_not_echo_diagnostic_bodies(self):
        cases = {'CLI_INVALID': b'unknown flag: PRIVATE_MARKER',
                 'YAML_INVALID': b'yaml: PRIVATE_MARKER',
                 'ENV_FILE_INVALID': b'env file /private/PRIVATE_MARKER not found',
                 'DEPENDENCY_MISSING': b'executable file not found PRIVATE_MARKER',
                 'TRANSPORT_INTERRUPTED': b'unexpected EOF PRIVATE_MARKER',
                 'REGISTRY_HTTP_REJECTED': b'503 Service Unavailable PRIVATE_MARKER'}
        for key, raw in cases.items():
            with tempfile.TemporaryFile() as private:
                private.write(raw)
                result = runner.compose_diagnostic_signals(private)
            self.assertTrue(result['signals'][key])
            self.assertNotIn('PRIVATE_MARKER', json.dumps(result))

    def test_workflow_preserves_build_start_once_and_existing_timeouts(self):
        # Workflow checks must inspect the checkout, not the synthetic source root.
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        self.assertEqual(workflow.count('run: python scripts/ci-verify.py prepare'), 1)
        self.assertEqual(workflow.count('-- docker compose build'), 1)
        self.assertEqual(workflow.count('-- docker compose up --no-build --detach --wait --wait-timeout 240'), 1)
        self.assertIn('timeout-minutes: 40', workflow)
        self.assertIn('timeout-minutes: 10', workflow)
        self.assertIn('path: safe-artifacts/frontend-test-summary.json', workflow)
        self.assertNotIn('report.json\n', workflow)
        self.assertNotIn('continue-on-error:', workflow)


class TerminalPrivacyWorkflowTests(unittest.TestCase):
    def test_terminal_privacy_keeps_prior_checks_and_always_cleanup(self):
        workflow = (diagnostics.ROOT / '.github/workflows/ci.yml').read_text()
        terminal = 'run: python scripts/runtime-log-privacy-check.py'
        self.assertEqual(workflow.count(terminal), 1)
        before, after = workflow.split(terminal)
        for gate in ('run: python scripts/ci-verify.py evidence',
                     'run: python scripts/ci-verify.py diagnostics',
                     'run: python scripts/ci-verify.py database',
                     'run: npm run test:e2e'):
            self.assertIn(gate, before)
        self.assertIn("Always remove only this run's Compose containers and volumes\n        if: always()", after)
        self.assertIn('--project-name "$COMPOSE_PROJECT_NAME" down --volumes --remove-orphans', after)
        self.assertNotIn('continue-on-error:', workflow)
        self.assertIn('run: python scripts/runtime-log-privacy-test.py', workflow)
        self.assertIn('run: python scripts/ci-test-report-test.py', workflow)


if __name__ == '__main__':
    unittest.main()
