#!/usr/bin/env python3
"""Service-free synthetic parsing, ownership and handoff tests. No Java or Docker."""
import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


auth = load('ci-auth-bootstrap')
checks = load('ci-verify')
PROJECT = 'fuse-ci-123-1'


def tokens():
    return {key: base64.urlsafe_b64encode(hashlib.sha256(('issued:' + key).encode()).digest()).decode().rstrip('=')
            for key, _ in auth.ACTORS}


def receipt():
    lines = ['# Fresh private bearer output. Keep private; hand off explicitly.',
             '# operation_id=00000000-0000-4000-8000-000000000001', '# status=PREPARED']
    for key, actor in auth.ACTORS:
        value = tokens()[key]
        lines.extend(['# actor=' + actor + ' fingerprint=' + auth.digest(value.encode()), key + '=' + value])
    return ('\n'.join(lines) + '\n\n# status=COMMITTED\n').encode()


def config_values(issued=False):
    values = {key: hashlib.sha256(key.encode()).hexdigest() for key, _ in auth.ACTORS}
    values.update({key: hashlib.sha256(key.encode()).hexdigest() for key in
                   ('FUSE_DB_PASSWORD', 'FUSE_DB_OWNER_PASSWORD', 'FUSE_EXPERIMENT_DB_PASSWORD')})
    values.update(FUSE_KYC_MODE='replay', FUSE_EXPERIMENT_LIVE_ENABLED='false',
                  FUSE_RUNTIME_UID=str(os.getuid()), FUSE_RUNTIME_GID=str(os.getgid()))
    if issued:
        values.update(tokens())
    return values


def configuration():
    values = config_values()
    backend = {key: values[key] for key, _ in auth.ACTORS}
    backend.update(FUSE_MIGRATE='false', FUSE_MIGRATION_USERNAME='', FUSE_MIGRATION_PASSWORD='',
        FUSE_DB_USERNAME='fuse_runtime', FUSE_DB_URL='jdbc:postgresql://postgres:5432/fuse',
        FUSE_DB_PASSWORD=values['FUSE_DB_PASSWORD'], FUSE_EXPERIMENT_DB_PASSWORD=values['FUSE_EXPERIMENT_DB_PASSWORD'],
        SPRING_PROFILES_ACTIVE='demo', FUSE_KYC_MODE='replay', FUSE_EXPERIMENT_LIVE_ENABLED='false',
        FUSE_REVIEWER_CUSTOMERS=auth.SCOPES, FUSE_SECURITY_CUSTOMERS=auth.SCOPES)
    memberships = {'postgres': ['data'], 'backend': ['web', 'data', 'kyc'],
                   'agent': ['kyc'], 'frontend': ['web'], 'ingress': ['ingress', 'web']}
    services = {name: {'networks': {n: None for n in networks}, 'environment': {}}
                for name, networks in memberships.items()}
    services['backend']['environment'] = backend
    services['agent']['environment'] = {'FUSE_KYC_MODE': 'replay', 'FUSE_SERVICE_TOKEN': values['FUSE_SERVICE_TOKEN']}
    services['postgres']['environment'] = {'POSTGRES_USER': 'fuse_owner', 'POSTGRES_DB': 'fuse',
        'POSTGRES_PASSWORD': values['FUSE_DB_OWNER_PASSWORD'], 'FUSE_DB_PASSWORD': values['FUSE_DB_PASSWORD'],
        'FUSE_EXPERIMENT_DB_PASSWORD': values['FUSE_EXPERIMENT_DB_PASSWORD']}
    services['postgres']['volumes'] = [
        {'type': 'volume', 'source': 'pgdata', 'target': '/var/lib/postgresql/data'},
        {'type': 'bind', 'source': str(auth.ROOT / 'scripts/init-postgres.sh'),
         'target': '/docker-entrypoint-initdb.d/10-fuse.sh', 'read_only': True}]
    return {'name': PROJECT, 'services': services,
            'networks': {name: {'name': PROJECT + '_' + name, 'driver': 'bridge', 'internal': name != 'ingress'}
                         for name in ('web', 'data', 'kyc', 'ingress')},
            'volumes': {'pgdata': {'name': PROJECT + '_pgdata'}}}


def docker_identity():
    identifier, network_id = 'a' * 64, 'b' * 64
    volume = {'Name': PROJECT + '_pgdata', 'Driver': 'local', 'Options': None,
              'Mountpoint': '/synthetic/volume', 'Labels': {'com.docker.compose.project': PROJECT,
                                                         'com.docker.compose.volume': 'pgdata'}}
    container = {'Id': identifier, 'Config': {'Image': 'postgres:16.15', 'Labels': {
        'com.docker.compose.project': PROJECT, 'com.docker.compose.service': 'postgres'}},
        'State': {'Status': 'running', 'Health': {'Status': 'healthy'}}, 'HostConfig': {'PortBindings': {}},
        'NetworkSettings': {'Networks': {PROJECT + '_data': {'IPAddress': '172.19.0.2', 'NetworkID': network_id}}},
        'Mounts': [{'Destination': '/var/lib/postgresql/data', 'Type': 'volume',
                    'Name': PROJECT + '_pgdata', 'Source': '/synthetic/volume'}]}
    network = {'Name': PROJECT + '_data', 'Id': network_id, 'Internal': True, 'Driver': 'bridge',
               'Labels': {'com.docker.compose.project': PROJECT},
               'Containers': {identifier: {'IPv4Address': '172.19.0.2/16'}}}
    return container, network, volume


class NoServices(unittest.TestCase):
    def setUp(self):
        # Any missing inner mock is a failure, never an accidental real operation.
        for name in ('run', 'Popen'):
            guard = patch.object(auth.subprocess, name, side_effect=AssertionError('No child processes in offline tests'))
            guard.start()
            self.addCleanup(guard.stop)


class ScopeTests(NoServices):
    def environment(self):
        return {'GITHUB_ACTIONS': 'true', 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1',
                'COMPOSE_PROJECT_NAME': PROJECT, 'COMPOSE_FILE': auth.COMPOSE_FILES,
                'GITHUB_WORKSPACE': str(auth.ROOT), 'GITHUB_SHA': 'a' * 40}

    def test_exact_ci_scope_and_nonroot_identity_required(self):
        with patch.object(auth.os, 'getuid', return_value=1001), patch.object(auth.os, 'getgid', return_value=1001):
            self.assertEqual(auth.project_scope(environment=self.environment()), PROJECT)
            for key, value in [('GITHUB_ACTIONS', 'false'), ('GITHUB_RUN_ATTEMPT', '2'),
                ('COMPOSE_PROJECT_NAME', 'fuse-ci-99-1'), ('COMPOSE_FILE', 'compose.dev.yaml'),
                ('COMPOSE_PROFILES', 'live'), ('DOCKER_HOST', 'tcp://other'), ('DOCKER_CONTEXT', 'remote'),
                ('FUSE_DB_PASSWORD', 'ambient'), ('SPRING_PROFILES_ACTIVE', 'test'),
                ('FUSE_UI_URL', 'http://external'), ('JAVA_TOOL_OPTIONS', '-javaagent:untrusted')]:
                with self.subTest(key=key), self.assertRaises(auth.Failure):
                    auth.project_scope(environment={**self.environment(), key: value})
        with patch.object(auth.os, 'getuid', return_value=0), self.assertRaises(auth.Failure):
            auth.project_scope(environment=self.environment())

    def test_child_environment_is_a_minimal_nonsecret_allowlist(self):
        env = {**self.environment(), 'PATH': '/synthetic/bin', 'HOME': '/synthetic/home',
               'OPENAI_API_KEY': 'private', 'AWS_SECRET_ACCESS_KEY': 'private', 'GH_TOKEN': 'private',
               'FUSE_DB_PASSWORD': 'private', 'GRADLE_OPTS': '-Dprivate', 'JAVA_TOOL_OPTIONS': 'private'}
        with patch.dict(os.environ, env, clear=True):
            result = auth.clean_process_environment()
        self.assertEqual(result, {key: env[key] for key in ('PATH', 'HOME', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')})

    def test_existing_resource_stops_before_any_mutating_command(self):
        for occupied in range(1, 9):
            commands = []
            def docker(*arguments):
                commands.append(arguments)
                return b'default\n' if len(commands) == 1 else b'existing\n' if len(commands) == occupied + 1 else b''
            with patch.object(auth, 'docker', side_effect=docker), self.assertRaises(auth.Failure):
                auth.require_fresh_project(PROJECT)
            self.assertFalse(any('up' in command or 'down' in command for command in commands))


class ManifestAndHandoffTests(NoServices):
    def fixture(self, root):
        (root / '.secrets').mkdir(mode=0o700)
        auth.private_create(root / '.env', ('\n'.join(key + '=' + value for key, value in config_values().items()) + '\n').encode())
        auth.private_create(root / '.secrets/signing.key', b'synthetic signing fixture only!!')
        for name in auth.SOURCES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic source only\n')

    def test_manifest_rejects_source_env_key_changes_and_second_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with patch.object(auth, 'project_scope', return_value=PROJECT), patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40}):
                auth.record_preparation(root)
                auth.verify_manifest(root, PROJECT)
                for path in (root / '.env', root / '.secrets/signing.key', root / auth.SOURCES[0]):
                    original = path.read_bytes()
                    path.write_bytes(original + b'changed')
                    with self.assertRaises(auth.Failure):
                        auth.verify_manifest(root, PROJECT)
                    path.write_bytes(original)
                added = root / 'backend/src/main/resources/db/migration/V999__unexpected.sql'
                added.write_text('synthetic extra migration')
                with self.assertRaises(auth.Failure):
                    auth.verify_manifest(root, PROJECT)
                added.unlink()
                auth.private_create(root / '.secrets/ci-auth-attempt.json', b'{}')
                with self.assertRaises(auth.Failure):
                    auth.verify_manifest(root, PROJECT)

    def test_handoff_changes_exactly_eight_assignments_preserves_key_and_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            before, key = auth.private_read(root / '.env'), auth.private_read(root / '.secrets/signing.key')
            auth.handoff(root, before, tokens())
            after = auth.private_read(root / '.env')
            self.assertEqual(auth.private_read(root / '.secrets/signing.key'), key)
            self.assertEqual(checks.credentials(root / '.env'), {**config_values(), **tokens()})
            for key, _ in auth.ACTORS:
                after = after.replace((key + '=' + tokens()[key]).encode(),
                                      (key + '=' + config_values()[key]).encode())
            self.assertEqual(after, before)
            self.assertFalse(list(root.glob('.ci-auth-handoff-*')))

    def test_handoff_rejects_changed_input_reuse_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            before = auth.private_read(root / '.env')
            with self.assertRaises(auth.Failure):
                auth.handoff(root, before + b'changed', tokens())
            with self.assertRaises(auth.Failure):
                auth.handoff(root, before, {key: config_values()[key] for key, _ in auth.ACTORS})
            (root / '.env').rename(root / 'retained')
            (root / '.env').symlink_to(root / 'retained')
            with self.assertRaises(OSError):
                auth.handoff(root, before, tokens())
            self.assertEqual((root / 'retained').read_bytes(), before)

    def test_private_inputs_reject_unsafe_mode_hardlink_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'synthetic'
            auth.private_create(path, b'synthetic fixture')
            path.chmod(0o644)
            with self.assertRaises(auth.Failure):
                auth.private_read(path)
            path.chmod(0o600)
            os.link(path, root / 'alias')
            with self.assertRaises(auth.Failure):
                auth.private_read(path)
            root.chmod(0o755)
            with self.assertRaises(auth.Failure):
                auth.private_directory(root)

    def test_cleanup_grant_is_bound_and_precedes_service_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.secrets').mkdir(mode=0o700)
            output = root / 'runner-output'
            output.touch()
            with patch.object(auth, 'ROOT', root), patch.dict(os.environ, {'GITHUB_SHA': 'a' * 40,
                    'RUNNER_TEMP': str(root), 'GITHUB_OUTPUT': str(output)}):
                auth.grant_cleanup(PROJECT)
                marker = json.loads(auth.private_read(root / '.secrets/ci-auth-attempt.json'))
                self.assertEqual(marker['project'], PROJECT)
                self.assertEqual(marker['head'], 'a' * 40)
                self.assertEqual(output.read_text(), 'owns_project=true\n')
                with self.assertRaises(FileExistsError):
                    auth.grant_cleanup(PROJECT)
        source = (auth.ROOT / 'scripts/ci-auth-bootstrap.py').read_text()
        body = source[source.index('def provision():'):]
        self.assertLess(body.index('require_fresh_project(project)'), body.index('grant_cleanup(project)'))
        self.assertLess(body.index('grant_cleanup(project)'), body.index("docker('compose', 'up'"))


class ReceiptAndFormatTests(NoServices):
    def test_receipt_requires_exact_committed_actors_fingerprints_and_fresh_format(self):
        self.assertEqual(auth.parse_receipt(receipt()), tokens())
        for raw in (receipt().replace(b'# status=COMMITTED', b'# status=PREPARED'), receipt() + b'EXTRA=value\n',
                    receipt().replace(b'actor=staff-01', b'actor=unknown'),
                    receipt().replace(b'fingerprint=', b'fingerprint=0', 1),
                    receipt().replace(b'FUSE_SERVICE_TOKEN=', b'FUSE_FRESH_TOKEN=')):
            with self.subTest(raw_length=len(raw)), self.assertRaises(auth.Failure):
                auth.parse_receipt(raw)

    def test_canonical_base64url_and_hex_are_phase_specific(self):
        value = next(iter(tokens().values()))
        self.assertTrue(auth.fresh_token(value))
        for invalid in (value + '=', value[:-1] + '/', 'a' * 64, '', 'CHANGE_ME', value[:-1] + 'B'):
            self.assertFalse(auth.fresh_token(invalid))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            for issued in (False, True):
                data = config_values(issued)
                path.write_text('\n'.join(key + '=' + value for key, value in data.items()))
                self.assertEqual(checks.credentials(path, issued=issued), data)
                with self.assertRaises(ValueError):
                    checks.credentials(path, issued=not issued)
            data['FUSE_DB_PASSWORD'] = value
            path.write_text('\n'.join(key + '=' + item for key, item in data.items()))
            with self.assertRaises(ValueError):
                checks.credentials(path)

    def test_public_failure_never_echoes_exception_or_receipt(self):
        output = io.StringIO()
        with patch.object(auth.sys, 'argv', ['ci-auth-bootstrap.py', 'provision']), \
                patch.object(auth, 'provision', side_effect=RuntimeError('PRIVATE_BEARER_MUST_NOT_ESCAPE')), \
                contextlib.redirect_stderr(output):
            self.assertEqual(auth.main(), 1)
        self.assertNotIn('PRIVATE_BEARER', output.getvalue())
        self.assertIn('EXECUTION_FAILED', output.getvalue())


class TargetAndWorkflowTests(NoServices):
    def test_config_requires_readonly_runtime_auth_and_generated_passwords(self):
        auth.validate_config(configuration(), PROJECT, config_values())
        for service, key, value in [('backend', 'FUSE_MIGRATE', 'true'),
                ('backend', 'FUSE_MIGRATION_PASSWORD', config_values()['FUSE_DB_OWNER_PASSWORD']),
                ('postgres', 'POSTGRES_PASSWORD', 'ambient'), ('backend', 'FUSE_DB_PASSWORD', 'ambient'),
                ('backend', 'FUSE_EXPERIMENT_DB_PASSWORD', 'ambient'), ('agent', 'FUSE_KYC_MODE', 'live'),
                ('backend', 'FUSE_REVIEWER_CUSTOMERS', 'customer-999')]:
            config = configuration()
            config['services'][service]['environment'][key] = value
            with self.subTest(key=key), self.assertRaises(auth.Failure):
                auth.validate_config(config, PROJECT, config_values())
        for mutate in (lambda c: c['volumes']['pgdata'].update(external=True),
                       lambda c: c['services']['postgres'].update(ports=[{'published': '5432'}]),
                       lambda c: c['networks']['data'].update(internal=False)):
            config = configuration()
            mutate(config)
            with self.assertRaises(auth.Failure):
                auth.validate_config(config, PROJECT, config_values())

    def test_target_identity_rejects_reused_storage_or_other_network(self):
        self.assertEqual(auth.validate_postgres(*docker_identity(), PROJECT), '172.19.0.2')
        for change in ('owner', 'host-bind', 'external-volume', 'other-network', 'public-address', 'extra-peer'):
            container, network, volume = docker_identity()
            if change == 'owner': volume['Labels']['com.docker.compose.project'] = 'other'
            if change == 'host-bind': container['Mounts'][0]['Type'] = 'bind'
            if change == 'external-volume': volume['Options'] = {'device': '/existing'}
            if change == 'other-network': network['Internal'] = False
            if change == 'public-address': container['NetworkSettings']['Networks'][PROJECT + '_data']['IPAddress'] = '8.8.8.8'
            if change == 'extra-peer': network['Containers']['c' * 64] = {'IPv4Address': '172.19.0.3/16'}
            with self.subTest(change=change), self.assertRaises(auth.Failure):
                auth.validate_postgres(container, network, volume, PROJECT)

    def test_workflow_keeps_single_consistent_scope_and_cleanup_after_owned_failure(self):
        workflow = (auth.ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('  combined-compose-browser:\n', 1)[1].split('\n  supply-chain:', 1)[0]
        self.assertIn('COMPOSE_FILE: compose.yaml:compose.ci.yaml', job)
        self.assertIn("if: always() && steps.ci_auth.outputs.owns_project == 'true'", job)
        self.assertIn('--project-name "$COMPOSE_PROJECT_NAME" down --volumes --remove-orphans', job)
        stages = ['scripts/ci-verify.py prepare', '--label compose-build', 'scripts/ci-auth-bootstrap.py provision',
                  '--label compose-up', 'scripts/ci-verify.py ready', 'scripts/container-network-check.py',
                  'npm run test:e2e', 'scripts/ci-verify.py evidence', 'scripts/runtime-log-privacy-check.py', '--label compose-cleanup']
        self.assertEqual([job.index(stage) for stage in stages], sorted(job.index(stage) for stage in stages))
        self.assertNotIn('continue-on-error:', job)
        self.assertNotIn('compose.dev.yaml', job)
        helper = (auth.ROOT / 'backend/src/test/java/com/finsec/fuse/testing/ComposeCiAuthBootstrap.java').read_text()
        self.assertIn('DemoTokenProvisioner.main(new String[] {"init-fresh", "--new-install", "--output", args[0]})', helper)
        self.assertNotIn('SpringApplication', helper)
        self.assertNotIn('DemoTokenTestFixture', helper)
        frontend = (auth.ROOT / 'frontend/tests/e2e/fullstack.spec.ts').read_text()
        self.assertIn("Buffer.from(value, 'base64url').toString('base64url') !== value", frontend)


if __name__ == '__main__':
    unittest.main()
