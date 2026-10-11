#!/usr/bin/env python3
"""Explicit synthetic CI migration/issuance/handoff, never operational bootstrap.

Only the provision command starts the fresh run's postgres service. No application
is started here. Owner connectivity is short-lived, derived from inspected Docker
identity, and never handed to the backend. Raw child output stays private.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = 'compose.yaml:compose.ci.yaml'
SOURCES = ('.github/workflows/ci.yml', 'compose.yaml', 'compose.ci.yaml', 'build.gradle',
           'scripts/ci-auth-bootstrap.py', 'scripts/ci-verify.py',
           '.env.example', 'scripts/bootstrap-dev.sh', 'scripts/bootstrap_dev.py', 'scripts/init-postgres.sh',
           'backend/src/test/java/com/finsec/fuse/testing/ComposeCiAuthBootstrap.java',
           'backend/src/main/java/com/finsec/fuse/auth/DemoTokenProvisioner.java',
           'backend/src/main/java/com/finsec/fuse/auth/DemoTokenAdministration.java',
           'backend/src/main/java/com/finsec/fuse/auth/DemoTokenStore.java',
           'backend/src/main/java/com/finsec/fuse/auth/DevActorRegistry.java',
           'backend/src/main/java/com/finsec/fuse/auth/Actor.java') + tuple(
               str(path.relative_to(ROOT)) for path in sorted((ROOT / 'backend/src/main/resources/db/migration').glob('*.sql')))
ACTORS = tuple((f'FUSE_CUSTOMER_{n}_TOKEN', f'customer-{n}') for n in range(101, 105)) + (
    ('FUSE_REVIEWER_TOKEN', 'staff-01'), ('FUSE_SECURITY_TOKEN', 'security-01'),
    ('FUSE_DEVELOPER_TOKEN', 'developer-01'), ('FUSE_SERVICE_TOKEN', 'kyc-service'))
SCOPES = 'customer-101,customer-102,customer-103,customer-104'
REASONS = frozenset({'CI_SCOPE_REJECTED', 'PRIVATE_FILE_REJECTED', 'MANIFEST_REJECTED',
    'CONFIGURATION_REJECTED', 'PROJECT_NOT_FRESH', 'DOCKER_IDENTITY_REJECTED',
    'COMMAND_FAILED', 'RECEIPT_REJECTED', 'HANDOFF_REJECTED', 'EXECUTION_FAILED'})


class Failure(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Failure(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def project_scope(root=ROOT, environment=None):
    env = os.environ if environment is None else environment
    project = 'fuse-ci-' + env.get('GITHUB_RUN_ID', '') + '-' + env.get('GITHUB_RUN_ATTEMPT', '')
    allowed = {'FUSE_UI_URL': 'http://127.0.0.1:5173', 'FUSE_E2E_INTEGRATION': '1',
               'FUSE_UI_SECURITY_HEADERS': '1', 'FUSE_E2E_ENV_FILE': str(root / '.env'),
               'FUSE_E2E_SUMMARY_PATH': str(root / 'safe-artifacts/browser-summary.json')}
    require(env.get('GITHUB_ACTIONS') == 'true'
            and re.fullmatch(r'fuse-ci-[1-9][0-9]*-[1-9][0-9]*', project)
            and env.get('COMPOSE_PROJECT_NAME') == project
            and env.get('COMPOSE_FILE') == COMPOSE_FILES
            and env.get('GITHUB_WORKSPACE') == str(root.resolve())
            and re.fullmatch(r'[a-f0-9]{40}', env.get('GITHUB_SHA', ''))
            and os.getuid() > 0 and os.getgid() > 0
            and all(key in allowed and value == allowed[key] for key, value in env.items()
                    if key.startswith(('FUSE_', 'SPRING_')) and value)
            and not any(env.get(key) for key in ('COMPOSE_PROFILES', 'COMPOSE_ENV_FILES',
                'COMPOSE_PATH_SEPARATOR', 'DOCKER_HOST', 'DOCKER_CONTEXT',
                'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH')),
            'CI_SCOPE_REJECTED')
    return project


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_FILE_REJECTED')


def private_read(path, limit=65536):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_size <= limit, 'PRIVATE_FILE_REJECTED')
        value = stream.read(limit + 1)
        require(len(value) <= limit, 'PRIVATE_FILE_REJECTED')
        return value


def private_create(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def grant_cleanup(project):
    # Only this marker grants the workflow permission to remove project resources.
    # It precedes every possible start, so failed/uncertain starts are still cleaned.
    private_create(ROOT / '.secrets/ci-auth-attempt.json',
                   (json.dumps({'schemaVersion': 'FUSE-CI-AUTH-ATTEMPT-1',
                                'project': project, 'head': os.environ['GITHUB_SHA']}) + '\n').encode())
    path = Path(os.environ.get('GITHUB_OUTPUT', ''))
    temporary = Path(os.environ.get('RUNNER_TEMP', ''))
    require(path.is_absolute() and temporary.is_absolute()
            and path.resolve().is_relative_to(temporary.resolve()), 'CI_SCOPE_REJECTED')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW), 'ab') as output:
        info = os.fstat(output.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1,
                'CI_SCOPE_REJECTED')
        output.write(b'owns_project=true\n')
        output.flush()
        os.fsync(output.fileno())


def manifest(root, project):
    private_directory(root / '.secrets')
    sources = sorted(set(SOURCES) | {str(path.relative_to(root)) for path in
        (root / 'backend/src/main/resources/db/migration').glob('*.sql')})
    return {'schemaVersion': 'FUSE-CI-AUTH-BASE-1', 'project': project,
            'head': os.environ.get('GITHUB_SHA'),
            'environmentSha256': digest(private_read(root / '.env')),
            'signingKeySha256': digest(private_read(root / '.secrets/signing.key', 4096)),
            'sources': {name: digest((root / name).read_bytes()) for name in sources}}


def record_preparation(root=ROOT):
    """Called only after ci-verify's fresh-file refusal and successful bootstrap."""
    project = project_scope(root)
    private_create(root / '.secrets/ci-auth-base.json',
                   (json.dumps(manifest(root, project), sort_keys=True) + '\n').encode())


def verify_manifest(root, project):
    expected = manifest(root, project)
    observed = json.loads(private_read(root / '.secrets/ci-auth-base.json'))
    require(observed == expected, 'MANIFEST_REJECTED')
    require(not (root / '.secrets/ci-auth-attempt.json').exists()
            and not (root / '.secrets/ci-auth-issued.env').exists()
            and not (root / '.secrets/ci-auth-complete.json').exists(), 'PROJECT_NOT_FRESH')
    return expected


def command(arguments, *, environment=None, timeout=60, limit=1048576):
    # TemporaryFile is anonymous/0600. Never return stderr, exception strings or
    # publish raw diagnostics, even when a child unexpectedly prints a bearer.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        process = subprocess.run(arguments, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=output, stderr=error, timeout=timeout)
        require(process.returncode == 0, 'COMMAND_FAILED')
        output.seek(0)
        raw = output.read(limit + 1)
        require(len(raw) <= limit, 'COMMAND_FAILED')
        return raw


def docker(*arguments, **kwargs):
    return command(['docker', *arguments], **kwargs)


def validate_config(config, project, values):
    require(config.get('name') == project and set(config.get('services', {})) ==
            {'postgres', 'backend', 'agent', 'frontend', 'ingress'}, 'CONFIGURATION_REJECTED')
    services = config['services']
    backend, agent = services['backend']['environment'], services['agent']['environment']
    postgres = services['postgres']['environment']
    require(backend.get('FUSE_MIGRATE') == 'false'
            and backend.get('FUSE_MIGRATION_USERNAME') == ''
            and backend.get('FUSE_MIGRATION_PASSWORD') == ''
            and not backend.get('FUSE_DB_OWNER_PASSWORD')
            and backend.get('FUSE_DB_USERNAME') == 'fuse_runtime'
            and backend.get('FUSE_DB_PASSWORD') == values['FUSE_DB_PASSWORD']
            and backend.get('FUSE_EXPERIMENT_DB_PASSWORD') == values['FUSE_EXPERIMENT_DB_PASSWORD']
            and values['FUSE_DB_OWNER_PASSWORD'] not in backend.values()
            and postgres.get('POSTGRES_USER') == 'fuse_owner' and postgres.get('POSTGRES_DB') == 'fuse'
            and postgres.get('POSTGRES_PASSWORD') == values['FUSE_DB_OWNER_PASSWORD']
            and postgres.get('FUSE_DB_PASSWORD') == values['FUSE_DB_PASSWORD']
            and postgres.get('FUSE_EXPERIMENT_DB_PASSWORD') == values['FUSE_EXPERIMENT_DB_PASSWORD']
            and backend.get('FUSE_DB_URL') == 'jdbc:postgresql://postgres:5432/fuse'
            and backend.get('SPRING_PROFILES_ACTIVE') == 'demo'
            and backend.get('FUSE_KYC_MODE') == agent.get('FUSE_KYC_MODE') == 'replay'
            and backend.get('FUSE_EXPERIMENT_LIVE_ENABLED') == 'false'
            and not agent.get('FUSE_LLM_MODEL') and not agent.get('FUSE_LLM_API_KEY')
            and backend.get('FUSE_REVIEWER_CUSTOMERS') == SCOPES
            and backend.get('FUSE_SECURITY_CUSTOMERS') == SCOPES
            and all(backend.get(key) == values[key] for key, _ in ACTORS)
            and agent.get('FUSE_SERVICE_TOKEN') == values['FUSE_SERVICE_TOKEN'], 'CONFIGURATION_REJECTED')
    memberships = {'postgres': {'data'}, 'backend': {'web', 'data', 'kyc'},
                   'agent': {'kyc'}, 'frontend': {'web'}, 'ingress': {'ingress', 'web'}}
    for name, service in services.items():
        require(set(service.get('networks', {})) == memberships[name]
                and not any(service.get(key) for key in ('network_mode', 'privileged', 'cap_add',
                    'extra_hosts', 'external_links', 'env_file'))
                and (name == 'ingress' or not service.get('ports')), 'CONFIGURATION_REJECTED')
    require(set(config.get('networks', {})) == {'web', 'data', 'kyc', 'ingress'}, 'CONFIGURATION_REJECTED')
    for name, network in config['networks'].items():
        require(network.get('name') == project + '_' + name and network.get('driver') == 'bridge'
                and network.get('internal', False) is (name != 'ingress')
                and not network.get('external'), 'CONFIGURATION_REJECTED')
    volumes = config.get('volumes', {})
    require(set(volumes) == {'pgdata'} and set(volumes['pgdata']) <= {'name', 'driver'}
            and volumes['pgdata'].get('name') == project + '_pgdata'
            and volumes['pgdata'].get('driver', 'local') == 'local', 'CONFIGURATION_REJECTED')
    mounts = services['postgres'].get('volumes', [])
    require(len(mounts) == 2, 'CONFIGURATION_REJECTED')
    data = [mount for mount in mounts if mount.get('target') == '/var/lib/postgresql/data']
    init = [mount for mount in mounts if mount.get('target') == '/docker-entrypoint-initdb.d/10-fuse.sh']
    require(len(data) == len(init) == 1 and data[0].get('type') == 'volume'
            and data[0].get('source') == 'pgdata' and not data[0].get('volume', {}).get('subpath')
            and init[0].get('type') == 'bind' and init[0].get('source') == str(ROOT / 'scripts/init-postgres.sh')
            and init[0].get('read_only') is True, 'CONFIGURATION_REJECTED')


def require_fresh_project(project):
    require(docker('context', 'show').strip() == b'default', 'CI_SCOPE_REJECTED')
    for kind in ('container', 'volume', 'network'):
        arguments = ['ps', '--all'] if kind == 'container' else [kind, 'ls']
        require(not docker(*arguments, '--filter', 'label=com.docker.compose.project=' + project,
                           '--format', '{{.ID}}' if kind == 'container' else '{{.Name}}').strip(), 'PROJECT_NOT_FRESH')
    require(not docker('volume', 'ls', '--filter', 'name=' + project + '_pgdata',
                       '--format', '{{.Name}}').strip(), 'PROJECT_NOT_FRESH')
    for name in ('web', 'data', 'kyc', 'ingress'):
        require(not docker('network', 'ls', '--filter', 'name=' + project + '_' + name,
                           '--format', '{{.Name}}').strip(), 'PROJECT_NOT_FRESH')


def validate_postgres(container, network, volume, project):
    labels = container.get('Config', {}).get('Labels', {})
    state = container.get('State', {})
    attached = container.get('NetworkSettings', {}).get('Networks', {})
    require(labels.get('com.docker.compose.project') == project
            and labels.get('com.docker.compose.service') == 'postgres'
            and container.get('Config', {}).get('Image') == 'postgres:16.15'
            and state.get('Status') == 'running' and state.get('Health', {}).get('Status') == 'healthy'
            and not container.get('HostConfig', {}).get('PortBindings')
            and set(attached) == {project + '_data'}
            and network.get('Name') == project + '_data' and network.get('Internal') is True
            and network.get('Driver') == 'bridge'
            and network.get('Labels', {}).get('com.docker.compose.project') == project,
            'DOCKER_IDENTITY_REJECTED')
    attachment = attached[project + '_data']
    identifier = container.get('Id', '')
    require(re.fullmatch(r'[a-f0-9]{64}', identifier)
            and attachment.get('NetworkID') == network.get('Id')
            and identifier in network.get('Containers', {})
            and set(network['Containers']) == {identifier}, 'DOCKER_IDENTITY_REJECTED')
    mounts = [mount for mount in container.get('Mounts', []) if mount.get('Destination') == '/var/lib/postgresql/data']
    require(len(mounts) == 1 and mounts[0].get('Type') == 'volume'
            and mounts[0].get('Name') == volume.get('Name') == project + '_pgdata'
            and mounts[0].get('Source') == volume.get('Mountpoint')
            and volume.get('Driver') == 'local' and not volume.get('Options')
            and volume.get('Labels', {}).get('com.docker.compose.project') == project
            and volume.get('Labels', {}).get('com.docker.compose.volume') == 'pgdata', 'DOCKER_IDENTITY_REJECTED')
    ip = ipaddress.ip_address(attachment.get('IPAddress', ''))
    require(ip.version == 4 and ip.is_private and not (ip.is_loopback or ip.is_link_local
            or ip.is_unspecified or ip.is_multicast or ip.is_reserved)
            and network['Containers'][identifier].get('IPv4Address', '').split('/')[0] == str(ip),
            'DOCKER_IDENTITY_REJECTED')
    return str(ip)


def postgres_address(project):
    ids = docker('compose', 'ps', '--all', '--quiet', 'postgres').decode('ascii').splitlines()
    require(len(ids) == 1 and re.fullmatch(r'[a-f0-9]{64}', ids[0]), 'DOCKER_IDENTITY_REJECTED')
    # Full inspect data is private in memory only; no Docker environment is emitted.
    container = json.loads(docker('inspect', ids[0]))
    network = json.loads(docker('network', 'inspect', project + '_data'))
    volume = json.loads(docker('volume', 'inspect', project + '_pgdata'))
    require(len(container) == len(network) == len(volume) == 1, 'DOCKER_IDENTITY_REJECTED')
    return validate_postgres(container[0], network[0], volume[0], project)


def fresh_token(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', value):
        return False
    try:
        decoded = base64.b64decode(value + '=', altchars=b'-_', validate=True)
        return len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip('=') == value
    except ValueError:
        return False


def parse_receipt(raw):
    lines = [line for line in raw.decode('ascii').splitlines() if line]
    require(len(lines) == 20 and lines[0] == '# Fresh private bearer output. Keep private; hand off explicitly.'
            and lines[2] == '# status=PREPARED' and lines[-1] == '# status=COMMITTED', 'RECEIPT_REJECTED')
    require(lines[1].startswith('# operation_id='), 'RECEIPT_REJECTED')
    operation = lines[1].removeprefix('# operation_id=')
    require(str(uuid.UUID(operation)) == operation, 'RECEIPT_REJECTED')
    tokens = {}
    for index, (key, actor) in enumerate(ACTORS):
        metadata, assignment = lines[3 + index * 2:5 + index * 2]
        require(assignment.startswith(key + '='), 'RECEIPT_REJECTED')
        value = assignment[len(key) + 1:]
        require(fresh_token(value) and metadata == '# actor=' + actor + ' fingerprint=' + digest(value.encode()),
                'RECEIPT_REJECTED')
        tokens[key] = value
    require(len(set(tokens.values())) == 8, 'RECEIPT_REJECTED')
    return tokens


def handoff(root, before, tokens):
    require(set(tokens) == {key for key, _ in ACTORS}
            and len(set(tokens.values())) == 8 and all(fresh_token(value) for value in tokens.values()),
            'HANDOFF_REJECTED')
    require(private_read(root / '.env') == before, 'HANDOFF_REJECTED')
    lines = before.decode('ascii').splitlines()
    previous = {}
    for index, line in enumerate(lines):
        key, separator, value = line.partition('=')
        if separator and key in tokens:
            require(key not in previous, 'HANDOFF_REJECTED')
            previous[key] = value
            lines[index] = key + '=' + tokens[key]
    require(set(previous) == set(tokens) and not set(previous.values()) & set(tokens.values()), 'HANDOFF_REJECTED')
    updated = ('\n'.join(lines) + '\n').encode('ascii')
    descriptor, name = tempfile.mkstemp(prefix='.ci-auth-handoff-', dir=root)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        require(private_read(root / '.env') == before, 'HANDOFF_REJECTED')
        os.replace(name, root / '.env')
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        require(private_read(root / '.env') == updated, 'HANDOFF_REJECTED')
    finally:
        if os.path.exists(name):
            os.unlink(name)


def clean_process_environment():
    # No administrative credentials, Java injection flags or provider config can
    # enter Gradle. Only the later Java child receives the generated owner password.
    allowed = {'PATH', 'JAVA_HOME', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'RUNNER_TEMP',
               'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def provision():
    project = project_scope()
    original_manifest = verify_manifest(ROOT, project)
    spec = importlib.util.spec_from_file_location('ci_verify_auth', ROOT / 'scripts/ci-verify.py')
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    values = checks.credentials(issued=False)
    require(all(re.fullmatch(r'[a-f0-9]{64}', values[key]) for key, _ in ACTORS)
            and values.get('FUSE_RUNTIME_UID') == str(os.getuid())
            and values.get('FUSE_RUNTIME_GID') == str(os.getgid())
            and all(values.get(key, SCOPES) == SCOPES for key in
                    ('FUSE_REVIEWER_CUSTOMERS', 'FUSE_SECURITY_CUSTOMERS')), 'CONFIGURATION_REJECTED')
    before = private_read(ROOT / '.env')
    validate_config(json.loads(docker('compose', 'config', '--format', 'json')), project, values)
    require_fresh_project(project)
    # A failed or uncertain attempt is never retried. The job's always-cleanup
    # handles only this run; PREPARED private files remain until runner disposal.
    grant_cleanup(project)
    environment = clean_process_environment()
    classpath_file = ROOT / '.secrets/ci-auth-classpath.txt'
    command(['./gradlew', '--no-daemon', '--console=plain', 'writeTestClasspath',
             '-PtestClasspathFile=' + str(classpath_file)], environment=environment, timeout=900)
    # Gradle creates a non-secret classpath file; it is not a credential input.
    require(classpath_file.is_file() and not classpath_file.is_symlink()
            and classpath_file.stat().st_size <= 65536, 'CONFIGURATION_REJECTED')
    classpath = classpath_file.read_text().strip()
    require(classpath and '\n' not in classpath and '\r' not in classpath, 'CONFIGURATION_REJECTED')
    docker('compose', 'up', '--no-build', '--detach', '--wait', '--wait-timeout', '60', 'postgres', timeout=90)
    address = postgres_address(project)
    output = ROOT / '.secrets/ci-auth-issued.env'
    # Compile first, then give owner connectivity only to this standalone child.
    environment.update(GITHUB_ACTIONS='true', FUSE_CI_AUTH_PROJECT=project,
        FUSE_CI_AUTH_ADDRESS=address, FUSE_DB_URL='jdbc:postgresql://' + address + ':5432/fuse',
        FUSE_MIGRATION_USERNAME='fuse_owner', FUSE_MIGRATION_PASSWORD=values['FUSE_DB_OWNER_PASSWORD'])
    command(['java', '-cp', classpath, 'com.finsec.fuse.testing.ComposeCiAuthBootstrap', str(output)],
            environment=environment, timeout=120)
    tokens = parse_receipt(private_read(output))
    require(manifest(ROOT, project) == original_manifest, 'MANIFEST_REJECTED')
    handoff(ROOT, before, tokens)
    updated = checks.credentials()
    require(all(updated[key] == token for key, token in tokens.items()), 'HANDOFF_REJECTED')
    validate_config(json.loads(docker('compose', 'config', '--format', 'json')), project, updated)
    private_create(ROOT / '.secrets/ci-auth-complete.json',
                   (json.dumps({'schemaVersion': 'FUSE-CI-AUTH-COMPLETE-1', 'project': project,
                                'environmentSha256': digest(private_read(ROOT / '.env')),
                                'issuedCredentialCount': 8}) + '\n').encode())


def main():
    if sys.argv[1:] != ['provision']:
        print('Usage: ci-auth-bootstrap.py provision', file=sys.stderr)
        return 1
    try:
        provision()
        print('Synthetic CI auth: PASS; fresh issuance and private handoff completed for eight roles.')
        return 0
    except Exception as failure:
        reason = str(failure) if isinstance(failure, Failure) and str(failure) in REASONS else 'EXECUTION_FAILED'
        print('Synthetic CI auth: FAIL (' + reason + '); no retry or completion claimed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
