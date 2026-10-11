#!/usr/bin/env python3
"""GitHub-hosted disposable acceptance of the SHIPPED admin images and web main.

No operator target, credentials or existing project are accepted. The older combined
CI helper is used only for its private-file/receipt/identity checks, never its Java
migration+issuance entrypoint. Output is a fixed aggregate; all child diagnostics,
Docker inspect/config data and credentials remain private in memory/0600 files.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ('images', 'plain_up_excludes_admins', 'no_argument_refusal', 'invalid_target_refusal',
          'fresh_migration', 'repeat_refusal', 'token_identity', 'private_output_refusals',
          'separate_issuance', 'separate_handoff', 'replay_readiness', 'http_and_durable_outcomes',
          'stop_restart_preserves_authority', 'private_diagnostics', 'source_unchanged')
MAIN_URL = 'jdbc:postgresql://postgres:5432/fuse'
REASONS = frozenset({'SCOPE_REJECTED', 'EXISTING_STATE', 'SOURCE_REJECTED', 'CONFIG_REJECTED',
                    'COMMAND_FAILED', 'ASSERTION_FAILED', 'PRIVATE_DIAGNOSTIC', 'CLEANUP_FAILED', 'EXECUTION_FAILED'})


class Failure(RuntimeError):
    pass


def require(value, reason='ASSERTION_FAILED'):
    if not value:
        raise Failure(reason)


def helper(name):
    spec = importlib.util.spec_from_file_location('fresh_' + name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def scope(environment=None, root=ROOT, uid=None, gid=None):
    env = os.environ if environment is None else environment
    uid, gid = os.getuid() if uid is None else uid, os.getgid() if gid is None else gid
    project = 'fuse-fresh-' + env.get('GITHUB_RUN_ID', '') + '-' + env.get('GITHUB_RUN_ATTEMPT', '')
    require(env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_WORKSPACE') == str(root.resolve())
            and re.fullmatch(r'fuse-fresh-[1-9][0-9]*-[1-9][0-9]*', project)
            and re.fullmatch(r'[0-9a-f]{40}', env.get('GITHUB_SHA', ''))
            and env.get('COMPOSE_PROJECT_NAME') == project
            and env.get('COMPOSE_FILE') == 'compose.yaml:compose.admin.yaml'
            and 0 < uid < 2147483647 and uid != 10001 and 0 < gid < 2147483647
            and not any(value for key, value in env.items() if key.startswith(('FUSE_', 'SPRING_')))
            and not any(env.get(key) for key in ('COMPOSE_PROFILES', 'COMPOSE_ENV_FILES', 'COMPOSE_PATH_SEPARATOR',
                'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH')),
            'SCOPE_REJECTED')
    return project


def clean_environment():
    allowed = {'PATH', 'HOME', 'LANG', 'LC_ALL', 'TMPDIR', 'RUNNER_TEMP'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def run(arguments, *, expected=0, timeout=60, environment=None):
    # Anonymous files bound memory and avoid raw diagnostics in CI logs or exception text.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        process = subprocess.run(arguments, cwd=ROOT, env=clean_environment() if environment is None else environment,
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=error, timeout=timeout)
        output.seek(0); error.seek(0)
        stdout, stderr = output.read(8_388_609), error.read(8_388_609)
        require(len(stdout) <= 8_388_608 and len(stderr) <= 8_388_608, 'COMMAND_FAILED')
        require((process.returncode == 0) if expected == 0 else (process.returncode != 0), 'COMMAND_FAILED')
        return stdout, stderr


def quiet(arguments, **kwargs):
    return run(arguments, **kwargs)[0]


def docker(*arguments, **kwargs):
    return quiet(['docker', *arguments], **kwargs)


def compose(project, *, admins=True):
    args = ['docker', 'compose', '--project-directory', str(ROOT), '--env-file', str(ROOT / '.env'),
            '--project-name', project, '-f', str(ROOT / 'compose.yaml')]
    if admins:
        args += ['-f', str(ROOT / 'compose.admin.yaml')]
    return args


def source_hash():
    require(quiet(['git', 'rev-parse', 'HEAD']).strip().decode() == os.environ['GITHUB_SHA'], 'SOURCE_REJECTED')
    quiet(['git', 'diff', '--quiet', 'HEAD', '--']); quiet(['git', 'diff', '--cached', '--quiet'])
    names = quiet(['git', 'ls-files', '-z']).decode().split('\0')
    result = hashlib.sha256()
    for name in sorted(x for x in names if x):
        path = ROOT / name
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(ROOT), 'SOURCE_REJECTED')
        result.update(name.encode() + b'\0' + hashlib.sha256(path.read_bytes()).digest())
    return result.hexdigest()


def validate_config(config, project, values):
    services = config.get('services', {})
    require(config.get('name') == project and set(services) ==
            {'postgres', 'backend', 'agent', 'frontend', 'ingress', 'migration', 'token-admin'}, 'CONFIG_REJECTED')
    backend, agent = services['backend']['environment'], services['agent']['environment']
    require(backend.get('FUSE_MIGRATE') == 'false' and backend.get('FUSE_DB_URL') == MAIN_URL
            and backend.get('FUSE_DB_USERNAME') == 'fuse_runtime'
            and backend.get('FUSE_DB_PASSWORD') == values['FUSE_DB_PASSWORD']
            and backend.get('FUSE_EXPERIMENT_DB_USERNAME') == 'fuse_experiment_owner'
            and backend.get('FUSE_EXPERIMENT_DB_PASSWORD') == values['FUSE_EXPERIMENT_DB_PASSWORD']
            and all(key not in backend for key in ('FUSE_MIGRATION_USERNAME', 'FUSE_MIGRATION_PASSWORD', 'FUSE_DB_OWNER_PASSWORD'))
            and values['FUSE_DB_OWNER_PASSWORD'] not in backend.values()
            and backend.get('FUSE_KYC_MODE') == agent.get('FUSE_KYC_MODE') == 'replay'
            and backend.get('FUSE_EXPERIMENT_LIVE_ENABLED') == 'false'
            and not agent.get('FUSE_LLM_API_KEY') and not agent.get('FUSE_LLM_MODEL'), 'CONFIG_REJECTED')
    for name in ('migration', 'token-admin'):
        item = services[name]
        require(item.get('profiles') == ['admin'] and item.get('restart') == 'no'
                and item.get('read_only') is True and set(item.get('networks', {})) == {'data'}
                and item.get('build', {}).get('target') == name
                and not any(item.get(key) for key in ('command', 'entrypoint', 'depends_on', 'ports', 'privileged', 'cap_add', 'env_file'))
                and item['environment']['FUSE_DB_URL'] == MAIN_URL
                and item['environment']['FUSE_MIGRATION_USERNAME'] == 'fuse_owner'
                and item['environment']['FUSE_MIGRATION_PASSWORD'] == values['FUSE_DB_OWNER_PASSWORD'], 'CONFIG_REJECTED')
    require(services['backend']['build']['target'] == 'backend'
            and services['token-admin'].get('user') is None
            and services['token-admin']['build']['args'] == {'FUSE_ADMIN_UID': str(os.getuid()), 'FUSE_ADMIN_GID': str(os.getgid())}, 'CONFIG_REJECTED')
    require(set(config.get('volumes', {})) == {'pgdata'}
            and config['volumes']['pgdata'].get('name') == project + '_pgdata'
            and not config['volumes']['pgdata'].get('external'), 'CONFIG_REJECTED')
    for name, network in config.get('networks', {}).items():
        require(name in {'web', 'data', 'kyc', 'ingress'} and network.get('name') == project + '_' + name
                and not network.get('external') and network.get('internal', False) is (name != 'ingress'), 'CONFIG_REJECTED')


def no_canaries(raw, values):
    require(all(value.encode() not in raw for value in values if len(value) >= 8), 'PRIVATE_DIAGNOSTIC')


def prepared_canaries(raw):
    # PREPARED output can exist after a failed/unknown commit. Inspect it privately
    # for leak detection only; this does not authorize a handoff or retry.
    return [match.decode() for match in re.findall(rb'(?m)^FUSE_[A-Z0-9_]+=([A-Za-z0-9_-]{43})$', raw)]


def admin(project, service, case, arguments, canaries, *, success, options=(), receipt=None):
    name = project + '-' + case
    require(not docker('ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}').strip(), 'EXISTING_STATE')
    try:
        out, err = run(compose(project) + ['run', '--no-deps', '--name', name, *options, service, *arguments],
                       expected=0 if success else 1, timeout=120)
        log_out, log_err = run(['docker', 'logs', name])
        diagnostics = out + err + log_out + log_err
        no_canaries(diagnostics, canaries)
        if receipt is not None and os.path.lexists(receipt):
            no_canaries(diagnostics, prepared_canaries(helper('ci-auth-bootstrap').private_read(receipt)))
        inspected = json.loads(docker('inspect', name))[0]
        require(inspected['Config']['Labels']['com.docker.compose.project'] == project
                and not inspected['HostConfig'].get('PortBindings')
                and inspected['State']['Running'] is False, 'CONFIG_REJECTED')
        if service == 'migration' and success:
            require(b'Migration COMPLETE:' in out)
        return diagnostics  # Retained privately until generated COMMITTED bearer values are also checked.
    finally:
        # Exact generated name, never an operator-supplied container selector.
        ids = docker('ps', '--all', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}').splitlines()
        if ids:
            inspected = json.loads(docker('inspect', name))[0]
            require(inspected['Config']['Labels']['com.docker.compose.project'] == project, 'CLEANUP_FAILED')
            docker('rm', '--force', name)


def sql(project, statement):
    # Only fixed statements over the just-inspected disposable postgres container.
    return quiet(compose(project, admins=False) + ['exec', '-T', 'postgres', 'psql', '-X', '-A', '-t',
            '-U', 'fuse_owner', '-d', 'fuse', '-v', 'ON_ERROR_STOP=1', '-c', statement]).strip()


def authority_snapshot(project):
    return sql(project, "SELECT row_to_json(r)::text FROM demo_auth_registry r ORDER BY id; "
               "SELECT row_to_json(t)::text FROM demo_token t ORDER BY fingerprint; "
               "SELECT row_to_json(h)::text FROM flyway_schema_history h ORDER BY installed_rank")


def marker(project):
    return {'schemaVersion': 'FUSE-FRESH-OWNERSHIP-1', 'project': project, 'head': os.environ['GITHUB_SHA']}


def cleanup(project, files):
    observed = json.loads(files.private_read(ROOT / '.secrets/ci-fresh-attempt.json'))
    require(observed == marker(project), 'CLEANUP_FAILED')
    quiet(compose(project) + ['--profile', 'admin', 'down', '--volumes', '--remove-orphans'], timeout=90)
    for kind in ('container', 'network', 'volume'):
        args = ['ps', '--all'] if kind == 'container' else [kind, 'ls']
        require(not docker(*args, '--filter', 'label=com.docker.compose.project=' + project,
                           '--format', '{{.ID}}' if kind == 'container' else '{{.Name}}').strip(), 'CLEANUP_FAILED')


def readiness(checks):
    deadline = time.monotonic() + 180
    while True:
        try:
            result = checks.request('/actuator/health/readiness')
            if result.get('status') == 'UP':
                return
        except Exception:
            pass
        require(time.monotonic() < deadline)
        time.sleep(1)


def durable_outcomes(project):
    raw = sql(project, """SELECT json_build_object('customer',a.customer_id,'state',w.state,'used',w.used_risk,'reserved',w.reserved_risk,
      'payments',(SELECT count(*) FROM mock_payment p WHERE p.workflow_id=w.id),
      'consumes',(SELECT count(*) FROM risk_ledger r WHERE r.workflow_id=w.id AND event_type='CONSUME'),
      'approvals',(SELECT count(*) FROM approval p WHERE p.workflow_id=w.id AND status='CONSUMED'),
      'activeJobs',(SELECT count(*) FROM workflow_job j WHERE j.workflow_id=w.id AND state IN ('PENDING','RUNNING')),
      'audit',(SELECT count(*) FROM audit_event e WHERE e.workflow_id=w.id))
      FROM workflow w JOIN loan_application a ON a.id=w.application_id ORDER BY a.customer_id""")
    rows = [json.loads(line) for line in raw.splitlines()]
    require(len(rows) == 2 and [r.pop('customer') for r in rows] == ['customer-101', 'customer-102'])
    for row, state, used, paid in zip(rows, ('BLOCKED', 'PAID'), (10, 85), (0, 1)):
        require(row.pop('audit') > 0 and row == dict(state=state, used=used, reserved=0, payments=paid,
                                                   consumes=paid, approvals=paid, activeJobs=0))
    return raw


def execute(project, report, files, checks):
    require(not any(os.path.lexists(ROOT / name) for name in ('.env', '.secrets', 'safe-artifacts')), 'EXISTING_STATE')
    report['sourceHashBefore'] = source_hash()
    require(docker('context', 'show').strip() == b'default', 'SCOPE_REJECTED')
    files.require_fresh_project(project)
    quiet(['bash', 'scripts/bootstrap-dev.sh'])
    values = checks.credentials(issued=False)
    files.private_directory(ROOT / '.secrets'); files.private_read(ROOT / '.env')
    before = files.private_read(ROOT / '.env')
    output_dir = ROOT / '.secrets/auth-output'; output_dir.mkdir(mode=0o700)
    canaries = [MAIN_URL] + [value for key, value in values.items() if key.endswith(('_PASSWORD', '_TOKEN')) and '${' not in value]
    config = json.loads(quiet(compose(project) + ['--profile', 'admin', 'config', '--format', 'json']))
    validate_config(config, project, values)
    files.private_create(ROOT / '.secrets/ci-fresh-attempt.json', (json.dumps(marker(project)) + '\n').encode())
    report['ownsProject'] = True
    # Builds use existing dependencies only; all build output stays private.
    quiet(compose(project) + ['--profile', 'admin', 'build'], timeout=1200)
    for service in ('backend', 'migration', 'token-admin'):
        inspected = json.loads(docker('image', 'inspect', project + '-' + service))[0]
        require(inspected['Config']['Entrypoint'] == ['java', '-jar', '/app/app.jar']
                and not inspected['Config'].get('Cmd'), 'CONFIG_REJECTED')
        if service == 'token-admin':
            require(inspected['Config']['User'] == str(os.getuid()) + ':' + str(os.getgid()))
        report['imageIds'][service] = inspected['Id']
    report['checks']['images'] = 'PASS'
    for service in ('migration', 'token-admin'):
        admin(project, service, service + '-noargs', [], canaries, success=False)
    report['checks']['no_argument_refusal'] = 'PASS'
    invalid_url = MAIN_URL + '?password=SYNTHETIC_URL_CANARY'
    admin(project, 'migration', 'invalid-url', ['migrate-fresh', '--new-install'], canaries + [invalid_url, 'SYNTHETIC_URL_CANARY'],
          success=False, options=['-e', 'FUSE_DB_URL=' + invalid_url])
    report['checks']['invalid_target_refusal'] = 'PASS'
    quiet(compose(project, admins=False) + ['up', '--no-build', '--detach', '--wait', '--wait-timeout', '60', 'postgres'], timeout=90)
    # Reuse the existing identity oracle, but explicitly supply this project's commands.
    ids = quiet(compose(project, admins=False) + ['ps', '--all', '--quiet', 'postgres']).decode().splitlines()
    require(len(ids) == 1)
    files.validate_postgres(json.loads(docker('inspect', ids[0]))[0], json.loads(docker('network', 'inspect', project + '_data'))[0],
                            json.loads(docker('volume', 'inspect', project + '_pgdata'))[0], project)
    admin(project, 'migration', 'fresh-migration', ['migrate-fresh', '--new-install'], canaries, success=True)
    require(sql(project, "SELECT count(*)=7 AND bool_and(success) FROM flyway_schema_history") == b't')
    require(sql(project, "SELECT (SELECT count(*) FROM demo_token)=0 AND (SELECT count(*) FROM demo_auth_registry)=0 "
                "AND (SELECT count(*) FROM mock_profile)=0 AND (SELECT count(*) FROM workflow)=0 "
                "AND (SELECT count(*) FROM execution_gate WHERE id=1 AND epoch=0)=1") == b't')
    require(sql(project, "SELECT has_table_privilege('fuse_runtime','flyway_schema_history','SELECT') "
                "AND NOT has_table_privilege('fuse_runtime','flyway_schema_history','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') "
                "AND NOT has_any_column_privilege('fuse_runtime','flyway_schema_history','INSERT,UPDATE,REFERENCES')") == b't')
    report['checks']['fresh_migration'] = 'PASS'
    migrated = authority_snapshot(project)
    admin(project, 'migration', 'repeat', ['migrate-fresh', '--new-install'], canaries, success=False)
    require(authority_snapshot(project) == migrated); report['checks']['repeat_refusal'] = 'PASS'
    # Actual passwd resolution and a non10001 host-owned bind, without changing the provisioner.
    identity = quiet(compose(project) + ['run', '--rm', '--no-deps', '--entrypoint', '/bin/sh', 'token-admin', '-c',
             'test "$(id -u)" -gt 0 && getent passwd "$(id -u)" >/dev/null && printf "%s:%s" "$(id -u)" "$(id -g)"'])
    require(identity == (str(os.getuid()) + ':' + str(os.getgid())).encode())
    # The image already contains UID/GID10001. Exercise the reviewed duplicate-ID
    # build case as well; only the separate non10001 image below issues durable tokens.
    collision = project + '-token-collision'
    require(not docker('image', 'ls', '--quiet', '--filter', 'reference=' + collision).strip(), 'EXISTING_STATE')
    quiet(['docker', 'build', '--file', 'backend/Dockerfile', '--target', 'token-admin',
           '--build-arg', 'FUSE_ADMIN_UID=10001', '--build-arg', 'FUSE_ADMIN_GID=10001', '--tag', collision, '.'], timeout=1200)
    collision_image = json.loads(docker('image', 'inspect', collision))[0]
    require(collision_image['Config']['User'] == '10001:10001')
    identity = docker('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                      '--security-opt', 'no-new-privileges:true', '--entrypoint', '/bin/sh', collision, '-c',
                      'test "$(id -u)" = 10001 && test "$(id -g)" = 10001 && getent passwd 10001 >/dev/null')
    require(not identity)
    docker('image', 'rm', collision)
    report['checks']['token_identity'] = 'PASS' 
    files.private_create(output_dir / 'exists.env', b'SYNTHETIC_UNCHANGED\n')
    (output_dir / 'link.env').symlink_to('exists.env')
    for case, path, options in (('existing-output', 'exists.env', ()), ('symlink-output', 'link.env', ()),
                               ('mismatched-owner', 'mismatch.env', ('--user', '10001:10001'))):
        admin(project, 'token-admin', case, ['init-fresh', '--new-install', '--output', '/private-output/' + path],
              canaries, success=False, options=options)
    require(files.private_read(output_dir / 'exists.env') == b'SYNTHETIC_UNCHANGED\n'
            and not (output_dir / 'mismatch.env').exists() and authority_snapshot(project) == migrated)
    # A failed DB connection leaves a private PREPARED receipt. Its generated values
    # must also be absent from stdout, stderr and container logs before removal.
    admin(project, 'token-admin', 'prepared-failure', ['init-fresh', '--new-install', '--output', '/private-output/prepared.env'],
          canaries + ['SYNTHETIC_WRONG_OWNER_PASSWORD'], success=False,
          options=['-e', 'FUSE_MIGRATION_PASSWORD=SYNTHETIC_WRONG_OWNER_PASSWORD'], receipt=output_dir / 'prepared.env')
    prepared = files.private_read(output_dir / 'prepared.env')
    require(b'# status=PREPARED' in prepared and b'# status=COMMITTED' not in prepared
            and len(prepared_canaries(prepared)) == 8 and authority_snapshot(project) == migrated)
    report['checks']['private_output_refusals'] = 'PASS'
    issued_diagnostics = admin(project, 'token-admin', 'fresh-issuance', ['init-fresh', '--new-install', '--output', '/private-output/issued.env'],
                               canaries, success=True, receipt=output_dir / 'issued.env')
    tokens = files.parse_receipt(files.private_read(output_dir / 'issued.env'))
    no_canaries(issued_diagnostics, list(tokens.values()))
    require(sql(project, 'SELECT count(*) FROM demo_token') == b'8')
    require(files.private_read(ROOT / '.env') == before)
    report['checks']['separate_issuance'] = 'PASS'
    files.handoff(ROOT, before, tokens)  # Synthetic CI-only, separate from either product command.
    values = checks.credentials(); canaries += list(tokens.values())
    validate_config(json.loads(quiet(compose(project) + ['--profile', 'admin', 'config', '--format', 'json'])), project, values)
    report['checks']['separate_handoff'] = 'PASS'
    authority = authority_snapshot(project)
    quiet(compose(project) + ['up', '--no-build', '--detach', '--wait', '--wait-timeout', '240'], timeout=270)
    actual = quiet(compose(project) + ['ps', '--services', '--status', 'running']).decode().splitlines()
    require(set(actual) == {'postgres', 'backend', 'agent', 'frontend', 'ingress'})
    report['checks']['plain_up_excludes_admins'] = 'PASS'
    readiness(checks); report['checks']['replay_readiness'] = 'PASS'
    environment = clean_environment(); environment.update(tokens)
    environment.update(FUSE_BASE_URL='http://127.0.0.1:8080', NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
    smoke = quiet([sys.executable, 'scripts/run_demo.py'], environment=environment, timeout=210)
    api_rows = [json.loads(line) for line in smoke.splitlines() if line]
    require(len(api_rows) == 2 and [row.get('customer') for row in api_rows] == [101, 102])
    for row, state, used in zip(api_rows, ('BLOCKED', 'PAID'), (10, 85)):
        require((row.get('state'), row.get('usedRisk'), row.get('reservedRisk')) == (state, used, 0))
    outcomes = durable_outcomes(project); report['checks']['http_and_durable_outcomes'] = 'PASS'
    quiet(compose(project) + ['stop'], timeout=90)
    quiet(compose(project) + ['start', '--wait', '--wait-timeout', '60', 'postgres'], timeout=90)
    quiet(compose(project) + ['start', '--wait', '--wait-timeout', '60', 'agent'], timeout=90)
    quiet(compose(project) + ['start', 'backend', 'frontend', 'ingress'], timeout=90)
    readiness(checks)
    require(authority_snapshot(project) == authority and durable_outcomes(project) == outcomes)
    report['checks']['stop_restart_preserves_authority'] = 'PASS'
    log_out, log_err = run(compose(project) + ['logs', '--no-color'])
    no_canaries(log_out + log_err, canaries)
    report['checks']['private_diagnostics'] = 'PASS'
    report['sourceHashAfter'] = source_hash()
    require(report['sourceHashBefore'] == report['sourceHashAfter'], 'SOURCE_REJECTED')
    report['checks']['source_unchanged'] = 'PASS'


def public_report(report):
    require(set(report) == {'schemaVersion', 'status', 'head', 'checks', 'imageIds', 'sourceHashBefore',
            'sourceHashAfter', 'cleanupVerified', 'ownsProject', 'failure'}, 'ASSERTION_FAILED')
    require(report['schemaVersion'] == 'FUSE-SHIPPED-FRESH-SETUP-1' and report['status'] in {'PASS', 'FAIL'}
            and re.fullmatch(r'[0-9a-f]{40}', report['head']) and set(report['checks']) == set(CHECKS)
            and set(report['checks'].values()) <= {'PASS', 'NOT_RUN'}
            and set(report['imageIds']) <= {'backend', 'migration', 'token-admin'}
            and all(re.fullmatch(r'sha256:[0-9a-f]{64}', value) for value in report['imageIds'].values())
            and all(value is None or re.fullmatch(r'[0-9a-f]{64}', value) for value in (report['sourceHashBefore'], report['sourceHashAfter'])))
    require(type(report['cleanupVerified']) is bool and type(report['ownsProject']) is bool
            and (report['failure'] is None or report['failure'] in REASONS))
    if report['status'] == 'PASS':
        require(report['cleanupVerified'] and report['ownsProject'] and report['failure'] is None
                and all(value == 'PASS' for value in report['checks'].values())
                and report['sourceHashBefore'] == report['sourceHashAfter'] and report['sourceHashBefore'] is not None
                and set(report['imageIds']) == {'backend', 'migration', 'token-admin'})
    return (json.dumps(report, sort_keys=True, indent=2) + '\n').encode()


def diagnostic_report(report):
    """Closed log projection; the exact CHECKS length bounds every emitted count."""
    public_report(report)
    passed = sum(report['checks'][name] == 'PASS' for name in CHECKS)
    return json.dumps({'schemaVersion': 'FUSE-FRESH-DIAGNOSTIC-1', 'status': report['status'],
        'failure': report['failure'] or 'NONE',
        'checks': {name: report['checks'][name] for name in CHECKS},
        'planned': len(CHECKS), 'passed': passed, 'notRun': len(CHECKS) - passed,
        'cleanup': 'PASS' if report['cleanupVerified'] else 'NOT_CONFIRMED'}, sort_keys=True)


def print_diagnostic(report):
    try:
        payload = diagnostic_report(report)
    except Exception:
        print('{"schemaVersion":"FUSE-FRESH-DIAGNOSTIC-1","status":"INVALID"}')
        return False
    print(payload)
    return True


def main():
    if sys.argv[1:] not in (['execute'], ['cleanup']):
        print('Usage: ci-fresh-setup.py execute|cleanup', file=sys.stderr); return 1
    report = None
    try:
        project = scope(); files, checks = helper('ci-auth-bootstrap'), helper('ci-verify')
        if sys.argv[1] == 'cleanup':
            if (ROOT / '.secrets/ci-fresh-attempt.json').exists():
                cleanup(project, files)
            return 0
        report = dict(schemaVersion='FUSE-SHIPPED-FRESH-SETUP-1', status='FAIL', head=os.environ['GITHUB_SHA'],
                      checks=dict.fromkeys(CHECKS, 'NOT_RUN'), imageIds={}, sourceHashBefore=None, sourceHashAfter=None,
                      ownsProject=False, cleanupVerified=False, failure=None)
        try:
            execute(project, report, files, checks)
        except Exception as error:
            report['failure'] = str(error) if isinstance(error, Failure) and str(error) in REASONS else 'EXECUTION_FAILED'
        finally:
            if report['ownsProject']:
                try:
                    cleanup(project, files); report['cleanupVerified'] = True
                except Exception:
                    report['failure'] = 'CLEANUP_FAILED'
        if report['failure'] is None:
            report['status'] = 'PASS'
        payload = public_report(report)
        (ROOT / 'safe-artifacts').mkdir(mode=0o700, exist_ok=True)
        files.private_create(ROOT / 'safe-artifacts/fresh-setup-summary.json', payload)
        if not print_diagnostic(report):
            return 1
        return int(report['status'] != 'PASS')
    except Exception:
        print('{"schemaVersion":"FUSE-FRESH-DIAGNOSTIC-1","status":"INVALID"}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
