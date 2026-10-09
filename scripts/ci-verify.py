#!/usr/bin/env python3
"""CI-only checks against an isolated mock Compose project; never print credentials."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.request import ProxyHandler, Request, build_opener, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SAFE = ROOT / 'safe-artifacts'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = build_opener(ProxyHandler({}), NoRedirect())


def credentials(path: Path = ROOT / '.env') -> dict[str, str]:
    # Parse data, never source shell code. Only bootstrap's literal hex credentials.
    result = {}
    for line in path.read_text().splitlines():
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key in result:
            raise ValueError('Duplicate configuration field')
        result[key] = value
    keys = ['FUSE_DB_PASSWORD', 'FUSE_DB_OWNER_PASSWORD', 'FUSE_EXPERIMENT_DB_PASSWORD',
            'FUSE_SERVICE_TOKEN', 'FUSE_REVIEWER_TOKEN', 'FUSE_SECURITY_TOKEN', 'FUSE_DEVELOPER_TOKEN']
    keys += [f'FUSE_CUSTOMER_{number}_TOKEN' for number in range(101, 105)]
    if any(not re.fullmatch(r'[a-f0-9]{64}', result.get(key, '')) for key in keys):
        raise ValueError('Fresh random bootstrap credentials required')
    if len({result[key] for key in keys}) != len(keys):
        raise ValueError('Role credentials must be independent')
    if result.get('FUSE_KYC_MODE') != 'replay' or result.get('FUSE_EXPERIMENT_LIVE_ENABLED') != 'false':
        raise ValueError('Only disabled-provider replay is allowed in CI')
    if any(result.get(key) for key in ('FUSE_LLM_API_KEY', 'FUSE_LLM_MODEL', 'FUSE_KYC_PROMPT_PATH', 'FUSE_PRIVATE_DOCUMENTS_PATH')):
        raise ValueError('Private assets and provider settings are not allowed in CI')
    return result


def emit(name: str, value: dict) -> None:
    SAFE.mkdir(mode=0o700, exist_ok=True)
    path = SAFE / name
    with path.open('w') as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write('\n')
    path.chmod(0o600)


def request(path: str, token: str | None = None, *, port=8080):
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    with HTTP.open(Request(f'http://127.0.0.1:{port}{path}', headers=headers), timeout=5) as response:
        return json.load(response)


def prepare() -> None:
    if (ROOT / '.env').exists() or (ROOT / '.secrets/signing.key').exists():
        raise ValueError('CI refuses an existing configuration; use a fresh checkout')
    # The CI runner supplies only this project's name; cleanup uses the same name.
    if not re.fullmatch(r'fuse-ci-[0-9]+-[0-9]+', os.getenv('COMPOSE_PROJECT_NAME', '')):
        raise ValueError('Missing isolated CI Compose project name')
    forbidden = [key for key, value in os.environ.items()
                 if value and (key.startswith(('FUSE_', 'SPRING_')) and key not in {'FUSE_UI_URL', 'FUSE_E2E_INTEGRATION', 'FUSE_E2E_ENV_FILE', 'FUSE_E2E_SUMMARY_PATH', 'FUSE_UI_SECURITY_HEADERS'})]
    if os.getenv('FUSE_UI_SECURITY_HEADERS', '1') != '1':
        raise ValueError('Security header browser checks must be enabled in CI')
    if forbidden:
        raise ValueError('Ambient application configuration cannot override generated CI configuration')
    subprocess.run(['bash', 'scripts/bootstrap-dev.sh'], cwd=ROOT, check=True, capture_output=True)
    credentials()
    print('Fresh isolated replay configuration generated; credentials remain private.')


def ready() -> None:
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            # Agent has no published host port. Readiness is checked within its container;
            # capture output so configuration/error bodies never reach CI logs.
            probe = ('import json,os,urllib.request; '
                     'assert os.environ.get("FUSE_KYC_MODE") == "replay"; '
                     'r=urllib.request.urlopen("http://127.0.0.1:8001/ready",timeout=5); '
                     'd=json.load(r); assert r.status == 200 and d.get("ready") is True')
            agent = subprocess.run(['docker', 'compose', 'exec', '-T', 'agent', 'python', '-c', probe],
                                   cwd=ROOT, capture_output=True, timeout=10)
            backend = request('/actuator/health/readiness')
            with HTTP.open('http://127.0.0.1:5173/', timeout=5) as response:
                frontend = response.status == 200 and b'<div id="root">' in response.read()
            if agent.returncode == 0 and backend.get('status') == 'UP' and frontend:
                emit('compose-readiness.json', {'agent': 'READY_REPLAY', 'backend': 'UP', 'frontend': 'HTTP_200', 'providerCalls': False})
                return
        except Exception:
            pass
        time.sleep(1)
    raise TimeoutError('Compose services did not become ready')


def smoke() -> None:
    tokens = credentials()
    env = {key: value for key, value in os.environ.items() if not key.startswith(('FUSE_', 'SPRING_'))}
    env.update({key: value for key, value in tokens.items() if key.endswith('_TOKEN')})
    env.update(FUSE_BASE_URL='http://127.0.0.1:8080', NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
    process = subprocess.run([sys.executable, 'scripts/run_demo.py'], cwd=ROOT, env=env,
                             capture_output=True, text=True, timeout=200)
    if process.returncode:
        raise RuntimeError('Actual HTTP mock workflow smoke failed')
    rows = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    by_customer = {row['customer']: row for row in rows}
    if len(rows) != 2 or set(by_customer) != {101, 102}:
        raise ValueError('Wrong HTTP smoke observation count')
    clean = []
    for customer, expected, points in ((101, 'BLOCKED', 10), (102, 'PAID', 85)):
        row = by_customer[customer]
        if (row['state'], row['usedRisk'], row['reservedRisk']) != (expected, points, 0):
            raise ValueError('Observed HTTP workflow state does not match the contract')
        trace = request(f"/api/v1/workflows/{row['workflowId']}/trace", tokens['FUSE_REVIEWER_TOKEN'])
        payments = trace['payments']
        if len(payments) != int(customer == 102):
            raise ValueError('Actual ledger count does not match the HTTP workflow')
        clean.append({'mockCustomer': customer, 'state': expected, 'usedRisk': points, 'reservedRisk': 0,
                      'paymentCount': len(payments)})
    emit('http-smoke.json', {'status': 'PASS', 'source': 'REAL_HTTP_AND_PERSISTED_TRACE', 'observations': clean})


def database() -> None:
    project = os.getenv('COMPOSE_PROJECT_NAME', '')
    if not re.fullmatch(r'fuse-ci-[0-9]+-[0-9]+', project):
        raise ValueError('Only the isolated CI database can be inspected')
    query = """SELECT json_build_object('mockCustomer', a.customer_id, 'state', w.state,
        'generation', w.generation, 'usedRisk', w.used_risk, 'reservedRisk', w.reserved_risk,
        'paymentCount', (SELECT count(*) FROM mock_payment p WHERE p.workflow_id=w.id),
        'consumeCount', (SELECT count(*) FROM risk_ledger r WHERE r.workflow_id=w.id AND r.event_type='CONSUME'),
        'consumedApprovals', (SELECT count(*) FROM approval a2 WHERE a2.workflow_id=w.id AND a2.status='CONSUMED'),
        'kycRunCount', (SELECT run_count FROM workflow_stage s WHERE s.workflow_id=w.id AND s.stage='KYC'))
        FROM workflow w JOIN loan_application a ON a.id=w.application_id ORDER BY a.customer_id"""
    process = subprocess.run(['docker', 'compose', '--project-name', project, 'exec', '-T', 'postgres',
                              'psql', '-X', '-A', '-t', '-U', 'fuse_owner', '-d', 'fuse', '-v', 'ON_ERROR_STOP=1', '-c', query],
                             capture_output=True, text=True, check=True, timeout=30)
    rows = [json.loads(line) for line in process.stdout.splitlines() if line.strip()]
    observed = {row['mockCustomer']: row for row in rows}
    expected = {'customer-101': ('BLOCKED', 1, 10, 0, 0, 0, 0, 1),
                'customer-102': ('PAID', 1, 85, 0, 1, 1, 1, 1),
                'customer-103': ('REJECTED', 2, 35, 0, 0, 0, 0, 2)}
    keys = ('state', 'generation', 'usedRisk', 'reservedRisk', 'paymentCount', 'consumeCount', 'consumedApprovals', 'kycRunCount')
    if set(observed) != set(expected) or len(rows) != 3:
        raise ValueError('Database observation set differs from the three browser scenarios')
    if any(tuple(observed[customer][key] for key in keys) != values for customer, values in expected.items()):
        raise ValueError('Database invariants do not match the browser and HTTP claims')
    emit('database-check.json', {'status': 'PASS', 'source': 'POSTGRESQL_READ_ONLY_QUERY', 'observations': rows})


def validate_bundle(bundle: Path, secret_values: list[str]) -> list[str]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError('Unsafe evidence directory')
    manifest_path = bundle / 'manifest.json'
    if manifest_path.is_symlink():
        raise ValueError('Unsafe evidence manifest')
    manifest = json.loads(manifest_path.read_bytes())
    required = {'case_results.json', 'case_results.csv', 'metrics.json'}
    files = manifest['files']
    if not required.issubset(files):
        raise ValueError('Evidence manifest lacks required files')
    names = ['manifest.json', *files]
    allowed = re.compile(r'(case_results\.(csv|json)|metrics\.json|traces/[0-9]{6}-(baseline|fuse)\.json)')
    if any(not allowed.fullmatch(name) for name in files):
        raise ValueError('Unexpected artifact path in evidence manifest')
    actual = {str(path.relative_to(bundle)) for path in bundle.rglob('*') if path.is_file() or path.is_symlink()}
    if actual != set(names) or any(path.is_symlink() for path in bundle.rglob('*')):
        raise ValueError('Evidence directory contains unlisted files or symlinks')
    for name in names:
        content = (bundle / name).read_bytes()
        if any(value.encode() in content for value in secret_values) or b'Bearer ' in content:
            raise ValueError('Credential content detected; artifact publication blocked')
        if name != 'manifest.json' and (hashlib.sha256(content).hexdigest() != files[name]['sha256'] or len(content) != files[name]['bytes']):
            raise ValueError('Evidence payload does not match its manifest')
    return names


def evidence() -> None:
    from evaluation.fixture_loader import load_fixture_set
    from evaluation.scenario_runner import execute_java, normalize_java_report
    from evaluation.export import export_evidence_bundle
    tokens = credentials()
    manifest = load_fixture_set('security-evaluation-v1', [])
    # Private API diagnostics stay in an automatically removed temp directory.
    with tempfile.TemporaryDirectory(prefix='fuse-private-ci-') as work:
        raw = execute_java(manifest, 'http://127.0.0.1:8080', tokens['FUSE_DEVELOPER_TOKEN'],
                           'REPLAY', 1, Path(work), deadline_seconds=900)
        report = normalize_java_report(raw, manifest, 'REPLAY', 1)
        bundle = export_evidence_bundle(report, manifest, Path(work) / 'safe')
        secret_values = [value for key, value in tokens.items() if key.endswith(('_TOKEN', '_PASSWORD')) and len(value) >= 32]
        names = validate_bundle(bundle, secret_values)
        destination = SAFE / 'evidence' / bundle.name
        destination.mkdir(parents=True, mode=0o700)
        for name in names:
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copyfile(bundle / name, path)
            path.chmod(0o600)
        if report.status != 'COMPLETED' or len(report.caseOutputs) != 120 or report.metrics['excludedPairCount'] != 0:
            raise ValueError('Full replay did not finish all 120 environment results without exclusions')
        rows = json.loads((destination / 'case_results.json').read_bytes())
        if any(row['expectedMatch'] is not True for row in rows):
            raise ValueError('Full replay contains an expectation mismatch or missing result')
        emit('experiment-summary.json', {'status': 'PASS', 'fixtureSetId': 'security-evaluation-v1',
             'plannedCases': 60, 'environmentResults': 120, 'modelMode': 'REPLAY', 'syntheticModelOutputs': True,
             'liveRobustnessMeasured': False, 'source': 'JAVA_POSTGRES_EXECUTION'})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'ready', 'smoke', 'database', 'evidence'])
    args = parser.parse_args()
    try:
        globals()[args.command]()
        print(f'CI {args.command}: PASS')
        return 0
    except Exception as error:
        # No exception strings: dependencies can echo request bodies/headers.
        print(f'CI {args.command}: FAIL ({type(error).__name__}); no completion claimed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
