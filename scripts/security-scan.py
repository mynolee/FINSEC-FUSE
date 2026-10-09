#!/usr/bin/env python3
"""Local candidate-only scanning. Only fixed aggregate fields may leave this process.

No cloud SAST, credentials, private inputs, raw findings, or automatic suppressions.
A missing tool/report, zero collection, skipped package, or finding blocks release.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
from datetime import date, datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {'semgrep': '1.99.0', 'detect-secrets': '1.5.0', 'pip-audit': '2.9.0', 'cyclonedx-bom': '5.3.0', 'cyclonedx-python-lib': '9.1.0'}
SCOPE = ('backend/src', 'agent', 'evaluation', 'frontend/src', 'frontend/tests', 'scripts', '.github/workflows', 'ingress')
EXCLUDED = {'node_modules', '__pycache__', '.pytest_cache', 'build', 'dist', 'exported_runs', '.git', '.venv', 'venv'}
SUFFIXES = {'.py', '.java', '.ts', '.tsx', '.js', '.json', '.yml', '.yaml', '.sh', '.txt', '.sql', '.properties', '.conf'}
MANIFESTS = ('build.gradle', 'settings.gradle', 'gradle/wrapper/gradle-wrapper.properties', 'agent/requirements.txt', 'agent/requirements-dev.txt', 'frontend/package.json', 'frontend/package-lock.json', 'compose.yaml', 'compose.dev.yaml', 'compose.live.yaml', 'compose.private.yaml', '.dockerignore', 'agent/Dockerfile', 'backend/Dockerfile', 'frontend/Dockerfile', 'scripts/security/requirements.txt', 'scripts/security/requirements.lock', 'ingress/Dockerfile', 'ingress/nginx.conf')


def candidate(root, destination):
    """Copy explicit first-party scope only; never traverse symlinks or private siblings."""
    count = 0
    digest = hashlib.sha256()
    for prefix in SCOPE:
        base = root / prefix
        if base.is_symlink():
            raise ValueError('symlink scope')
        if not base.is_dir():
            raise ValueError('missing scope')
        for path in sorted(base.rglob('*')):
            relative = path.relative_to(root)
            if any(part in EXCLUDED for part in relative.parts):
                continue
            if path.is_symlink():
                raise ValueError('symlink candidate')
            if not path.is_file() or path.suffix not in SUFFIXES or path.name.startswith('.env'):
                continue
            if path.stat().st_size > 5_000_000:
                raise ValueError('oversized candidate')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            data = path.read_bytes()
            target.write_bytes(data)
            digest.update(str(relative).encode() + b'\0' + data)
            count += 1
    return count, digest.hexdigest()


def verdict(collected=0, findings=0, skipped=0, code=None, available=True):
    if any(type(value) is not int or value < 0 for value in (collected, findings, skipped)):
        return {'status': 'ERROR', 'collected': 0, 'findings': 0, 'skipped': 0, 'exitCode': 2}
    if not available or code is None:
        status = 'NOT_RUN'
    elif code not in (0, 1) or collected <= 0 or skipped:
        status = 'ERROR'
    elif findings or code:
        status = 'FAIL'
    else:
        status = 'PASS'
    return {'status': status, 'collected': collected, 'findings': findings, 'skipped': skipped, 'exitCode': code}


def run(command, cwd, timeout=300):
    env = {k: v for k, v in os.environ.items() if k in {'PATH', 'HOME', 'TMPDIR', 'RUNNER_TEMP', 'SYSTEMROOT', 'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'SSL_CERT_FILE', 'REQUESTS_CA_BUNDLE', 'PIP_PROXY', 'NODE_EXTRA_CA_CERTS'}}
    env.update({'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
    if os.getenv('CODEX_PROXY_CERT'):
        env.setdefault('NODE_EXTRA_CA_CERTS', os.environ['CODEX_PROXY_CERT'])
        env.setdefault('REQUESTS_CA_BUNDLE', os.environ['CODEX_PROXY_CERT'])
    # stdout and stderr remain private. Never print an exception containing tool text.
    try:
        with tempfile.TemporaryDirectory(prefix='fuse-scanner-cache-') as cache:
            env['XDG_CACHE_HOME'] = cache
            env['XDG_CONFIG_HOME'] = cache
            env['SEMGREP_SETTINGS_FILE'] = str(Path(cache) / 'semgrep-settings.yml')
            result = subprocess.run(command, cwd=cwd, capture_output=True, timeout=timeout, env=env)
        return result.returncode, result.stdout
    except (OSError, subprocess.TimeoutExpired):
        return None, b''


def parse(raw):
    return json.loads(raw)


def metadata_fingerprint(path, row, root):
    """Only a complete named fingerprint field at its exact occurrence is metadata."""
    if row.get('type') != 'Hex High Entropy String':
        return False
    if path == 'scripts/security/dependency-review.json':
        try:
            source = (root / path).read_text()
            document = json.loads(source)
            if set(document) != {'schemaVersion', 'status', 'decision', 'impactTests', 'sha256'} or document['schemaVersion'] != 1 or set(document['sha256']) != set(MANIFESTS):
                return False
            line = source.splitlines()[row['line_number'] - 1]
            match = re.fullmatch(r'\s*"([^"]+)": "([0-9a-f]{64})",?\s*', line)
            if not match:
                return False
            key, value = match.groups()
            return key in MANIFESTS and document['sha256'][key] == value and hashlib.sha256((root / key).read_bytes()).hexdigest() == value and hashlib.sha1(value.encode()).hexdigest() == row['hashed_secret']
        except (OSError, ValueError, KeyError, TypeError, IndexError):
            return False
    if path != 'scripts/security/secret-review.json':
        return False
    try:
        source = (root / path).read_text()
        document = json.loads(source)
        required = {'path', 'type', 'fingerprintSha1', 'lineNumber', 'fileSha256', 'reason', 'reviewedOn', 'expiresOn'}
        if document.get('schemaVersion') != 1 or set(document) - {'schemaVersion', 'status', 'reviewerRole', 'findings'}:
            return False
        if not isinstance(document.get('findings'), list) or any(set(r) != required for r in document['findings']):
            return False
        for record in document['findings']:
            if not re.fullmatch(r'[0-9a-f]{40}', record['fingerprintSha1']) or not re.fullmatch(r'[0-9a-f]{64}', record['fileSha256']):
                return False
        line = source.splitlines()[row['line_number'] - 1]
        match = re.fullmatch(r'\s*"(fingerprintSha1|fileSha256)": "([0-9a-f]+)",?\s*', line)
        if not match:
            return False
        key, value = match.groups()
        expected_length = 40 if key == 'fingerprintSha1' else 64
        return len(value) == expected_length and hashlib.sha1(value.encode()).hexdigest() == row['hashed_secret']
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return False


def secret_findings(data, root):
    findings = [(path, row) for path, rows in data['results'].items() for row in rows if not metadata_fingerprint(path, row, root)]
    try:
        review = json.loads((root / 'scripts/security/secret-review.json').read_text())
        if review['status'] != 'APPROVED':
            return len(findings)
        today = datetime.now(timezone.utc).date()
        candidate_paths = {path for path, _ in findings}
        approved = {(r['path'], r['type'], r['fingerprintSha1'], r['lineNumber']) for r in review['findings']
                    if r['path'] in candidate_paths and not Path(r['path']).is_absolute() and '..' not in Path(r['path']).parts and date.fromisoformat(r['expiresOn']) >= today and date.fromisoformat(r['reviewedOn']) <= today and r['reason'] and
                    hashlib.sha256((root / r['path']).read_bytes()).hexdigest() == r['fileSha256']}
        return sum((path, row['type'], row['hashed_secret'], row['line_number']) not in approved for path, row in findings)
    except (OSError, KeyError, ValueError, TypeError):
        return len(findings)


def dependency_review(root):
    try:
        review = json.loads((root / 'scripts/security/dependency-review.json').read_text())
        approved = review['status'] == 'APPROVED' and bool(review['decision']) and bool(review['impactTests'])
        expected = review['sha256']
        valid = approved and set(expected) == set(MANIFESTS) and all(
            re.fullmatch(r'[0-9a-f]{64}', expected[p]) and
            hashlib.sha256((root / p).read_bytes()).hexdigest() == expected[p] for p in MANIFESTS)
        return verdict(len(MANIFESTS), 0 if valid else 1, 0, 0)
    except (OSError, ValueError, KeyError, TypeError):
        return verdict(code=2)


def maven_scan(root):
    """OSV v1 queries contain only validated public Maven package coordinates."""
    try:
        inventory = json.loads((root / 'backend/build/reports/security/dependency-inventory.json').read_text())
        if inventory['schemaVersion'] != 'FUSE-DEPENDENCY-INVENTORY-1':
            raise ValueError('schema')
        if inventory.get('buildGradleSha256') != hashlib.sha256((root / 'build.gradle').read_bytes()).hexdigest() or inventory.get('settingsGradleSha256') != hashlib.sha256((root / 'settings.gradle').read_bytes()).hexdigest():
            raise ValueError('stale inventory')
        configurations = inventory['configurations']
        if any(not configurations.get(k) for k in ('runtimeClasspath', 'testRuntimeClasspath')):
            raise ValueError('missing resolution')
        coordinates = sorted({(x['group'], x['name'], x['version']) for rows in configurations.values() for x in rows})
        if not coordinates or len(coordinates) > 2000:
            raise ValueError('count')
        for coordinate in coordinates:
            if any(not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,180}', value) for value in coordinate):
                raise ValueError('coordinate')
        queries = [{'package': {'ecosystem': 'Maven', 'name': g + ':' + n}, 'version': v} for g, n, v in coordinates]
        findings = 0
        for offset in range(0, len(queries), 100):
            batch = queries[offset:offset + 100]
            request = urllib.request.Request('https://api.osv.dev/v1/querybatch',
                data=json.dumps({'queries': batch}).encode(), headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(request, timeout=45) as response:
                result = json.load(response)
            if len(result['results']) != len(batch):
                raise ValueError('incomplete response')
            findings += sum(len(row.get('vulns', [])) for row in result['results'])
        return verdict(len(coordinates), findings, 0, 0), verdict(len(coordinates), 0, 0, 0)
    except Exception:
        return verdict(code=2), verdict(code=2)


def maven_sbom(root, private_reports=None):
    """Generate real CycloneDX with the pinned library from resolved Gradle coordinates."""
    try:
        if importlib.metadata.version('cyclonedx-python-lib') != TOOLS['cyclonedx-python-lib']:
            return verdict(available=False)
        from cyclonedx.model.bom import Bom
        from cyclonedx.model.component import Component, ComponentType
        from cyclonedx.output import make_outputter, OutputFormat
        from cyclonedx.schema import SchemaVersion
        from packageurl import PackageURL
        inventory = json.loads((root / 'backend/build/reports/security/dependency-inventory.json').read_text())
        if inventory['schemaVersion'] != 'FUSE-DEPENDENCY-INVENTORY-1' or inventory.get('buildGradleSha256') != hashlib.sha256((root / 'build.gradle').read_bytes()).hexdigest() or inventory.get('settingsGradleSha256') != hashlib.sha256((root / 'settings.gradle').read_bytes()).hexdigest():
            raise ValueError('stale inventory')
        configurations = inventory['configurations']
        if any(not configurations.get(k) for k in ('runtimeClasspath', 'testRuntimeClasspath')):
            raise ValueError('missing resolution')
        coordinates = sorted({(x['group'], x['name'], x['version']) for rows in configurations.values() for x in rows})
        bom = Bom()
        for group, name, version in coordinates:
            if any(not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,180}', value) for value in (group, name, version)):
                raise ValueError('coordinate')
            bom.components.add(Component(name=name, group=group, version=version, type=ComponentType.LIBRARY,
                purl=PackageURL(type='maven', namespace=group, name=name, version=version)))
        raw = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5).output_as_string()
        if private_reports is not None:
            (private_reports / 'maven-sbom.json').write_text(raw)
        return verdict(len(json.loads(raw)['components']), 0, 0, 0)
    except Exception:
        return verdict(code=2)


def execute(root, work, private_reports=None):
    report = {'schemaVersion': 1, 'observedAt': datetime.now(timezone.utc).isoformat(),
              'scope': list(SCOPE), 'excluded': ['private inputs', 'private prompts', 'environment files', 'caches', 'generated outputs'],
              'exceptions': [], 'exceptionExpiry': None, 'tools': {}, 'checks': {},
              'limitations': ['Targeted local SAST rules are not comprehensive.', 'Scanners do not replace API, database, browser or independent security review.']}
    git_code, git_raw = run(['git', 'rev-parse', 'HEAD'], root)
    report['commit'] = git_raw.decode().strip() if git_code == 0 and re.fullmatch(rb'[0-9a-f]{40}\s*', git_raw) else None
    report['treeBinding'] = 'candidateSha256 and manifestSha256 bind the actual working tree; commit alone does not'
    count, digest = candidate(root, work / 'candidate')
    report['candidateFiles'] = count
    report['candidateSha256'] = digest
    report['manifestSha256'] = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in MANIFESTS if (root / p).is_file()}
    for tool, version in TOOLS.items():
        try:
            actual = importlib.metadata.version(tool)
        except importlib.metadata.PackageNotFoundError:
            actual = None
        report['tools'][tool] = {'expected': version, 'observed': actual, 'versionMatched': actual == version}
    def check(name, tool, command, reader, cwd=None):
        if tool and not report['tools'][tool]['versionMatched']:
            report['checks'][name] = verdict(available=False)
            return
        code, raw = run(command, cwd or work / 'candidate')
        if private_reports is not None:
            (private_reports / (name + '.json')).write_bytes(raw)
        try:
            data = parse(raw)
            collected, findings, skipped = reader(data)
            report['checks'][name] = verdict(collected, findings, skipped, code)
            return data
        except (ValueError, TypeError, KeyError, AttributeError):
            report['checks'][name] = verdict(code=code if code not in (0, 1) else 2)
    check('sast', 'semgrep', ['semgrep', 'scan', '--config', str(work / 'candidate/scripts/security/semgrep.yml'), '--json', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--jobs=2', '--timeout=20', '.'],
          lambda d: (len(d['paths']['scanned']), len(d['results']), len(d.get('errors', []))))
    secret_data = check('secrets', 'detect-secrets', ['detect-secrets', 'scan', '--all-files', '--no-verify', '.'],
          lambda d: (count, secret_findings(d, root), 0))
    if secret_data:
        raw_count = sum(len(v) for v in secret_data['results'].values())
        report['checks']['secrets']['candidateFindings'] = raw_count
        report['checks']['secrets']['reviewedFalsePositives'] = raw_count - report['checks']['secrets']['findings']
    python_dependencies = check('python-sca', 'pip-audit', ['pip-audit', '-r', str(root / 'agent/requirements-dev.txt'), '--format=json', '--progress-spinner=off'],
          lambda d: (len(d['dependencies']), sum(len(x.get('vulns', [])) for x in d['dependencies']), sum('skip_reason' in x for x in d['dependencies'])))
    check('npm-sca', None, ['npm', 'audit', '--json', '--package-lock-only', '--ignore-scripts'],
          lambda d: (d['metadata']['dependencies']['total'], d['metadata']['vulnerabilities']['total'], 0), root / 'frontend')
    code, raw = run(['npm', '--version'], root)
    npm_version = raw.decode().strip() if code == 0 and re.fullmatch(rb'[0-9.]+\s*', raw) else None
    report['tools']['npm'] = {'expected': '11.9.0', 'observed': npm_version, 'versionMatched': npm_version == '11.9.0'}
    resolved_python = work / 'python-resolved.txt'
    if python_dependencies and not any('skip_reason' in x for x in python_dependencies.get('dependencies', [])):
        resolved_python.write_text(''.join(x['name'] + '==' + x['version'] + '\n' for x in python_dependencies['dependencies']))
    check('python-sbom', 'cyclonedx-bom', ['cyclonedx-py', 'requirements', str(resolved_python), '--output-format=JSON', '--outfile=-'],
          lambda d: (len(d['components']), 0, 0))
    check('npm-sbom', None, ['npm', 'sbom', '--sbom-format=cyclonedx', '--package-lock-only', '--ignore-scripts'],
          lambda d: (len(d['components']), 0, 0), root / 'frontend')
    if not report['tools']['npm']['versionMatched']:
        report['checks']['npm-sca'] = verdict(available=False)
        report['checks']['npm-sbom'] = verdict(available=False)
    report['checks']['dependency-review'] = dependency_review(root)
    report['tools']['maven-sca'] = {'observed': 'OSV API v1; local coordinate adapter 1'}
    report['checks']['maven-sca'], report['checks']['maven-inventory'] = maven_scan(root)
    report['checks']['maven-sbom'] = maven_sbom(root, private_reports)
    after_count, after_digest = candidate(root, work / 'current')
    manifests_current = {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in MANIFESTS if (root / p).is_file()}
    unchanged = after_count == count and after_digest == digest and manifests_current == report['manifestSha256']
    report['checks']['source-currentness'] = verdict(1, 0 if unchanged else 1, 0, 0)
    report['status'] = 'PASS' if all(c['status'] == 'PASS' for c in report['checks'].values()) else 'BLOCKED'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-reports', help='Optional existing directory outside the repository; never uploaded')
    parser.add_argument('--verify-locks', action='store_true', help='Verify dependency review only; full scans also enforce this gate')
    parser.add_argument('--output', default='safe-artifacts/security-summary.json')
    args = parser.parse_args()
    if args.verify_locks:
        result = dependency_review(ROOT)
        print('dependency-review: ' + result['status'])
        return 0 if result['status'] == 'PASS' else 1
    private_reports = Path(args.private_reports).resolve() if args.private_reports else None
    if private_reports is not None and (private_reports.is_relative_to(ROOT) or not private_reports.is_dir()):
        parser.error('private report directory must already exist outside repository')
    with tempfile.TemporaryDirectory(prefix='fuse-scan-', dir=os.getenv('RUNNER_TEMP')) as directory:
        try:
            report = execute(ROOT, Path(directory), private_reports)
        except Exception:
            report = {'schemaVersion': 1, 'status': 'BLOCKED', 'reason': 'SCAN_SETUP_ERROR', 'checks': {}}
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + '\n')
    print('security-scan: ' + report['status'] + '; only aggregate report retained')
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
