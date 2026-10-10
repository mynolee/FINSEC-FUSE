#!/usr/bin/env python3
"""Closed, revision-bound evidence for one real Python replay startup test.

Run with python -I -B; default policy or --case service-token. Only fixed outcomes and validated CI identities are public.
A verified source snapshot avoids untracked modules and stale bytecode. This is
not an attestation against a compromised Python installation or CI runner.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).absolute().parents[1]
TEST = 'agent.tests.test_startup_process.PythonStartupProcessTest.test_missing_policy_process_refuses_startup_and_new_valid_process_recovers'
CASES = {
    'policy': (TEST, 'agent/tests/test_startup_process.py'),
    'service-token': (
        'agent.tests.test_startup_process.PythonStartupProcessTest.test_missing_service_token_process_refuses_startup_and_new_valid_process_recovers',
        'agent/tests/test_startup_process.py'),
}
POLICY = 'backend/src/main/resources/config/security_policy.json'
RUNNER = 'scripts/ci-python-startup-report.py'
PINS = {'fastapi': '0.136.1', 'pydantic': '2.12.5', 'httpx': '0.28.1',
        'httpcore': '1.0.9', 'uvicorn': '0.34.3', 'pytest': '9.0.3'}
COUNTS = ('executed', 'passed', 'failures', 'errors', 'skips', 'expectedFailures', 'unexpectedSuccesses')
LIMIT = 1024 * 1024


class Invalid(ValueError):
    pass


def require(value):
    if not value:
        raise Invalid()


def case_details(case):
    require(type(case) is str and case in CASES)
    return CASES[case]


def safe_read(path):
    path = Path(path).absolute()
    require('..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2:
                flags |= os.O_DIRECTORY
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_size <= LIMIT)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(LIMIT + 1)
        require(len(data) <= LIMIT)
        return data
    finally:
        os.close(fd)


def environment():
    # No inherited provider, Python, Git, proxy, token or loader configuration.
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
            'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0'}


def git(root, *args):
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['/usr/bin/git', '-C', str(root), *args], env=environment(),
                                stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.DEVNULL, timeout=20)
        require(result.returncode == 0 and output.tell() <= LIMIT)
        output.seek(0)
        return output.read(LIMIT + 1)


def context(env, root):
    head, run, attempt = (env.get(k, '') for k in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    require(re.fullmatch('[a-f0-9]{40}', head) and re.fullmatch('[1-9][0-9]{0,19}', run)
            and re.fullmatch('[1-9][0-9]{0,5}', attempt))
    require(env.get('GITHUB_WORKSPACE') == str(root))
    return {'checkout': head, 'run': run, 'attempt': attempt}


def source(root, head, case='policy'):
    _, test_path = case_details(case)
    require(git(root, 'rev-parse', '--show-toplevel').strip() == str(root).encode())
    require(git(root, 'rev-parse', '--verify', 'HEAD').strip() == head.encode())
    entries = git(root, 'ls-tree', '-rz', 'HEAD', '--', 'agent', POLICY, RUNNER).split(b'\0')
    require(1 < len(entries) <= 513)
    files, total = {}, 0
    for entry in entries:
        if not entry:
            continue
        meta, raw = entry.split(b'\t', 1)
        mode, kind, oid = meta.split()
        name = raw.decode('ascii')
        require(mode in (b'100644', b'100755') and kind == b'blob')
        require(re.fullmatch('[A-Za-z0-9_./-]{1,256}', name)
                and all(p not in ('', '.', '..', '__pycache__') for p in name.split('/'))
                and not name.endswith(('.pyc', '.pyo')))
        data = safe_read(root / name)
        total += len(data)
        require(total <= 16 * LIMIT and data == git(root, 'cat-file', 'blob', oid.decode('ascii')))
        files[name] = data
    require({POLICY, RUNNER, 'agent/__init__.py', test_path, 'agent/app.py',
             'agent/security_policy.py', 'agent/requirements.txt', 'agent/requirements-dev.txt'} <= files.keys())
    digest = hashlib.sha256()
    for name, data in sorted(files.items()):
        digest.update(name.encode() + b'\0' + hashlib.sha256(data).digest())
    return files, digest.hexdigest()


def pinned():
    return (sys.version_info[:3] == (3, 12, 15)
            and all(importlib.metadata.version(name) == version for name, version in PINS.items()))


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.identities = []
        self.passed = 0

    def startTest(self, test):
        self.identities.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.passed += 1
        super().addSuccess(test)


def execute(suite, case='policy'):
    identity, _ = case_details(case)
    require(suite.countTestCases() == 1)
    result = Result()
    suite.run(result)
    return {'identity': identity, 'identities': result.identities,
            'counts': dict(zip(COUNTS, (result.testsRun, result.passed, len(result.failures),
                         len(result.errors), len(result.skipped), len(result.expectedFailures),
                         len(result.unexpectedSuccesses))))}


def validate(payload, case='policy'):
    identity, _ = case_details(case)
    require(type(payload) is dict and set(payload) == {'identity', 'identities', 'counts'})
    require(payload['identity'] == identity and payload['identities'] == [identity])
    counts = payload['counts']
    require(type(counts) is dict and set(counts) == set(COUNTS))
    require(all(type(counts[k]) is int and 0 <= counts[k] <= 1 for k in COUNTS))
    require(counts['executed'] == 1 and sum(counts[k] for k in COUNTS[1:]) == 1)
    return {key: counts[key] for key in COUNTS}


def worker(snapshot, case='policy'):
    # Capture file-descriptor writes as well as Python prints and tracebacks.
    output = os.dup(1)
    with open(os.devnull, 'wb') as private:
        os.dup2(private.fileno(), 1)
        os.dup2(private.fileno(), 2)
    try:
        identity, test_path = case_details(case)
        require(pinned())
        sys.path.insert(0, str(snapshot))
        suite = unittest.defaultTestLoader.loadTestsFromName(identity)
        require(not unittest.defaultTestLoader.errors)
        loaded = sys.modules.get(identity.rsplit('.', 2)[0])
        require(loaded is not None and Path(loaded.__file__).absolute()
                == snapshot / test_path)
        payload = execute(suite, case)
        validate(payload, case)
        encoded = json.dumps(payload).encode()
        require(len(encoded) <= 8192)
        os.write(output, encoded)
        return 0
    except BaseException:
        return 1
    finally:
        os.close(output)


def run_snapshot(directory, case='policy'):
    case_details(case)
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([sys.executable, '-I', '-B', str(directory / RUNNER), '--worker', '--case', case],
                                   cwd=directory, env=environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            code = process.wait(timeout=100)
        finally:
            # Includes any still-running Uvicorn descendants on failure/timeout.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        require(code == 0 and 0 < output.tell() <= 8192)
        output.seek(0)
        def pairs(items):
            obj = {}
            for key, value in items:
                require(key not in obj)
                obj[key] = value
            return obj
        return validate(json.loads(output.read(8193), object_pairs_hook=pairs), case)


def report(root=ROOT, env=None, case='policy'):
    identity, _ = case_details(case)
    result = {'schemaVersion': 'FUSE-PYTHON-STARTUP-EVIDENCE-1', 'identity': identity,
              'outcome': 'UNAVAILABLE', 'reason': 'CONTEXT_REJECTED',
              'counts': dict.fromkeys(COUNTS, 0), 'binding': None, 'sourceSha256': None}
    try:
        result['binding'] = context(os.environ if env is None else env, root)
        result['reason'] = 'SOURCE_REJECTED'
        files, digest = source(root, result['binding']['checkout'], case)
        result['sourceSha256'] = digest
        result['reason'] = 'DEPENDENCIES_UNAVAILABLE'
        require(pinned())
        result['reason'] = 'EXECUTION_REJECTED'
        with tempfile.TemporaryDirectory(prefix='startup-evidence-') as temporary:
            snapshot = Path(temporary)
            for name, data in files.items():
                target = snapshot / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            counts = run_snapshot(snapshot, case)
            result['reason'] = 'SOURCE_CHANGED'
            require(source(root, result['binding']['checkout'], case)[1] == digest)
            require(all(safe_read(snapshot / name) == data for name, data in files.items()))
        result['counts'] = counts
        result['outcome'] = 'PASS' if counts['passed'] == 1 else 'FAIL'
        result['reason'] = 'COMPLETE' if counts['passed'] == 1 else 'TEST_NOT_PASSED'
    except BaseException:
        pass
    return result


def arguments(args):
    # Exact argument shapes only: never accept a caller-selected module or path.
    worker_mode = bool(args and args[0] == '--worker')
    rest = args[1:] if worker_mode else args
    if not rest:
        return worker_mode, 'policy'
    require(len(rest) == 2 and rest[0] == '--case')
    case_details(rest[1])
    return worker_mode, rest[1]


def main():
    try:
        require(sys.flags.isolated and sys.flags.dont_write_bytecode)
        worker_mode, case = arguments(sys.argv[1:])
    except (Invalid, TypeError):
        print('PYTHON_STARTUP_ARGUMENTS_REJECTED')
        return 1
    if worker_mode:
        return worker(ROOT, case)
    result = report(case=case)
    print(json.dumps(result, sort_keys=True))
    return int(result['outcome'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
