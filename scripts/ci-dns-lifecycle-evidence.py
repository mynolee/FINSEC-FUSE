#!/usr/bin/env python3
"""Separate, fail-closed offline DNS evidence; never changes project-wide scope.

Run with python -I -B. Only fixed node IDs, PASS outcomes and revision/runtime
bindings are published. This does not attest a compromised CI runner.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import threading
import subprocess
import sys
import tempfile

ROOT = Path(__file__).absolute().parents[1]
RUNNER = 'scripts/ci-dns-lifecycle-evidence.py'
HELPER = 'scripts/ci-python-startup-report.py'
TEST = 'agent/tests/test_dns_lifecycle.py'
WORKFLOW = '.github/workflows/ci.yml'
ARTIFACT = 'dns-lifecycle-evidence.json'
# Fixed reviewed identities, not dynamically inferred from collection.
EXPECTED = (
    'agent/tests/test_dns_lifecycle.py::test_timeouts_keep_four_native_slots_and_recover_through_dns',
    'agent/tests/test_dns_lifecycle.py::test_cancellation_retains_slots_and_consumes_late_results[False]',
    'agent/tests/test_dns_lifecycle.py::test_cancellation_retains_slots_and_consumes_late_results[True]',
    'agent/tests/test_dns_lifecycle.py::test_distinct_closed_loops_share_default_process_capacity',
    'agent/tests/test_dns_lifecycle.py::test_queued_submissions_stay_bounded_until_real_completion',
    'agent/tests/test_dns_lifecycle.py::test_submission_failure_is_terminal_without_retry',
    'agent/tests/test_dns_lifecycle.py::test_inline_completion_releases_exactly_once',
    'agent/tests/test_dns_lifecycle.py::test_close_running_native_is_terminal_without_early_release',
    'agent/tests/test_dns_lifecycle.py::test_reduced_capacity_is_enforced_before_submission[1]',
    'agent/tests/test_dns_lifecycle.py::test_reduced_capacity_is_enforced_before_submission[2]',
    'agent/tests/test_dns_lifecycle.py::test_reduced_capacity_is_enforced_before_submission[4]',
    'agent/tests/test_dns_lifecycle.py::test_unsafe_dns_answers_fail_before_tcp[records0]',
    'agent/tests/test_dns_lifecycle.py::test_unsafe_dns_answers_fail_before_tcp[records1]',
    'agent/tests/test_dns_lifecycle.py::test_unsafe_dns_answers_fail_before_tcp[records2]',
    'agent/tests/test_dns_lifecycle.py::test_unregistered_destination_never_submits_dns[evil.invalid-443]',
    'agent/tests/test_dns_lifecycle.py::test_unregistered_destination_never_submits_dns[api.openai.com-80]',
    'agent/tests/test_dns_lifecycle.py::test_unregistered_destination_never_submits_dns[8.8.8.8-443]',
    'agent/tests/test_dns_lifecycle.py::test_submit_start_then_raise_cannot_refill_uncertain_slot',
    'agent/tests/test_dns_lifecycle.py::test_executor_construction_failure_is_terminal_with_no_native_reservation',
    'agent/tests/test_dns_lifecycle.py::test_native_error_releases_capacity_for_fresh_dns',
    'agent/tests/test_dns_lifecycle.py::test_completion_cancel_order_never_double_releases[True]',
    'agent/tests/test_dns_lifecycle.py::test_completion_cancel_order_never_double_releases[False]',
    'agent/tests/test_dns_lifecycle.py::test_close_races_with_submission_without_pool_replacement',
    'agent/tests/test_dns_lifecycle.py::test_inline_failed_future_releases_once_and_recovers',
    'agent/tests/test_dns_lifecycle.py::test_public_ipv4_ipv6_pinned_once_without_rebinding[8.8.8.8]',
    'agent/tests/test_dns_lifecycle.py::test_public_ipv4_ipv6_pinned_once_without_rebinding[2606:4700:4700::1111]',
    'agent/tests/test_dns_lifecycle.py::test_malformed_dns_never_reaches_tcp[records0]',
    'agent/tests/test_dns_lifecycle.py::test_malformed_dns_never_reaches_tcp[records1]',
    'agent/tests/test_dns_lifecycle.py::test_invalid_capacity_cannot_expand_process_limit[0]',
    'agent/tests/test_dns_lifecycle.py::test_invalid_capacity_cannot_expand_process_limit[5]',
    'agent/tests/test_dns_lifecycle.py::test_invalid_capacity_cannot_expand_process_limit[-1]',
    'agent/tests/test_dns_lifecycle.py::test_invalid_capacity_cannot_expand_process_limit[True]',
    'agent/tests/test_dns_lifecycle.py::test_invalid_capacity_cannot_expand_process_limit[1.5]',
    'agent/tests/test_dns_lifecycle.py::test_real_executor_enqueue_then_thread_start_failure_is_terminal',
    'agent/tests/test_dns_lifecycle.py::test_close_before_submission_creates_no_executor',
    'agent/tests/test_dns_lifecycle.py::test_asgi_default_limits_retain_native_dns_and_recover_same_adapter[False]',
    'agent/tests/test_dns_lifecycle.py::test_asgi_default_limits_retain_native_dns_and_recover_same_adapter[True]',
)

try:
    spec = importlib.util.spec_from_file_location('startup_evidence_helpers', ROOT / HELPER)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
except BaseException:
    print('DNS_LIFECYCLE_EVIDENCE_REJECTED: HELPER_REJECTED')
    raise SystemExit(1)
require = helper.require


def source(root, head):
    require(helper.git(root, 'rev-parse', '--show-toplevel').strip() == str(root).encode())
    require(helper.git(root, 'rev-parse', '--verify', 'HEAD').strip() == head.encode())
    tree = helper.git(root, 'rev-parse', 'HEAD^{tree}').strip().decode('ascii')
    require(re.fullmatch('[a-f0-9]{40}', tree))
    entries = helper.git(root, 'ls-tree', '-rz', 'HEAD', '--', 'agent', helper.POLICY,
                         RUNNER, HELPER, WORKFLOW).split(b'\0')
    require(1 < len(entries) <= 513)
    files, total, digest = {}, 0, hashlib.sha256()
    for entry in sorted(e for e in entries if e):
        meta, raw = entry.split(b'\t', 1)
        mode, kind, oid = meta.split()
        name = raw.decode('ascii')
        require(mode in (b'100644', b'100755') and kind == b'blob')
        require(re.fullmatch('[A-Za-z0-9_./-]{1,256}', name)
                and all(p not in ('', '.', '..', '__pycache__') for p in name.split('/'))
                and not name.endswith(('.pyc', '.pyo')))
        data = helper.safe_read(root / name)
        total += len(data)
        require(total <= 16 * helper.LIMIT)
        require(data == helper.git(root, 'cat-file', 'blob', oid.decode('ascii')))
        require(bool((root / name).stat().st_mode & 0o111) == (mode == b'100755'))
        files[name] = data
        digest.update(mode + b'\0' + raw + b'\0' + hashlib.sha256(data).digest())
    require({RUNNER, HELPER, TEST, WORKFLOW, helper.POLICY, 'agent/__init__.py',
             'agent/outbound.py', 'agent/app.py', 'agent/requirements.txt',
             'agent/requirements-dev.txt'} <= files.keys())
    return files, digest.hexdigest(), tree


class EvidencePlugin:
    def __init__(self):
        self.collected, self.phases = [], []
        self.invalid = False

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_collectreport(self, report):
        if report.outcome != 'passed':
            self.invalid = True

    def pytest_runtest_logreport(self, report):
        if (report.nodeid not in EXPECTED or report.when not in ('setup', 'call', 'teardown')
                or report.outcome != 'passed' or hasattr(report, 'wasxfail')):
            self.invalid = True
            return
        self.phases.append([report.nodeid, report.when, 'PASS'])

    def payload(self, code):
        return {'collected': self.collected, 'phases': self.phases,
                'invalid': self.invalid, 'exitCode': int(code)}


def validate(payload):
    require(type(payload) is dict and set(payload) == {'collected', 'phases', 'invalid', 'exitCode'})
    require(payload['invalid'] is False and type(payload['exitCode']) is int and payload['exitCode'] == 0)
    collected, phases = payload['collected'], payload['phases']
    require(type(collected) is list and all(type(x) is str for x in collected))
    require(len(EXPECTED) > 0 and len(set(EXPECTED)) == len(EXPECTED))
    require(len(collected) == len(EXPECTED) and set(collected) == set(EXPECTED))
    require(type(phases) is list and len(phases) == 3 * len(EXPECTED))
    require(all(type(p) is list and len(p) == 3 and all(type(x) is str for x in p) for p in phases))
    require(sorted(phases) == sorted([[node, phase, 'PASS'] for node in EXPECTED
                                     for phase in ('setup', 'call', 'teardown')]))
    return [{'nodeid': node, 'setup': 'PASS', 'call': 'PASS', 'teardown': 'PASS'} for node in EXPECTED]


def worker(snapshot):
    output = os.dup(1)
    with open(os.devnull, 'wb') as private:
        os.dup2(private.fileno(), 1)
        os.dup2(private.fileno(), 2)
    try:
        require(sys.implementation.name == 'cpython' and helper.pinned())
        os.environ['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
        sys.path.insert(0, str(snapshot))
        # Guard before importing pytest or candidate modules and retain it through
        # teardown. Tests stub DNS and TCP; actual provider/network I/O is forbidden.
        blocked = []
        def audit(event, args):
            forbidden = event in {'socket.connect', 'socket.bind', 'socket.getaddrinfo',
                'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.sendto',
                'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork', 'os.exec'}
            if event == 'socket.__new__':
                forbidden = args[1] != socket.AF_UNIX or (args[2] & 15) != socket.SOCK_STREAM
            if forbidden:
                blocked.append(True)
                raise RuntimeError('OFFLINE_IO_REJECTED')
        sys.addaudithook(audit)
        def no_listen(*args, **kwargs):
            blocked.append(True)
            raise RuntimeError('OFFLINE_IO_REJECTED')
        socket.socket.listen = no_listen
        original_threads = set(threading.enumerate())
        import pytest
        plugin = EvidencePlugin()
        code = pytest.main(['-q', '-p', 'no:cacheprovider', '--noconftest',
                            '-c', os.devnull, '--rootdir', str(snapshot), TEST], plugins=[plugin])
        require(not blocked and set(threading.enumerate()) <= original_threads)
        payload = plugin.payload(code)
        validate(payload)
        encoded = json.dumps(payload).encode()
        require(len(encoded) <= 65536)
        os.write(output, encoded)
        return 0
    except BaseException:
        return 1
    finally:
        os.close(output)


def run_snapshot(snapshot):
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen([sys.executable, '-I', '-B', str(snapshot / RUNNER), '--worker'],
                                   cwd=snapshot, env=helper.environment(), stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            code = process.wait(timeout=45)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        require(code == 0 and 0 < output.tell() <= 65536)
        output.seek(0)
        def pairs(items):
            obj = {}
            for key, value in items:
                require(key not in obj)
                obj[key] = value
            return obj
        return validate(json.loads(output.read(65537), object_pairs_hook=pairs))


def report(root=ROOT, env=None):
    reason = 'CONTEXT_REJECTED'
    try:
        binding = helper.context(os.environ if env is None else env, root)
        reason = 'SOURCE_REJECTED'
        files, digest, tree = source(root, binding['checkout'])
        reason = 'DEPENDENCIES_UNAVAILABLE'
        require(sys.implementation.name == 'cpython' and helper.pinned())
        reason = 'EXECUTION_REJECTED'
        with tempfile.TemporaryDirectory(prefix='dns-evidence-') as temporary:
            snapshot = Path(temporary)
            for name, data in files.items():
                target = snapshot / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            outcomes = run_snapshot(snapshot)
            reason = 'SOURCE_CHANGED'
            require(source(root, binding['checkout'])[1:] == (digest, tree))
            require(all(helper.safe_read(snapshot / name) == data for name, data in files.items()))
        return {'schemaVersion': 'FUSE-DNS-LIFECYCLE-EVIDENCE-1', 'outcome': 'PASS',
                'scope': 'OFFLINE_DNS_LIFECYCLE_ONLY', 'binding': dict(binding, tree=tree),
                'sourceSha256Before': digest, 'sourceSha256After': digest,
                'sourceUnchangedDuringRun': True, 'python': '3.12.15',
                'implementation': 'CPython',
                'dependencies': dict(helper.PINS), 'tests': outcomes, 'exitCode': 0}, None
    except BaseException:
        return None, reason


def main():
    try:
        require(sys.flags.isolated and sys.flags.dont_write_bytecode)
        require(sys.argv[1:] in ([], ['--worker']))
    except BaseException:
        print('DNS_LIFECYCLE_EVIDENCE_REJECTED: ARGUMENTS_REJECTED')
        return 1
    if sys.argv[1:] == ['--worker']:
        return worker(ROOT)
    result, reason = report()
    if result is None:
        print('DNS_LIFECYCLE_EVIDENCE_REJECTED: ' + reason)
        return 1
    try:
        directory = ROOT / 'safe-artifacts'
        require(not directory.is_symlink())
        directory.mkdir(exist_ok=True)
        target = directory / ARTIFACT
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(result, stream, sort_keys=True)
            stream.write('\n')
    except BaseException:
        print('DNS_LIFECYCLE_EVIDENCE_REJECTED: ARTIFACT_REJECTED')
        return 1
    print('DNS_LIFECYCLE_EVIDENCE_JSON: ' + json.dumps(result, sort_keys=True))
    print('DNS_LIFECYCLE_VERIFIED: ' + str(len(EXPECTED)) + '/' + str(len(EXPECTED)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
