#!/usr/bin/env python3
"""Terminal CI-only synthetic privacy check of five Docker stdout/stderr streams.

Run after other acceptance checks and diagnostics, before project-scoped down.
This check stops this run's services. It never builds, pulls, changes networks,
starts services, calls providers, or publishes captured request/log bodies.
File, syslog, remote sinks and rotated-away history are explicitly NOT_RUN.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / 'safe-artifacts/runtime-log-privacy-summary.json'
SERVICES = ('ingress', 'frontend', 'backend', 'agent', 'postgres')
NETWORKS = {'ingress': {'ingress', 'web'}, 'frontend': {'web'},
            'backend': {'web', 'data', 'kyc'}, 'agent': {'kyc'}, 'postgres': {'data'}}
MAX_CAPTURE = 8 * 1024 * 1024  # Per stream; exceeding it fails rather than sampling.
MAX_RESPONSE = 256 * 1024
MAX_REQUEST = 4096
# Frontend's default proxy_connect_timeout and ingress proxy_read_timeout are
# 60s. Only the three stopped-upstream probes get 70s (210s total, no retries).
# Nginx 1.28 maps connection errors to 502 and upstream timeouts to 504.
# https://github.com/nginx/nginx/blob/release-1.28.0/src/http/ngx_http_upstream.c
UPSTREAM_TIMEOUT = 70
UPSTREAM_STATUSES = frozenset({502, 504})
HTTP_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
HTTP_QUOTED = rb'"(?:[\t\x20\x21\x23-\x5b\x5d-\x7e]|\\[\t\x20-\x7e])*"'
CHUNK_LINE = re.compile(rb'([0-9a-fA-F]{1,8})(?:[ \t]*;[ \t]*' + HTTP_TOKEN
                        + rb'(?:[ \t]*=[ \t]*(?:' + HTTP_TOKEN + rb'|' + HTTP_QUOTED
                        + rb'))?)*[ \t]*')
INSPECT = ('{"id":{{json .Id}},"image":{{json .Image}},'
           '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
           '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
           '"state":{{json .State.Status}},"restarts":{{json .RestartCount}},'
           '"started":{{json .State.StartedAt}},"oom":{{json .State.OOMKilled}},'
           '"logging":{{json .HostConfig.LogConfig}},"ports":{{json .HostConfig.PortBindings}},'
           '"networks":{{json .NetworkSettings.Networks}}}')
PROBE_IDS = ('ui_success', 'api_success', 'ui_api_success',
             'api_invalid_bearer', 'ui_api_invalid_bearer',
             'api_crlf_query', 'ui_api_crlf_query',
             'api_crlf_body', 'ui_api_crlf_body',
             'api_malformed_wire', 'ui_malformed_wire', 'agent_crlf_body',
             'ingress_backend_failure', 'frontend_backend_failure', 'ingress_frontend_failure')
REASONS = frozenset({'CI_PROJECT_REQUIRED', 'CONFIGURATION_REJECTED', 'DOCKER_COMMAND_FAILED',
    'SERVICE_IDENTITY_REJECTED', 'SERVICE_STATE_CHANGED', 'LOG_DRIVER_REJECTED',
    'PRIVATE_STORAGE_REJECTED', 'CAPTURE_FAILED', 'CAPTURE_LIMIT_EXCEEDED',
    'CAPTURE_INCOMPLETE', 'REQUEST_FAILED', 'REQUEST_TIMEOUT', 'REQUEST_TRUNCATED',
    'UNEXPECTED_HTTP_STATUS', 'CANARY_DETECTED',
    'SCANNER_CONTROL_FAILED', 'SHUTDOWN_NOT_VERIFIED', 'EXECUTION_FAILED'})


class CheckError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise CheckError(reason)


def command(*args, input=None, timeout=20):
    # Even command failures are private; do not interpolate stderr or exception text.
    process = None
    try:
        require(input is None or len(input) <= MAX_REQUEST, 'DOCKER_COMMAND_FAILED')
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(['docker', *args], cwd=ROOT,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if input is not None:
            process.stdin.write(input)
            process.stdin.close()
        outputs = [bytearray(), bytearray()]
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'DOCKER_COMMAND_FAILED')
                for key, _ in selector.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output = outputs[key.data]
                    require(len(output) + len(chunk) <= MAX_RESPONSE, 'DOCKER_COMMAND_FAILED')
                    output.extend(chunk)
        require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0,
                'DOCKER_COMMAND_FAILED')
        return bytes(outputs[0])
    except Exception:
        raise CheckError('DOCKER_COMMAND_FAILED') from None
    finally:
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass


def inspect(container):
    try:
        item = json.loads(command('inspect', '--format', INSPECT, container))
        require(isinstance(item.get('networks'), dict), 'SERVICE_IDENTITY_REJECTED')
        item['networks'] = sorted(item['networks'])
        return item
    except CheckError:
        raise
    except Exception:
        raise CheckError('SERVICE_IDENTITY_REJECTED') from None


def preflight():
    project = os.environ.get('COMPOSE_PROJECT_NAME', '')
    require(os.environ.get('GITHUB_ACTIONS') == 'true'
            and re.fullmatch(r'fuse-ci-[0-9]+-[0-9]+', project)
            and project == 'fuse-ci-' + os.environ.get('GITHUB_RUN_ID', '') + '-'
            + os.environ.get('GITHUB_RUN_ATTEMPT', ''), 'CI_PROJECT_REQUIRED')
    # Reuse the existing parser: literal fresh, independent mock credentials;
    # replay only, no private documents/prompt or provider configuration.
    try:
        spec = importlib.util.spec_from_file_location('fuse_ci_verify', ROOT / 'scripts/ci-verify.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        credentials = helper.credentials()
    except Exception:
        raise CheckError('CONFIGURATION_REJECTED') from None
    containers = {}
    for service in SERVICES:
        ids = command('ps', '--all', '--filter', 'label=com.docker.compose.project=' + project,
                      '--filter', 'label=com.docker.compose.service=' + service,
                      '--format', '{{.ID}}').decode('ascii').splitlines()
        require(len(ids) == 1 and re.fullmatch(r'[a-f0-9]{12,64}', ids[0]), 'SERVICE_IDENTITY_REJECTED')
        item = inspect(ids[0])
        require(item.get('project') == project and item.get('service') == service
                and re.fullmatch(r'[a-f0-9]{64}', item.get('id', ''))
                and item['id'].startswith(ids[0])
                and re.fullmatch(r'sha256:[a-f0-9]{64}', item.get('image', ''))
                and set(item.get('networks', {})) == {project + '_' + n for n in NETWORKS[service]},
                'SERVICE_IDENTITY_REJECTED')
        require(item.get('state') == 'running' and item.get('restarts') == 0
                and item.get('oom') is False, 'SERVICE_STATE_CHANGED')
        require(item.get('logging') == {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}},
                'LOG_DRIVER_REJECTED')
        expected_ports = {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}],
                          '8081/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5173'}]} if service == 'ingress' else {}
        require((item.get('ports') or {}) == expected_ports, 'SERVICE_IDENTITY_REJECTED')
        containers[service] = item
    require(len({c['id'] for c in containers.values()}) == len(SERVICES), 'SERVICE_IDENTITY_REJECTED')
    command('exec', containers['agent']['id'], 'python', '-c',
            'import os; assert os.environ.get("FUSE_KYC_MODE")=="replay"; '
            'assert not any(os.environ.get(k) for k in '
            '("FUSE_LLM_API_KEY","FUSE_LLM_MODEL","FUSE_KYC_PROMPT_PATH","FUSE_PRIVATE_DOCUMENTS_PATH"))')
    command('exec', containers['backend']['id'], 'bash', '-c',
            'test "$FUSE_KYC_MODE" = replay && test "$FUSE_EXPERIMENT_LIVE_ENABLED" = false')
    return containers, credentials


def unchanged(containers, stopped):
    for service, before in containers.items():
        after = inspect(before['id'])
        expected = dict(before, state='exited' if service in stopped else 'running')
        require(after == expected, 'SERVICE_STATE_CHANGED')


def private_file():
    directory = Path(os.getenv('RUNNER_TEMP') or tempfile.gettempdir()).resolve()
    require(directory.is_dir() and not directory.is_relative_to(ROOT.resolve()), 'PRIVATE_STORAGE_REJECTED')
    return tempfile.TemporaryFile(mode='w+b', dir=directory)


class Capture:
    """Drain the complete stream into an anonymous file, with a hard byte cap."""
    def __init__(self, container):
        self.raw = private_file()
        self.bytes = 0
        self.reason = None
        self.ended_at = None
        self.process = None
        self.thread = None
        try:
            self.process = subprocess.Popen(['docker', 'logs', '--follow', container], cwd=ROOT,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.thread = threading.Thread(target=self._drain, daemon=True)
            self.thread.start()
        except Exception:
            self.close()
            raise CheckError('CAPTURE_FAILED') from None

    def _drain(self):
        try:
            while True:
                data = self.process.stdout.read(65536)
                if not data:
                    break
                if self.bytes + len(data) > MAX_CAPTURE:
                    self.reason = 'CAPTURE_LIMIT_EXCEEDED'
                    self.process.kill()
                    break
                self.raw.write(data)
                self.bytes += len(data)
            self.raw.flush()
        except Exception:
            self.reason = 'CAPTURE_FAILED'
        finally:
            self.ended_at = time.monotonic()

    def alive(self):
        require(self.reason is None, self.reason or 'CAPTURE_FAILED')
        require(self.process.poll() is None, 'CAPTURE_INCOMPLETE')

    def finish(self, stop_started_at):
        try:
            require(self.process.wait(timeout=15) == 0, 'CAPTURE_FAILED')
            self.thread.join(timeout=5)
            require(not self.thread.is_alive(), 'CAPTURE_INCOMPLETE')
            require(self.reason is None, self.reason or 'CAPTURE_FAILED')
            require(self.ended_at is not None and self.ended_at >= stop_started_at, 'CAPTURE_INCOMPLETE')
        except subprocess.TimeoutExpired:
            raise CheckError('CAPTURE_INCOMPLETE') from None

    def close(self):
        complete = True
        if self.process is not None:
            try:
                if self.process.poll() is None:
                    self.process.kill()
                self.process.wait(timeout=5)
            except Exception:
                complete = False
            if self.thread is not None:
                self.thread.join(timeout=5)
                complete &= not self.thread.is_alive()
            if self.process.stdout is not None:
                try:
                    self.process.stdout.close()
                except Exception:
                    complete = False
        try:
            self.raw.close()
        except Exception:
            complete = False
        return complete


def scan(raw, markers, chunk_size=65536):
    """Every byte, not lines or a diagnostic head/tail. Retain cross-chunk overlap."""
    require(bool(markers) and all(markers), 'SCANNER_CONTROL_FAILED')
    overlap = max(map(len, markers)) - 1
    raw.flush()
    raw.seek(0)
    tail = b''
    found = False
    total = 0
    while True:
        chunk = raw.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        window = tail + chunk
        found |= any(marker in window for marker in markers)
        tail = window[-overlap:] if overlap else b''
    return found, total


def response_status(data, *, eof=False):
    """Return the status only when a bounded, unambiguous response is complete."""
    require(len(data) <= MAX_RESPONSE, 'REQUEST_FAILED')

    def incomplete():
        require(not eof, 'REQUEST_TRUNCATED')
        return None

    end = data.find(b'\r\n\r\n')
    if end < 0:
        return incomplete()
    lines = bytes(data[:end]).split(b'\r\n')
    status = re.fullmatch(rb'HTTP/1\.[01] ([2-5][0-9]{2}) [\x20-\x7e]*', lines[0])
    require(status is not None, 'REQUEST_FAILED')
    status = int(status.group(1))
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        require(separator and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                and all(byte == 9 or 32 <= byte <= 126 for byte in value), 'REQUEST_FAILED')
        headers.setdefault(name.lower(), []).append(value.strip(b' \t'))
    lengths = headers.get(b'content-length', [])
    encodings = headers.get(b'transfer-encoding', [])
    require(len(lengths) <= 1 and len(encodings) <= 1 and not (lengths and encodings), 'REQUEST_FAILED')
    body = data[end + 4:]
    if status in (204, 304):
        require(not body and not encodings, 'REQUEST_FAILED')
        return status
    if lengths:
        require(re.fullmatch(rb'[0-9]{1,9}', lengths[0]) is not None, 'REQUEST_FAILED')
        length = int(lengths[0])
        require(length <= MAX_RESPONSE and len(body) <= length, 'REQUEST_FAILED')
        return status if len(body) == length else incomplete()
    if encodings:
        require(encodings[0].lower() == b'chunked', 'REQUEST_FAILED')
        position = 0
        decoded_bytes = 0
        while True:
            line_end = body.find(b'\r\n', position)
            if line_end < 0:
                return incomplete()
            chunk = CHUNK_LINE.fullmatch(body[position:line_end])
            require(chunk is not None, 'REQUEST_FAILED')
            size = int(chunk.group(1), 16)
            decoded_bytes += size
            require(decoded_bytes <= MAX_RESPONSE, 'REQUEST_FAILED')
            position = line_end + 2
            if size == 0:
                while True:
                    trailer_end = body.find(b'\r\n', position)
                    if trailer_end < 0:
                        return incomplete()
                    trailer = bytes(body[position:trailer_end])
                    position = trailer_end + 2
                    if not trailer:
                        require(position == len(body), 'REQUEST_FAILED')
                        return status
                    name, colon, value = trailer.partition(b':')
                    require(colon and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                            and name.lower() not in {b'content-length', b'transfer-encoding'}
                            and all(byte == 9 or 32 <= byte <= 126 for byte in value), 'REQUEST_FAILED')
            if len(body) < position + size + 2:
                return incomplete()
            require(body[position + size:position + size + 2] == b'\r\n', 'REQUEST_FAILED')
            position += size + 2
    # HTTP/1.x also allows close-delimited responses. Only this case needs EOF.
    return status if eof else None


def wire(port, method, path, headers=(), body=b'', malformed=False, *, timeout=5):
    require(port in (8080, 5173) and method in ('GET', 'POST'), 'REQUEST_FAILED')
    require(type(timeout) is int and timeout in (5, UPSTREAM_TIMEOUT), 'REQUEST_FAILED')
    version = 'HTTP/1.X' if malformed else 'HTTP/1.1'
    request = (method + ' ' + path + ' ' + version + '\r\nHost: 127.0.0.1\r\nConnection: close\r\n'
               + ''.join(name + ': ' + value + '\r\n' for name, value in headers)
               + 'Content-Length: ' + str(len(body)) + '\r\n\r\n').encode('ascii') + body
    require(len(request) <= MAX_REQUEST, 'REQUEST_FAILED')
    try:
        # Direct loopback socket: ignores proxies and never follows redirects.
        deadline = time.monotonic() + timeout
        with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
            connection.sendall(request)
            result = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0, 'REQUEST_TIMEOUT')
                connection.settimeout(remaining)
                data = connection.recv(min(16384, MAX_RESPONSE + 1 - len(result)))
                if not data:
                    return response_status(result, eof=True)
                result.extend(data)
                status = response_status(result)
                if status is not None:
                    return status
    except CheckError:
        raise
    except (TimeoutError, socket.timeout):
        raise CheckError('REQUEST_TIMEOUT') from None
    except Exception:
        raise CheckError('REQUEST_FAILED') from None


AGENT_PROBE = '''import json,os,sys,urllib.request,urllib.error
payload=sys.stdin.buffer.read(4097)
assert len(payload)<=4096
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
request=urllib.request.Request('http://127.0.0.1:8001/internal/v1/kyc/evaluations',data=payload,
 headers={'X-Fuse-Service-Token':os.environ['FUSE_SERVICE_TOKEN'],'Content-Type':'application/json'})
try:
 with opener.open(request,timeout=5) as response: status=response.status
except urllib.error.HTTPError as error: status=error.code
print(json.dumps({'status':status}))
'''


def fresh_summary():
    return {'schemaVersion': 1, 'status': 'NOT_RUN',
            'scope': 'FIVE_DOCKER_STDOUT_STDERR_STREAMS_SYNTHETIC_WINDOW',
            'fileSyslogRemoteSinks': 'NOT_RUN', 'rotatedAwayHistory': 'NOT_RUN',
            'providerCalls': False, 'scannerControlPassed': False,
            'upstreamFailuresExercised': False, 'shutdownVerified': False,
            'probes': {name: {'status': 'NOT_RUN', 'httpStatus': None} for name in PROBE_IDS},
            'services': {name: {'captureComplete': False, 'scannedBytes': 0,
                                'canaryDetected': False} for name in SERVICES}, 'reasonCodes': []}


def add_reason(summary, reason):
    code = reason if reason in REASONS else 'EXECUTION_FAILED'
    if code not in summary['reasonCodes']:
        summary['reasonCodes'].append(code)


def execute(summary):
    containers, credentials = preflight()
    captures = {}
    stopped = set()
    stop_started = {}
    # ASCII cores survive JSON/URI escaping. Never emit them or credential values.
    values = {kind: 'FUSEPRIVACY' + secrets.token_hex(16).upper()
              for kind in ('query', 'header', 'bearer', 'body', 'forged')}
    markers = [value.encode('ascii') for value in values.values()]
    markers.extend(value.encode('ascii') for key, value in credentials.items() if key.endswith(('_TOKEN', '_PASSWORD')))
    try:
        with private_file() as control:
            control.write(b'ordinary startup diagnostic without synthetic values')
            require(scan(control, markers)[0] is False, 'SCANNER_CONTROL_FAILED')
            control.seek(0)
            control.truncate()
            control.write(b'x' * 65531 + markers[0] + b'\r\n' + markers[-1])
            detected, _ = scan(control, markers)
            require(detected, 'SCANNER_CONTROL_FAILED')
        summary['scannerControlPassed'] = True
        for service in SERVICES:
            captures[service] = Capture(containers[service]['id'])
        unchanged(containers, stopped)
        for capture in captures.values():
            capture.alive()
        common = [('User-Agent', values['header']), ('Referer', 'http://localhost/' + values['header']),
                  ('X-Privacy-Probe', values['header'])]
        auth = [('Authorization', 'Bearer ' + credentials['FUSE_CUSTOMER_101_TOKEN'])]
        crlf = values['query'] + '\r\n' + values['forged']
        # Known DTO fields force deserialization of the CRLF string. Invalid
        # customer/amount fail bean validation before WorkflowService.start.
        body = json.dumps({'businessReference': values['body'] + '\r\n' + values['forged'],
                           'customerId': '', 'amountKrw': 0,
                           'payoutAccountId': '00000000-0000-4000-8000-000000000002'}).encode('ascii')

        def probe(name, expected, port, method, path, headers=(), payload=b'', malformed=False, *, timeout=5):
            for service, capture in captures.items():
                if service not in stopped:
                    capture.alive()
            summary['probes'][name] = {'status': 'FAIL', 'httpStatus': None}
            status = wire(port, method, path, [*common, *headers], payload, malformed, timeout=timeout)
            allowed = (expected,) if type(expected) is int else expected
            summary['probes'][name] = {'status': 'PASS' if status in allowed else 'FAIL', 'httpStatus': status}
            require(status in allowed, 'UNEXPECTED_HTTP_STATUS')

        probe('ui_success', 200, 5173, 'GET', '/?probe=' + values['query'])
        for port, prefix in ((8080, 'api'), (5173, 'ui_api')):
            probe(prefix + '_success', 200, port, 'GET', '/api/v1/workflows?size=1', auth)
            probe(prefix + '_invalid_bearer', 401, port, 'GET', '/api/v1/workflows',
                  [('Authorization', 'Bearer ' + values['bearer'])])
            probe(prefix + '_crlf_query', 400, port, 'GET', '/api/v1/workflows?state=' + quote(crlf, safe=''), auth)
            probe(prefix + '_crlf_body', 400, port, 'POST', '/api/v1/workflows',
                  [*auth, ('Content-Type', 'application/json'),
                   ('Idempotency-Key', '00000000-0000-4000-8000-000000000001')], body)
        for port, name in ((8080, 'api_malformed_wire'), (5173, 'ui_malformed_wire')):
            probe(name, 400, port, 'GET', '/?probe=' + values['query'], malformed=True)
        observed = json.loads(command('exec', '-i', containers['agent']['id'], 'python', '-c', AGENT_PROBE,
                                      input=body, timeout=10))
        require(set(observed) == {'status'} and type(observed['status']) is int
                and 100 <= observed['status'] <= 599, 'REQUEST_FAILED')
        summary['probes']['agent_crlf_body'] = {'status': 'PASS' if observed['status'] == 422 else 'FAIL',
                                               'httpStatus': observed['status']}
        require(observed['status'] == 422, 'UNEXPECTED_HTTP_STATUS')
        unchanged(containers, stopped)
        stop_started['backend'] = time.monotonic()
        command('stop', '--time', '10', containers['backend']['id'])
        stopped.add('backend')
        unchanged(containers, stopped)
        failure_path = '/api/v1/workflows?state=' + quote(crlf, safe='')
        probe('ingress_backend_failure', UPSTREAM_STATUSES, 8080, 'POST', failure_path,
              [('Content-Type', 'application/json'), ('Authorization', 'Bearer ' + values['bearer'])], body,
              timeout=UPSTREAM_TIMEOUT)
        probe('frontend_backend_failure', UPSTREAM_STATUSES, 5173, 'POST', failure_path,
              [('Content-Type', 'application/json'), ('Authorization', 'Bearer ' + values['bearer'])], body,
              timeout=UPSTREAM_TIMEOUT)
        stop_started['frontend'] = time.monotonic()
        command('stop', '--time', '10', containers['frontend']['id'])
        stopped.add('frontend')
        unchanged(containers, stopped)
        probe('ingress_frontend_failure', UPSTREAM_STATUSES, 5173, 'GET', '/?probe=' + quote(crlf, safe=''),
              timeout=UPSTREAM_TIMEOUT)
        summary['upstreamFailuresExercised'] = True
    finally:
        # Stop only IDs whose ownership was verified before this terminal check.
        try:
            now = time.monotonic()
            for service in SERVICES:
                stop_started.setdefault(service, now)
            command('stop', '--time', '10', *(containers[s]['id'] for s in SERVICES), timeout=35)
            unchanged(containers, set(SERVICES))
            summary['shutdownVerified'] = True
        except Exception:
            add_reason(summary, 'SHUTDOWN_NOT_VERIFIED')
        for service, capture in captures.items():
            try:
                capture.finish(stop_started[service])
                detected, count = scan(capture.raw, markers)
                summary['services'][service] = {'captureComplete': True, 'scannedBytes': count,
                                                 'canaryDetected': detected}
                if detected:
                    add_reason(summary, 'CANARY_DETECTED')
            except CheckError as error:
                add_reason(summary, str(error))
            except Exception:
                add_reason(summary, 'CAPTURE_FAILED')
            finally:
                try:
                    if capture.close() is not True:
                        add_reason(summary, 'CAPTURE_INCOMPLETE')
                except Exception:
                    add_reason(summary, 'CAPTURE_INCOMPLETE')
    require(len(captures) == len(SERVICES)
            and all(item['captureComplete'] for item in summary['services'].values()), 'CAPTURE_INCOMPLETE')
    require(not summary['reasonCodes'], 'EXECUTION_FAILED')
    require(all(item['status'] == 'PASS' for item in summary['probes'].values()), 'EXECUTION_FAILED')
    summary['status'] = 'PASS'


def emit(summary, path=SUMMARY):
    require(not path.parent.is_symlink() and not path.is_symlink(), 'PRIVATE_STORAGE_REJECTED')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Constructed fields only, never subprocess objects or diagnostic strings.
    with path.open('w', encoding='utf-8') as output:
        json.dump(summary, output, indent=2, allow_nan=False)
        output.write('\n')
    path.chmod(0o600)


def main():
    summary = fresh_summary()
    try:
        execute(summary)
    except CheckError as error:
        summary['status'] = 'FAIL'
        add_reason(summary, str(error))
    except Exception:
        summary['status'] = 'FAIL'
        add_reason(summary, 'EXECUTION_FAILED')
    try:
        emit(summary)
    except Exception:
        print('Runtime Docker log privacy: FAIL. Safe summary unavailable; diagnostics withheld.')
        return 1
    print('Runtime Docker log privacy: ' + summary['status'] +
          '. File/syslog/remote sinks and rotated-away history NOT_RUN. Raw captures withheld.')
    return int(summary['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
