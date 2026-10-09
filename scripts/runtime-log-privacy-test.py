#!/usr/bin/env python3
"""Service-free tests; Docker, sockets and providers must never run here."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('privacy', Path(__file__).with_name('runtime-log-privacy-check.py'))
privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy)
PRIVATE = 'PRIVATE_DIAGNOSTIC_MUST_NEVER_ESCAPE'


def containers():
    project = 'fuse-ci-123-1'
    return {service: {'id': str(i + 1) * 64, 'image': 'sha256:' + 'a' * 64,
            'project': project, 'service': service, 'state': 'running', 'restarts': 0,
            'started': '2026-10-09T00:00:00Z', 'oom': False,
            'logging': {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}},
            'ports': {'8080/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '8080'}],
                      '8081/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '5173'}]} if service == 'ingress' else {},
            'networks': sorted(project + '_' + n for n in privacy.NETWORKS[service])}
            for i, service in enumerate(privacy.SERVICES)}


class NoExternalCalls(unittest.TestCase):
    def setUp(self):
        # A missing inner mock must abort rather than touch Docker or a socket.
        self.guards = [patch.object(privacy.subprocess, 'run', side_effect=AssertionError('Unmocked process')),
                       patch.object(privacy.subprocess, 'Popen', side_effect=AssertionError('Unmocked process')),
                       patch.object(privacy.socket, 'create_connection', side_effect=AssertionError('Unmocked socket'))]
        for guard in self.guards:
            guard.start()
            self.addCleanup(guard.stop)


class ScannerTests(NoExternalCalls):
    def test_all_positions_and_chunk_boundaries(self):
        marker = b'FUSEPRIVACY123456789ABCDEF'
        for offset in (0, 1, 6, 7, 8, 31, 65530, 100000):
            with self.subTest(offset=offset):
                body = b'x' * offset + marker + b'\r\nlast line'
                self.assertEqual(privacy.scan(io.BytesIO(body), [marker], 7), (True, len(body)))

    def test_more_than_200_lines_and_eof_are_not_omitted(self):
        body = b'normal\n' * 500 + b'FORGEDLINE'
        self.assertEqual(privacy.scan(io.BytesIO(body), [b'FORGEDLINE']), (True, len(body)))

    def test_escaped_crlf_still_detects_independent_ascii_cores(self):
        for body in (b'PRE\r\nFORGEDLINE', b'PRE\\r\\nFORGEDLINE', b'PRE%0D%0AFORGEDLINE',
                     b'PRE\\x0d\\x0aFORGEDLINE'):
            self.assertTrue(privacy.scan(io.BytesIO(body), [b'FORGEDLINE'], 3)[0])

    def test_each_marker_detected_independently(self):
        markers = [b'QUERY123', b'BODY456', b'HEADER789', b'FORGED012', b'TOKEN345']
        for marker in markers:
            self.assertTrue(privacy.scan(io.BytesIO(marker), markers, 2)[0])

    def test_no_match_and_empty_sink(self):
        self.assertEqual(privacy.scan(io.BytesIO(b'normal startup'), [b'CANARY']), (False, 14))
        self.assertEqual(privacy.scan(io.BytesIO(), [b'CANARY']), (False, 0))

    def test_empty_markers_rejected(self):
        for markers in ([], [b'']):
            with self.assertRaises(privacy.CheckError):
                privacy.scan(io.BytesIO(), markers)


class CaptureTests(NoExternalCalls):
    def capture(self, body):
        process = Mock()
        process.stdout = io.BytesIO(body)
        process.poll.return_value = 0
        process.wait.return_value = 0
        with patch.object(privacy.subprocess, 'Popen', return_value=process), \
                patch.object(privacy, 'private_file', side_effect=tempfile.TemporaryFile):
            result = privacy.Capture('a' * 64)
        result.thread.join(2)
        self.addCleanup(result.close)
        return result, process

    def test_complete_capture_both_streams_no_sampling(self):
        body = b'normal\n' * 400 + b'CANARY'
        capture, process = self.capture(body)
        capture.finish(0)
        self.assertEqual(privacy.scan(capture.raw, [b'CANARY']), (True, len(body)))
        self.assertEqual(capture.bytes, len(body))

    def test_cap_is_failure_not_truncation_pass(self):
        with patch.object(privacy, 'MAX_CAPTURE', 8):
            capture, process = self.capture(b'123456789')
        with self.assertRaisesRegex(privacy.CheckError, 'CAPTURE_LIMIT_EXCEEDED'):
            capture.finish(0)
        self.assertEqual(capture.bytes, 0)
        process.kill.assert_called()

    def test_early_eof_nonzero_and_timeout_fail(self):
        capture, process = self.capture(b'')
        with self.assertRaisesRegex(privacy.CheckError, 'CAPTURE_INCOMPLETE'):
            capture.alive()
        process.wait.return_value = 1
        with self.assertRaisesRegex(privacy.CheckError, 'CAPTURE_FAILED'):
            capture.finish(0)
        process.wait.side_effect = subprocess.TimeoutExpired('private', 15)
        with self.assertRaisesRegex(privacy.CheckError, 'CAPTURE_INCOMPLETE'):
            capture.finish(0)

    def test_eof_before_service_stop_is_incomplete_even_with_zero_exit(self):
        capture, _ = self.capture(b'normal')
        with self.assertRaisesRegex(privacy.CheckError, 'CAPTURE_INCOMPLETE'):
            capture.finish(capture.ended_at + 1)

    def test_anonymous_private_file_closed_and_not_in_repository(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'RUNNER_TEMP': directory}):
            raw = privacy.private_file()
            self.assertIsInstance(raw.name, int)
            self.assertEqual(os.listdir(directory), [])
            raw.close()
            self.assertTrue(raw.closed)
        with patch.dict(os.environ, {'RUNNER_TEMP': str(privacy.ROOT)}):
            with self.assertRaisesRegex(privacy.CheckError, 'PRIVATE_STORAGE_REJECTED'):
                privacy.private_file()


class PreflightTests(NoExternalCalls):
    def invoke(self, transform=lambda items: None, ids=None):
        items = containers()
        transform(items)
        helper = Mock()
        helper.credentials.return_value = {'FUSE_CUSTOMER_101_TOKEN': 'c' * 64}
        spec = Mock()
        spec.loader.exec_module.return_value = None
        def run(*args, **kwargs):
            if args[0] == 'ps':
                service = args[args.index('--format') - 1].split('=')[-1]
                return ids if ids is not None else (items[service]['id'][:12] + '\n').encode()
            return b''
        def inspect(identifier):
            return copy.deepcopy(next(row for row in items.values() if row['id'].startswith(identifier)))
        environment = {'GITHUB_ACTIONS': 'true', 'COMPOSE_PROJECT_NAME': 'fuse-ci-123-1',
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        with patch.dict(os.environ, environment, clear=True), patch.object(privacy, 'command', side_effect=run), \
                patch.object(privacy, 'inspect', side_effect=inspect), \
                patch.object(privacy.importlib.util, 'spec_from_file_location', return_value=spec), \
                patch.object(privacy.importlib.util, 'module_from_spec', return_value=helper):
            return privacy.preflight()

    def test_complete_preflight(self):
        observed, credentials = self.invoke()
        self.assertEqual(set(observed), set(privacy.SERVICES))
        self.assertIn('FUSE_CUSTOMER_101_TOKEN', credentials)

    def test_missing_and_duplicate_service_fail(self):
        for ids in (b'', b'111111111111\n111111111111\n'):
            with self.assertRaisesRegex(privacy.CheckError, 'SERVICE_IDENTITY_REJECTED'):
                self.invoke(ids=ids)

    def test_driver_network_port_identity_and_restart_mutations_fail(self):
        mutations = [('logging', {}), ('networks', []), ('ports', {}),
                     ('project', 'other'), ('state', 'exited'), ('restarts', 1), ('oom', True)]
        for field, value in mutations:
            with self.subTest(field=field), self.assertRaises(privacy.CheckError):
                self.invoke(lambda rows: rows['ingress'].__setitem__(field, value))

    def test_unknown_ci_project_rejected_before_access(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(privacy.CheckError, 'CI_PROJECT_REQUIRED'):
            privacy.preflight()

    def test_stopped_container_network_addresses_are_not_compared(self):
        original = containers()['backend']
        raw = dict(original, networks={name: {'IPAddress': ''} for name in original['networks']})
        with patch.object(privacy, 'command', return_value=json.dumps(raw).encode()):
            self.assertEqual(privacy.inspect(original['id']), original)

    def test_unchanged_requires_all_identities_and_expected_states(self):
        items = containers()
        def observed(identifier):
            result = copy.deepcopy(next(row for row in items.values() if row['id'] == identifier))
            if result['service'] == 'backend':
                result['state'] = 'exited'
            return result
        with patch.object(privacy, 'inspect', side_effect=observed):
            privacy.unchanged(items, {'backend'})
            with self.assertRaisesRegex(privacy.CheckError, 'SERVICE_STATE_CHANGED'):
                privacy.unchanged(items, set())


class WireTests(NoExternalCalls):
    def socket(self, response):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=False)
        connection.recv.side_effect = [response, b'']
        return connection

    def test_loopback_only_no_redirect_following(self):
        connection = self.socket(b'HTTP/1.1 302 Found\r\nLocation: https://example.invalid/\r\n\r\n')
        with patch.object(privacy.socket, 'create_connection', return_value=connection) as connect:
            self.assertEqual(privacy.wire(5173, 'GET', '/'), 302)
        connect.assert_called_once_with(('127.0.0.1', 5173), timeout=5)

    def test_malformed_wire_is_invalid_version_not_ignorable_header(self):
        connection = self.socket(b'HTTP/1.1 400 Bad Request\r\n\r\n')
        with patch.object(privacy.socket, 'create_connection', return_value=connection):
            self.assertEqual(privacy.wire(8080, 'GET', '/?x=CANARY', malformed=True), 400)
        self.assertIn(b'GET /?x=CANARY HTTP/1.X\r\n', connection.sendall.call_args.args[0])

    def test_limits_and_bad_response_fail(self):
        for body in (b'PRIVATE', b'HTTP/1.1 999 INVALID\r\n', b'x' * 100):
            connection = self.socket(body)
            with patch.object(privacy, 'MAX_RESPONSE', 50), \
                    patch.object(privacy.socket, 'create_connection', return_value=connection), \
                    self.assertRaises(privacy.CheckError):
                privacy.wire(8080, 'GET', '/')
        with self.assertRaises(privacy.CheckError):
            privacy.wire(9999, 'GET', '/')
        with self.assertRaises(privacy.CheckError):
            privacy.wire(8080, 'GET', '/' + 'x' * 5000)

    def test_complete_content_length_does_not_wait_for_delayed_close_or_reset(self):
        response = b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nbad'
        for after in (TimeoutError(PRIVATE), ConnectionResetError(PRIVATE)):
            connection = self.socket(response)
            connection.recv.side_effect = [response, after]
            with patch.object(privacy.socket, 'create_connection', return_value=connection):
                self.assertEqual(privacy.wire(8080, 'POST', '/', body=b'{}', timeout=70), 502)
            self.assertEqual(connection.recv.call_count, 1)

    def test_content_length_response_split_at_every_boundary(self):
        response = b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 3\r\n\r\nbad'
        for offset in range(1, len(response)):
            connection = self.socket(response)
            connection.recv.side_effect = [response[:offset], response[offset:], TimeoutError(PRIVATE)]
            with patch.object(privacy.socket, 'create_connection', return_value=connection):
                self.assertEqual(privacy.wire(8080, 'GET', '/'), 502)
            self.assertEqual(connection.recv.call_count, 2)

    def test_complete_chunked_response_with_trailers_does_not_wait_for_eof(self):
        response = (b'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n'
                    b'2;x=y\r\nba\r\n1\r\nd\r\n0\r\nX-Safe: yes\r\n\r\n')
        for offset in range(1, len(response)):
            connection = self.socket(response)
            connection.recv.side_effect = [response[:offset], response[offset:], TimeoutError(PRIVATE)]
            with patch.object(privacy.socket, 'create_connection', return_value=connection):
                self.assertEqual(privacy.wire(8080, 'GET', '/'), 502)
            self.assertEqual(connection.recv.call_count, 2)

    def test_truncated_headers_body_and_chunked_frames_fail_closed(self):
        responses = [b'HTTP/1.1 502 Bad Gateway\r\n',
                     b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\nbad',
                     b'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nba',
                     b'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nbad\r\n',
                     b'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Safe: yes\r\n']
        for response in responses:
            connection = self.socket(response)
            with patch.object(privacy.socket, 'create_connection', return_value=connection), \
                    self.assertRaisesRegex(privacy.CheckError, '^REQUEST_TRUNCATED$'):
                privacy.wire(8080, 'GET', '/')

    def test_invalid_ambiguous_and_oversized_frames_fail_closed(self):
        responses = [b'Content-Length: 1\r\nContent-Length: 1\r\n\r\nx',
                     b'Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\nx',
                     b'Content-Length: -1\r\n\r\n', b'Content-Length: 0\r\n\r\nx',
                     b'Content-Length: 999999999\r\n\r\n', b'Transfer-Encoding: gzip\r\n\r\n',
                     b'Invalid Header: x\r\n\r\n',
                     b'Transfer-Encoding: chunked\r\n\r\nZ\r\n',
                     b'Transfer-Encoding: chunked\r\n\r\nffffffff\r\n',
                     b'Transfer-Encoding: chunked\r\n\r\n1\r\nx!!',
                     b'Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nextra',
                     b'Transfer-Encoding: chunked\r\n\r\n0\r\nContent-Length: 0\r\n\r\n']
        for response in responses:
            with self.assertRaisesRegex(privacy.CheckError, '^REQUEST_FAILED$'):
                privacy.response_status(b'HTTP/1.1 502 Bad Gateway\r\n' + response)
        with patch.object(privacy, 'MAX_RESPONSE', 50), self.assertRaises(privacy.CheckError):
            privacy.response_status(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 30\r\n\r\n' + b'x' * 30)

    def test_chunk_extensions_require_tokens_or_complete_quoted_strings(self):
        prefix = b'HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\n\r\n'
        for extension in (b';', b';@@@', b';x="unterminated', b';x=', b';=value',
                          b';x=a b', b';x="a"junk', b';x="bad\x01"', b';x="bad\\"'):
            with self.subTest(extension=extension), self.assertRaisesRegex(privacy.CheckError, '^REQUEST_FAILED$'):
                privacy.response_status(prefix + b'1' + extension + b'\r\nx\r\n0\r\n\r\n')
        for extension in (b';x', b';x=y', b';x=""', b';x="a b"', b';x="a\\"b"',
                          b';x=y;another="two"', b' ; x = "a b" ; y=z'):
            self.assertEqual(privacy.response_status(prefix + b'1' + extension + b'\r\nx\r\n0\r\n\r\n'), 502)

    def test_close_delimited_response_still_requires_actual_eof(self):
        response = b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nbad'
        self.assertIsNone(privacy.response_status(response))
        self.assertEqual(privacy.response_status(response, eof=True), 502)

    def test_fake_clock_connect_timeout_boundary_and_finite_failure_budget(self):
        response = b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'
        for budget, ready_at, expected in ((5, 5.2, 'REQUEST_TIMEOUT'), (70, 5.2, 502),
                                           (70, 60.2, 502), (70, 69.9, 502),
                                           (70, 70.2, 'REQUEST_TIMEOUT')):
            clock = [0.0]
            connection = self.socket(response)
            def receive(size):
                remaining = connection.settimeout.call_args.args[0]
                if ready_at - clock[0] > remaining:
                    clock[0] += remaining
                    raise TimeoutError(PRIVATE)
                clock[0] = ready_at
                return response
            connection.recv.side_effect = receive
            with patch.object(privacy.socket, 'create_connection', return_value=connection), \
                    patch.object(privacy.time, 'monotonic', side_effect=lambda: clock[0]):
                if isinstance(expected, int):
                    self.assertEqual(privacy.wire(8080, 'GET', '/', timeout=budget), expected)
                else:
                    with self.assertRaisesRegex(privacy.CheckError, '^' + expected + '$'):
                        privacy.wire(8080, 'GET', '/', timeout=budget)
        with self.assertRaises(privacy.CheckError):
            privacy.wire(8080, 'GET', '/', timeout=60)


class OrchestrationTests(NoExternalCalls):
    def invoke(self, *, fail_probe=None, bad_status=None, bad_at=0, leak_service=None,
               capture_error=None, missing_capture=None, stop_error=False, exception=None):
        items = containers()
        captures = []
        calls = []
        token = 'c' * 64
        class FakeCapture:
            def __init__(self, identifier):
                self.service = next(name for name, row in items.items() if row['id'] == identifier)
                if self.service == missing_capture:
                    raise privacy.CheckError('CAPTURE_FAILED')
                self.raw = io.BytesIO(token.encode() if self.service == leak_service else b'normal\n')
                self.closed = False
                captures.append(self)
            def alive(self):
                if capture_error == 'early':
                    raise privacy.CheckError('CAPTURE_INCOMPLETE')
            def finish(self, stop_started_at):
                if capture_error == self.service:
                    raise privacy.CheckError('CAPTURE_INCOMPLETE')
            def close(self):
                self.closed = True
                self.raw.close()
                return True
        statuses = [200, 200, 401, 400, 400, 200, 401, 400, 400, 400, 400, 502, 502, 502]
        def wire(*args, **kwargs):
            index = len(calls)
            calls.append(args)
            self.assertEqual(kwargs['timeout'], privacy.UPSTREAM_TIMEOUT if index >= 11 else 5)
            if exception:
                raise RuntimeError(exception)
            if index == fail_probe:
                raise privacy.CheckError('REQUEST_FAILED')
            return bad_status if index == bad_at and bad_status else statuses[index]
        def command(*args, **kwargs):
            if args[0] == 'stop' and stop_error:
                raise privacy.CheckError('DOCKER_COMMAND_FAILED')
            return b'{"status":422}' if args[0] == 'exec' else b''
        summary = privacy.fresh_summary()
        error = None
        with patch.object(privacy, 'preflight', return_value=(items, {'FUSE_CUSTOMER_101_TOKEN': token})), \
                patch.object(privacy, 'Capture', FakeCapture), patch.object(privacy, 'unchanged'), \
                patch.object(privacy, 'private_file', side_effect=tempfile.TemporaryFile), \
                patch.object(privacy, 'wire', side_effect=wire), patch.object(privacy, 'command', side_effect=command) as commands:
            try:
                privacy.execute(summary)
            except Exception as failure:
                error = failure
        self.assertTrue(all(c.closed for c in captures))
        self.assertNotIn(token, json.dumps(summary))
        self.assertNotIn('FUSEPRIVACY', json.dumps(summary))
        return summary, error, calls, commands.call_args_list

    def test_all_probes_complete_and_terminal_stops_are_exact_ids(self):
        summary, error, calls, commands = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(summary['status'], 'PASS')
        self.assertTrue(summary['upstreamFailuresExercised'])
        self.assertTrue(summary['shutdownVerified'])
        self.assertEqual(len(calls), 14)
        self.assertEqual(len(summary['probes']), 15)
        stops = [call.args for call in commands if call.args[0] == 'stop']
        items = containers()
        self.assertEqual(stops, [('stop', '--time', '10', items['backend']['id']),
                                ('stop', '--time', '10', items['frontend']['id']),
                                ('stop', '--time', '10', *(items[s]['id'] for s in privacy.SERVICES))])
        self.assertEqual(summary['fileSyslogRemoteSinks'], 'NOT_RUN')
        self.assertEqual(summary['rotatedAwayHistory'], 'NOT_RUN')

    def test_queries_headers_and_body_use_distinct_canaries_and_crlf(self):
        _, _, calls, _ = self.invoke()
        self.assertIn('%0D%0A', calls[3][2])
        body = json.loads(calls[4][4])
        self.assertIn('\r\n', body['businessReference'])
        self.assertIn(('Content-Type', 'application/json'), calls[4][3])
        self.assertEqual(body['amountKrw'], 0)
        self.assertEqual(body['customerId'], '')

    def test_each_service_canary_detection_fails(self):
        for service in privacy.SERVICES:
            with self.subTest(service=service):
                summary, error, _, _ = self.invoke(leak_service=service)
                self.assertIsNotNone(error)
                self.assertIn('CANARY_DETECTED', summary['reasonCodes'])
                self.assertTrue(summary['services'][service]['canaryDetected'])
                self.assertNotEqual(summary['status'], 'PASS')

    def test_capture_failure_missing_capture_and_early_exit_fail(self):
        for options in ({'capture_error': 'backend'}, {'capture_error': 'early'}, {'missing_capture': 'agent'}):
            summary, error, _, _ = self.invoke(**options)
            self.assertIsNotNone(error)
            self.assertNotEqual(summary['status'], 'PASS')
            self.assertTrue(summary['shutdownVerified'])

    def test_each_probe_failure_still_stops_and_scans(self):
        for index in range(14):
            with self.subTest(index=index):
                summary, error, _, _ = self.invoke(fail_probe=index)
                self.assertIsNotNone(error)
                self.assertTrue(summary['shutdownVerified'])
                self.assertTrue(all(row['captureComplete'] for row in summary['services'].values()))
                self.assertNotEqual(summary['status'], 'PASS')

    def test_unexpected_status_shutdown_failure_and_exceptions_fail(self):
        for options in ({'bad_status': 429}, {'stop_error': True}, {'exception': PRIVATE}):
            summary, error, _, _ = self.invoke(**options)
            self.assertIsNotNone(error)
            self.assertNotEqual(summary['status'], 'PASS')
            self.assertNotIn(PRIVATE, json.dumps(summary))

    def test_all_upstream_probes_require_only_502_or_504_without_retry(self):
        names = ('ingress_backend_failure', 'frontend_backend_failure', 'ingress_frontend_failure')
        for index, name in enumerate(names, 11):
            for wrong in (200, 400, 500, 503, 505):
                summary, error, calls, _ = self.invoke(bad_status=wrong, bad_at=index)
                self.assertIsNotNone(error)
                self.assertEqual(len(calls), index + 1)
                self.assertEqual(summary['probes'][name], {'status': 'FAIL', 'httpStatus': wrong})
                self.assertFalse(summary['upstreamFailuresExercised'])

    def test_each_verified_stopped_upstream_accepts_and_preserves_502_or_504(self):
        names = ('ingress_backend_failure', 'frontend_backend_failure', 'ingress_frontend_failure')
        self.assertEqual(privacy.UPSTREAM_STATUSES, {502, 504})
        self.assertEqual(privacy.UPSTREAM_TIMEOUT, 70)
        self.assertEqual(3 * privacy.UPSTREAM_TIMEOUT, 210)
        for index, name in enumerate(names, 11):
            for status in (502, 504):
                summary, error, calls, _ = self.invoke(bad_status=status, bad_at=index)
                self.assertIsNone(error)
                self.assertEqual(summary['status'], 'PASS')
                self.assertEqual(len(calls), 14)
                self.assertEqual(summary['probes'][name], {'status': 'PASS', 'httpStatus': status})
        for index in range(11):
            summary, error, _, _ = self.invoke(bad_status=504, bad_at=index)
            self.assertIsNotNone(error)
            self.assertNotEqual(summary['status'], 'PASS')

    def test_attempted_transport_failure_is_fail_and_later_probes_not_run(self):
        summary, error, calls, _ = self.invoke(fail_probe=11)
        self.assertIsNotNone(error)
        self.assertEqual(len(calls), 12)
        self.assertEqual(summary['probes']['ingress_backend_failure'], {'status': 'FAIL', 'httpStatus': None})
        self.assertEqual(summary['probes']['frontend_backend_failure']['status'], 'NOT_RUN')
        self.assertEqual(summary['probes']['ingress_frontend_failure']['status'], 'NOT_RUN')


class ReportingTests(NoExternalCalls):
    def test_scanner_control_rejects_constant_positive_or_negative(self):
        for detected in (False, True):
            summary = privacy.fresh_summary()
            with patch.object(privacy, 'preflight', return_value=(containers(), {'FUSE_CUSTOMER_101_TOKEN': 'c' * 64})), \
                    patch.object(privacy, 'private_file', side_effect=tempfile.TemporaryFile), \
                    patch.object(privacy, 'command', return_value=b''), patch.object(privacy, 'unchanged'), \
                    patch.object(privacy, 'scan', return_value=(detected, 1)), \
                    self.assertRaisesRegex(privacy.CheckError, 'SCANNER_CONTROL_FAILED'):
                privacy.execute(summary)
            self.assertFalse(summary['scannerControlPassed'])
            self.assertNotEqual(summary['status'], 'PASS')

    def test_unknown_reason_text_is_never_reflected(self):
        summary = privacy.fresh_summary()
        privacy.add_reason(summary, PRIVATE)
        self.assertEqual(summary['reasonCodes'], ['EXECUTION_FAILED'])
        self.assertNotIn(PRIVATE, json.dumps(summary))

    def test_main_exception_output_and_artifact_are_private(self):
        for failure in (privacy.CheckError(PRIVATE), RuntimeError(PRIVATE)):
            stdout = io.StringIO()
            with patch.object(privacy, 'execute', side_effect=failure), patch.object(privacy, 'emit') as emit, \
                    contextlib.redirect_stdout(stdout):
                self.assertEqual(privacy.main(), 1)
            serialized = json.dumps(emit.call_args.args[0])
            self.assertNotIn(PRIVATE, serialized + stdout.getvalue())
            self.assertEqual(emit.call_args.args[0]['status'], 'FAIL')

    def test_exact_safe_schema_and_permissions(self):
        summary = privacy.fresh_summary()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'safe' / 'summary.json'
            privacy.emit(summary, path)
            self.assertEqual(json.loads(path.read_text()), summary)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(set(summary['services']), set(privacy.SERVICES))
        self.assertEqual(set(summary['probes']), set(privacy.PROBE_IDS))
        self.assertTrue(all(set(row) == {'captureComplete', 'scannedBytes', 'canaryDetected'}
                            for row in summary['services'].values()))

    def test_emit_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'link').symlink_to(root / 'target')
            with self.assertRaises(privacy.CheckError):
                privacy.emit(privacy.fresh_summary(), root / 'link')

    def test_raw_docker_error_is_withheld(self):
        process = self.pipe_process(PRIVATE.encode(), PRIVATE.encode(), 1)
        with patch.object(privacy.subprocess, 'Popen', return_value=process), \
                self.assertRaisesRegex(privacy.CheckError, '^DOCKER_COMMAND_FAILED$'):
            privacy.command('inspect', 'a' * 64)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def pipe_process(self, stdout, stderr, code=0):
        def pipe(body):
            reader, writer = os.pipe()
            os.write(writer, body)
            os.close(writer)
            result = os.fdopen(reader, 'rb')
            self.addCleanup(result.close)
            return result
        process = Mock(stdin=None, stdout=pipe(stdout), stderr=pipe(stderr))
        process.poll.return_value = code
        process.wait.return_value = code
        return process

    def test_command_success_and_hard_stream_caps(self):
        process = self.pipe_process(b'{"status":422}', b'')
        with patch.object(privacy.subprocess, 'Popen', return_value=process):
            self.assertEqual(privacy.command('exec'), b'{"status":422}')
        for stdout, stderr in ((b'x' * 51, b''), (b'', b'x' * 51)):
            process = self.pipe_process(stdout, stderr)
            with patch.object(privacy.subprocess, 'Popen', return_value=process), \
                    patch.object(privacy, 'MAX_RESPONSE', 50), \
                    self.assertRaisesRegex(privacy.CheckError, '^DOCKER_COMMAND_FAILED$'):
                privacy.command('inspect')
            self.assertTrue(process.stdout.closed and process.stderr.closed)


if __name__ == '__main__':
    unittest.main()
