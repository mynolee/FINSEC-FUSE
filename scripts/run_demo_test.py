"""Offline demo-client timing regressions. No service, credentials, or wall-clock sleeps."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('run_demo', Path(__file__).with_name('run_demo.py'))
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


class Clock:
    def __init__(self):
        self.now = 0.0

    def sleep(self, seconds):
        self.now += seconds


class DemoPollingTests(unittest.TestCase):
    def test_slow_valid_workflow_does_not_exhaust_own_read_quota(self):
        clock = Clock()
        reads = []

        def api(method, path, token, body=None, key=None, **kwargs):
            if method == 'POST':
                return {'workflowId': 'synthetic-workflow'}
            reads.append(clock.now)
            if sum(t >= clock.now - 60 for t in reads) > 120:
                raise SystemExit('HTTP 429')
            state = 'KYC_PENDING' if clock.now < 40 else 'BLOCKED'
            return {'state': state, 'usedRisk': 10, 'reservedRisk': 0,
                    'reasonCodes': ['EVIDENCE_MISSING']}

        with patch.dict(os.environ, {'FUSE_CUSTOMER_101_TOKEN': 'synthetic'}), \
             patch.object(demo, 'api', api), \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep), \
             contextlib.redirect_stdout(io.StringIO()):
            demo.run(101)
        self.assertGreaterEqual(clock.now, 40)
        self.assertLess(clock.now, 90)
        self.assertLessEqual(len(reads), 120)

    def test_read_rate_limit_waits_without_replaying_mutations(self):
        clock = Clock()
        attempts = []

        def api(method, path, token, body=None, **kwargs):
            attempts.append((method, clock.now))
            if method == 'POST':
                return {'workflowId': 'synthetic-workflow'}
            if clock.now < 60:
                raise demo.RateLimited('60')
            return {'state': 'BLOCKED', 'usedRisk': 10, 'reservedRisk': 0,
                    'reasonCodes': ['EVIDENCE_MISSING']}

        with patch.dict(os.environ, {'FUSE_CUSTOMER_101_TOKEN': 'synthetic'}), \
             patch.object(demo, 'api', api), \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep), \
             contextlib.redirect_stdout(io.StringIO()):
            demo.run(101)
        self.assertEqual(attempts, [('POST', 0), ('GET', 0), ('GET', 60)])

    def test_long_retry_after_reaches_deadline_without_early_retry(self):
        clock = Clock()
        attempts = []

        def limited(*args, **kwargs):
            attempts.append(clock.now)
            raise demo.RateLimited('300')

        with patch.object(demo, 'api', limited), \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep):
            with self.assertRaisesRegex(SystemExit, 'deadline'):
                demo.call('GET', '/workflows/synthetic', 'synthetic', 90)
        self.assertEqual(clock.now, 90)
        self.assertEqual(attempts, [0])

    def test_repeated_rate_limits_cannot_extend_deadline(self):
        clock = Clock()
        with patch.object(demo, 'api', side_effect=demo.RateLimited('60')) as request, \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep):
            with self.assertRaisesRegex(SystemExit, 'deadline'):
                demo.call('GET', '/workflows/synthetic', 'synthetic', 90)
        self.assertEqual(clock.now, 90)
        self.assertEqual(request.call_count, 2)

    def test_retry_after_validation_has_safe_fallback_and_no_zero_spin(self):
        for value in (None, '', '-1', 'NaN', '1.5', '1\r\nInjected: value', '9' * 10000):
            with self.subTest(value=str(value)[:20]):
                self.assertEqual(demo.RateLimited(value).delay, 60)
        self.assertEqual(demo.RateLimited('0').delay, 1)
        self.assertEqual(demo.RateLimited('2').delay, 2)
        self.assertEqual(demo.RateLimited('300').delay, 300)

    def test_mutation_429_is_not_automatically_retried(self):
        with patch.object(demo, 'api', side_effect=demo.RateLimited('60')) as request, \
             patch.object(demo.time, 'monotonic', return_value=0), \
             patch.object(demo.time, 'sleep') as sleep:
            with self.assertRaisesRegex(SystemExit, '429 on mutation'):
                demo.call('POST', '/workflows', 'synthetic', 90, {'synthetic': True})
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()

    def test_request_timeout_is_capped_by_remaining_deadline(self):
        with patch.object(demo, 'api', return_value={}) as request, \
             patch.object(demo.time, 'monotonic', return_value=89):
            demo.call('GET', '/workflows/synthetic', 'synthetic', 90)
        self.assertEqual(request.call_args.kwargs['timeout'], 1)

    def test_response_arriving_after_deadline_is_not_reported_as_success(self):
        clock = Clock()

        def delayed(*args, **kwargs):
            clock.now = 91
            return {'state': 'PAID'}

        with patch.object(demo, 'api', delayed), \
             patch.object(demo.time, 'monotonic', lambda: clock.now):
            with self.assertRaisesRegex(SystemExit, 'deadline'):
                demo.call('GET', '/workflows/synthetic', 'synthetic', 90)

    def test_normal_payment_submits_exact_approval_only_once(self):
        clock = Clock()
        approvals = []

        def api(method, path, token, body=None, **kwargs):
            if method == 'POST' and path == '/workflows':
                return {'workflowId': 'synthetic-workflow'}
            if path.endswith('/approval-preview'):
                return {'reviewSnapshotHash': 'synthetic-exact-preview'}
            if path.endswith('/approvals'):
                approvals.append(body)
                return {'state': 'APPROVED'}
            return {'state': 'WAIT_APPROVAL' if clock.now < 2 else 'PAID',
                    'usedRisk': 85, 'reservedRisk': 0, 'reasonCodes': []}

        with patch.dict(os.environ, {'FUSE_CUSTOMER_102_TOKEN': 'synthetic-customer',
                                     'FUSE_REVIEWER_TOKEN': 'synthetic-reviewer'}), \
             patch.object(demo, 'api', api), \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            demo.run(102)
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]['decision'], 'APPROVE')
        self.assertEqual(approvals[0]['reviewSnapshotHash'], 'synthetic-exact-preview')
        self.assertIn('"state": "PAID"', output.getvalue())

    def test_pending_forever_still_fails_at_deadline(self):
        clock = Clock()

        def pending(method, *args, **kwargs):
            return {'workflowId': 'synthetic-workflow'} if method == 'POST' else {'state': 'KYC_PENDING'}

        with patch.dict(os.environ, {'FUSE_CUSTOMER_101_TOKEN': 'synthetic'}), \
             patch.object(demo, 'api', pending), \
             patch.object(demo.time, 'monotonic', lambda: clock.now), \
             patch.object(demo.time, 'sleep', clock.sleep):
            with self.assertRaisesRegex(SystemExit, 'deadline'):
                demo.run(101)
        self.assertEqual(clock.now, 90)

    def test_unexpected_terminal_states_and_technical_errors_are_failures(self):
        for state in ('ON_HOLD', 'REJECTED', 'PAID'):
            with self.subTest(state=state):
                def api(method, *args, **kwargs):
                    if method == 'POST':
                        return {'workflowId': 'synthetic-workflow'}
                    return {'state': state, 'lastDecision': 'ERROR' if state == 'ON_HOLD' else 'ALLOW',
                            'usedRisk': 10, 'reservedRisk': 0, 'reasonCodes': []}
                with patch.dict(os.environ, {'FUSE_CUSTOMER_101_TOKEN': 'synthetic'}), \
                     patch.object(demo, 'api', api), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(SystemExit, 'Expected BLOCKED'):
                        demo.run(101)

    def test_http_429_extracts_only_delay_and_closes_error_body(self):
        body = io.BytesIO(b'private diagnostic must not be read')
        error = HTTPError('http://localhost/synthetic', 429, 'synthetic', {'Retry-After': '2'}, body)
        with patch.object(demo, 'urlopen', side_effect=error):
            with self.assertRaises(demo.RateLimited) as caught:
                demo.api('GET', '/synthetic', 'synthetic')
        self.assertEqual(caught.exception.delay, 2)
        self.assertTrue(body.closed)

    def test_http_failure_does_not_echo_raw_response(self):
        body = io.BytesIO(b'private diagnostic must not be emitted')
        error = HTTPError('http://localhost/synthetic', 503, 'synthetic', {}, body)
        with patch.object(demo, 'urlopen', side_effect=error):
            with self.assertRaises(SystemExit) as caught:
                demo.api('GET', '/synthetic', 'synthetic')
        self.assertEqual(str(caught.exception), 'HTTP 503; no completion claimed')
        self.assertTrue(body.closed)


if __name__ == '__main__':
    unittest.main()
