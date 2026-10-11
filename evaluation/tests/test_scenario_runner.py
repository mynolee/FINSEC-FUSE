"""Synthetic HTTP/clock regressions only; these do not execute financial cases."""
from contextlib import contextmanager
from email.utils import formatdate
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx

from evaluation import scenario_runner as runner
from evaluation.fixture_loader import load_fixture_set


class Clock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def sleep(self, seconds):
        assert 0 < seconds < float("inf")
        self.sleeps.append(seconds)
        self.now += seconds


class ObservationTest(unittest.TestCase):
    def setUp(self):
        self.manifest = load_fixture_set("security-evaluation-v1")
        self.clock = Clock()
        self.requests = []
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.output = Path(self.directory.name)

    @contextmanager
    def transport(self, handler):
        real_client = httpx.Client

        def observe(request):
            self.requests.append((self.clock.now, request))
            return handler(request)

        def client(**kwargs):
            self.assertFalse(kwargs["follow_redirects"])
            self.assertFalse(kwargs["trust_env"])
            return real_client(transport=httpx.MockTransport(observe), **kwargs)

        with patch.object(runner.httpx, "Client", side_effect=client), \
                patch.object(runner.time, "monotonic", side_effect=lambda: self.clock.now), \
                patch.object(runner.time, "time", side_effect=lambda: 1700000000 + self.clock.now), \
                patch.object(runner.time, "sleep", side_effect=self.clock.sleep):
            yield

    def run_experiment(self, deadline=180):
        return runner.execute_java(self.manifest, "http://127.0.0.1:8080", "synthetic-test-token",
                                   "REPLAY", 1, self.output, deadline_seconds=deadline)

    def accepted(self):
        return httpx.Response(202, json={"experimentId": "synthetic-experiment"})

    def completed(self):
        return httpx.Response(200, json={"status": "COMPLETED", "caseOutputs": [{}] * 120})

    def test_recovers_from_actual_120_reads_per_60_seconds_contract(self):
        # The browser has already used 118 reads from the same actor/window.
        policy = json.loads(Path("backend/src/main/resources/config/security_policy.json").read_text())
        self.assertEqual(policy["authenticatedReadsPerMinute"], 120)
        window_start, read_count, limited = 0.0, 118, []

        def handle(request):
            nonlocal window_start, read_count
            if request.method == "POST":
                body = json.loads(request.content)
                self.assertEqual(body["caseIds"], [case["caseId"] for case in self.manifest["cases"]])
                self.assertEqual(len(body["caseIds"]), 60)
                self.assertEqual((body["modelMode"], body["mode"], body["repeatCount"]), ("REPLAY", "PAIRED", 1))
                return self.accepted()
            if self.clock.now - window_start >= 60:
                window_start, read_count = self.clock.now, 0
            if read_count >= policy["authenticatedReadsPerMinute"]:
                limited.append(self.clock.now)
                return httpx.Response(429, headers={"Retry-After": "60"}, json={"private": "DO_NOT_PRINT"})
            read_count += 1
            return self.completed() if self.clock.now >= 65 else httpx.Response(200, json={"status": "RUNNING"})

        with self.transport(handle):
            result = self.run_experiment()
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(result["caseOutputs"]), 120)
        self.assertEqual(len(limited), 1)
        self.assertEqual(sum(request.method == "POST" for _, request in self.requests), 1)
        self.assertIn(60, self.clock.sleeps)
        self.assertTrue(all(seconds >= 1 for seconds in self.clock.sleeps))
        self.assertEqual(json.loads((self.output / "accepted.json").read_text())["experimentId"], "synthetic-experiment")
        self.assertNotIn("DO_NOT_PRINT", "".join(path.read_text() for path in self.output.iterdir()))

    def test_poll_cadence_stays_below_read_budget_without_prior_traffic(self):
        def handle(request):
            if request.method == "POST":
                return self.accepted()
            return self.completed() if self.clock.now >= 65 else httpx.Response(200, json={"status": "RUNNING"})
        with self.transport(handle):
            self.run_experiment()
        self.assertLessEqual(sum(request.method == "GET" and instant < 60 for instant, request in self.requests), 60)

    def test_valid_retry_after_seconds_and_http_date_are_honored(self):
        for header in ("7", formatdate(1700000007, usegmt=True)):
            with self.subTest(header=header):
                self.clock = Clock()
                calls = 0
                def handle(request):
                    nonlocal calls
                    if request.method == "POST":
                        return self.accepted()
                    calls += 1
                    return httpx.Response(429, headers={"Retry-After": header}) if calls == 1 else self.completed()
                with self.transport(handle):
                    self.run_experiment()
                self.assertEqual(self.clock.sleeps, [7])

    def test_missing_or_invalid_retry_after_uses_bounded_conservative_backoff(self):
        for header in (None, "garbage", "-1", "NaN", "Infinity", "0.01"):
            with self.subTest(header=header):
                self.clock = Clock()
                calls = 0
                def handle(request):
                    nonlocal calls
                    if request.method == "POST":
                        return self.accepted()
                    calls += 1
                    return (httpx.Response(429, headers={} if header is None else {"Retry-After": header})
                            if calls == 1 else self.completed())
                with self.transport(handle):
                    self.run_experiment()
                self.assertEqual(self.clock.sleeps, [60])

    def test_zero_or_past_retry_after_cannot_create_a_hot_loop(self):
        for header in ("0", formatdate(1699999990, usegmt=True)):
            with self.subTest(header=header):
                self.clock = Clock()
                calls = 0
                def handle(request):
                    nonlocal calls
                    if request.method == "POST":
                        return self.accepted()
                    calls += 1
                    return httpx.Response(429, headers={"Retry-After": header}) if calls == 1 else self.completed()
                with self.transport(handle):
                    self.run_experiment()
                self.assertEqual(self.clock.sleeps, [1])

    def test_huge_retry_after_and_repeated_429_never_extend_original_deadline(self):
        for header in ("60", "999999999999", "9" * 10000):
            with self.subTest(kind="bounded-header"):
                self.clock = Clock()
                self.requests = []
                def handle(request):
                    return self.accepted() if request.method == "POST" else httpx.Response(429, headers={"Retry-After": header})
                with self.transport(handle), self.assertRaises(TimeoutError):
                    self.run_experiment(deadline=90)
                self.assertEqual(self.clock.now, 90)
                self.assertTrue(all(instant < 90 for instant, request in self.requests))
                self.assertLessEqual(len(self.requests), 3)
                self.assertEqual(sum(request.method == "POST" for _, request in self.requests), 1)

    def test_running_observation_does_not_send_an_extra_get_at_deadline(self):
        def handle(request):
            return self.accepted() if request.method == "POST" else httpx.Response(200, json={"status": "RUNNING"})
        with self.transport(handle), self.assertRaises(TimeoutError):
            self.run_experiment(deadline=2.5)
        self.assertEqual(self.clock.now, 2.5)
        self.assertTrue(all(instant < 2.5 for instant, request in self.requests))
        self.assertEqual(json.loads((self.output / "raw-java-report.json").read_text())["status"], "RUNNING")

    def test_creation_and_non429_get_failures_are_never_retried(self):
        for method, status in (("POST", 429), ("POST", 503), ("GET", 401), ("GET", 403), ("GET", 500), ("GET", 307)):
            with self.subTest(method=method, status=status):
                self.clock = Clock()
                self.requests = []
                def handle(request):
                    return httpx.Response(status, headers={"Retry-After": "1", "Location": "https://must-not-follow.invalid"}) if request.method == method else self.accepted()
                with self.transport(handle), self.assertRaises(httpx.HTTPStatusError):
                    self.run_experiment()
                self.assertEqual(len(self.requests), 1 if method == "POST" else 2)
                self.assertEqual(self.clock.sleeps, [])
                self.assertTrue((self.output / "request.json").exists())

    def test_uncertain_creation_is_not_retried(self):
        def handle(request):
            raise httpx.ReadTimeout("synthetic uncertain POST", request=request)
        with self.transport(handle), self.assertRaises(httpx.ReadTimeout):
            self.run_experiment()
        self.assertEqual(len(self.requests), 1)
        self.assertTrue((self.output / "request.json").exists())

    def test_uncertain_get_is_not_retried_and_request_timeout_uses_remaining_budget(self):
        def handle(request):
            if request.method == "POST":
                return self.accepted()
            self.assertEqual(request.extensions["timeout"], {"connect": 2, "read": 2.5, "write": 2.5, "pool": 2.5})
            raise httpx.ReadTimeout("synthetic uncertain GET", request=request)
        with self.transport(handle), self.assertRaises(httpx.ReadTimeout):
            self.run_experiment(deadline=2.5)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.clock.sleeps, [])

    def test_terminal_failure_is_returned_without_relabeling(self):
        for status in ("FAILED", "INTERRUPTED"):
            def handle(request):
                return self.accepted() if request.method == "POST" else httpx.Response(200, json={"status": status})
            with self.transport(handle):
                self.assertEqual(self.run_experiment()["status"], status)

    def test_invalid_deadline_does_not_start_an_experiment(self):
        for deadline in (0, -1, float("nan"), float("inf")):
            with self.subTest(deadline=deadline), self.transport(lambda request: self.accepted()), self.assertRaises(ValueError):
                self.run_experiment(deadline=deadline)
        self.assertEqual(self.requests, [])


class EvidenceGateTest(unittest.TestCase):
    """Mock only HTTP/export plumbing; exercise the real, unchanged CI gates."""
    def setUp(self):
        spec = importlib.util.spec_from_file_location("ci_verify_evidence_test", Path("scripts/ci-verify.py"))
        self.checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checks)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def check_report(self, status="COMPLETED", count=120, excluded=0, expected=True):
        from evaluation import export
        report = SimpleNamespace(status=status, caseOutputs=[{}] * count, metrics={"excludedPairCount": excluded})
        bundle = self.root / "synthetic-bundle"
        bundle.mkdir()
        (bundle / "case_results.json").write_text(json.dumps([{"expectedMatch": expected}] * count))
        with patch.object(self.checks, "credentials", return_value={"FUSE_DEVELOPER_TOKEN": "synthetic-test-token"}), \
                patch.object(self.checks, "SAFE", self.root / "safe"), \
                patch.object(self.checks, "validate_bundle", return_value=["case_results.json"]), \
                patch.object(runner, "execute_java", return_value={}) as execute, \
                patch.object(runner, "normalize_java_report", return_value=report), \
                patch.object(export, "export_evidence_bundle", return_value=bundle):
            try:
                self.checks.evidence()
            finally:
                execute.assert_called_once()
                args, kwargs = execute.call_args
                self.assertEqual(len(args[0]["cases"]), 60)
                self.assertEqual(args[3:5], ("REPLAY", 1))
                self.assertEqual(kwargs, {"deadline_seconds": 900})

    def test_complete_120_matching_results_are_required_for_pass(self):
        self.check_report()
        summary = json.loads((self.root / "safe/experiment-summary.json").read_text())
        self.assertEqual((summary["status"], summary["plannedCases"], summary["environmentResults"]), ("PASS", 60, 120))
        self.assertFalse(summary["liveRobustnessMeasured"])

    def test_missing_extra_excluded_unfinished_and_mismatching_results_still_fail(self):
        cases = ({"status": "FAILED"}, {"status": "INTERRUPTED"}, {"count": 119}, {"count": 121},
                 {"excluded": 1}, {"expected": False}, {"expected": None})
        for index, changes in enumerate(cases):
            with self.subTest(changes=changes):
                self.root = Path(self.directory.name) / str(index)
                self.root.mkdir()
                with self.assertRaises(ValueError):
                    self.check_report(**changes)
                self.assertEqual(json.loads((self.root / "safe/experiment-summary.json").read_text()),
                                 {"status": "FAIL", "stage": "VERIFY_RESULTS", "httpStatus": None})

    def test_execution_http_failure_emits_only_safe_stage_and_status(self):
        marker = "SYNTHETIC_PRIVATE_RESPONSE_SENTINEL"
        request = httpx.Request("GET", "http://127.0.0.1/private/" + marker, headers={"Authorization": marker})
        response = httpx.Response(429, request=request, text=marker, headers={"private": marker})
        error = httpx.HTTPStatusError(marker, request=request, response=response)
        with patch.object(self.checks, "credentials", return_value={"FUSE_DEVELOPER_TOKEN": marker}), \
                patch.object(self.checks, "SAFE", self.root), \
                patch.object(runner, "execute_java", side_effect=error), self.assertRaises(httpx.HTTPStatusError):
            self.checks.evidence()
        summary = (self.root / "experiment-summary.json").read_text()
        self.assertEqual(json.loads(summary), {"status": "FAIL", "stage": "EXECUTE_REPLAY", "httpStatus": 429})
        self.assertNotIn(marker, summary)


if __name__ == "__main__":
    unittest.main()
