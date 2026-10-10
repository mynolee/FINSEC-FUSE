"""Standalone Python startup proof, using real bounded Uvicorn child processes.

Missing Python security policy is distinct from Java demo-policy/key admission.
These checks establish neither Java durable invariants nor whole-stack egress
assurance. Only synthetic replay is configured; no provider credentials exist.
"""
from contextlib import contextmanager
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "backend/src/main/resources/config/security_policy.json"
TOKEN = "synthetic-startup-only-service-token-0000000000"
BUSINESS = "/internal/v1/kyc/evaluations"
STARTUP_SECONDS = 20


def request_body():
    text = "synthetic startup fixture"
    body = {
        "requestId": "d4b948b6-811b-4e90-ae7a-4f9d15f80d8e",
        "workflowId": "256c4d72-ab54-4b03-a4eb-1b0f30b56a41",
        "generation": 1, "runId": "9758854f-6e94-4c7a-9c94-fb22d21d7f0b",
        "customerId": "customer-102", "policyVersion": "FUSE-MVP-2",
        "evidenceFacts": [
            {"evidenceId": "00000000-0000-4000-8000-000000001021", "kind": "ID_DOC", "result": "PASS"},
            {"evidenceId": "00000000-0000-4000-8000-000000001022", "kind": "FACE_MATCH", "result": "PASS"},
        ],
        "documents": [{"documentId": "00000000-0000-4000-8000-000000000201",
                       "documentVersion": 1, "contentHash": hashlib.sha256(text.encode()).hexdigest(),
                       "text": text}],
    }
    body["inputSnapshotHash"] = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    return body


def child_environment(policy):
    # Allowlist from literals only. Never inherit real credentials, Python hooks,
    # proxy settings, Uvicorn options, provider configuration, or test-runner env.
    return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONPATH": str(ROOT),
            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            "FUSE_SERVICE_TOKEN": TOKEN, "FUSE_KYC_MODE": "replay",
            "FUSE_SECURITY_POLICY_PATH": str(policy)}


def probe(port, path, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.3)
    try:
        payload = None if body is None else json.dumps(body).encode()
        headers = {} if body is None else {"Content-Type": "application/json", "X-Fuse-Service-Token": TOKEN}
        connection.request("GET" if body is None else "POST", path, body=payload, headers=headers)
        response = connection.getresponse()
        data = response.read(65537)
        if len(data) > 65536:
            raise AssertionError("Startup fixture response exceeded bound")
        return response.status, data
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError,
            TimeoutError, http.client.RemoteDisconnected):
        return None
    finally:
        connection.close()


class PythonStartupProcessTest(unittest.TestCase):
    @contextmanager
    def child(self, policy):
        if os.name != "posix":
            self.skipTest("NOT_RUN: inherited loopback socket fixture requires POSIX")
        # Reserve and inherit the same bound descriptor: no free-port close/rebind
        # race and no touching another service. Only Uvicorn starts listening.
        reserved = None
        try:
            reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reserved.bind(("127.0.0.1", 0))
        except OSError as failure:
            if reserved is not None:
                reserved.close()
            if failure.errno in (errno.EACCES, errno.EPERM):
                self.skipTest("NOT_RUN: local loopback socket/bind denied by execution permissions")
            raise
        with reserved:
            port = reserved.getsockname()[1]
            with tempfile.TemporaryFile() as log:
                process = subprocess.Popen(
                    [sys.executable, "-m", "uvicorn", "agent.app:app", "--fd", str(reserved.fileno()),
                     "--host", "127.0.0.1", "--workers", "1", "--loop", "asyncio", "--http", "h11",
                     "--lifespan", "on", "--no-access-log", "--no-server-header"],
                    cwd=ROOT, env=child_environment(policy), stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT, pass_fds=(reserved.fileno(),))
                # Child owns the descriptor until it exits. The context's second
                # close is harmless, and the parent never listens on this port.
                reserved.close()
                try:
                    yield process, port, log
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    self.assertIsNotNone(process.poll(), "Owned Uvicorn child did not terminate")

    def private_log(self, log):
        log.seek(0)
        value = log.read(65537)
        self.assertLessEqual(len(value), 65536, "Private child log exceeded bound")
        self.assertTrue(TOKEN.encode() not in value, "Synthetic service token escaped into child log")
        return value.decode("utf-8", errors="replace")

    def assert_not_serving(self, port, body):
        for path, payload in [("/health", None), ("/ready", None), (BUSINESS, body)]:
            self.assertIsNone(probe(port, path, payload), "Invalid startup served an HTTP response")

    def test_missing_policy_process_refuses_startup_and_new_valid_process_recovers(self):
        self.assertTrue(POLICY.is_file(), "Original security policy fixture is missing")
        policy_before = POLICY.read_bytes()
        body = request_body()
        with tempfile.TemporaryDirectory(prefix="fuse-python-startup-") as directory:
            missing = Path(directory) / "absent-security-policy.json"
            self.assertFalse(missing.exists(), "Missing-policy fixture unexpectedly exists")
            with self.child(missing) as (process, port, log):
                deadline = time.monotonic() + STARTUP_SECONDS
                while True:
                    self.assert_not_serving(port, body)
                    if process.poll() is not None:
                        break
                    self.assertLess(time.monotonic(), deadline, "Missing-policy child did not exit within bound")
                    time.sleep(0.05)
                self.assertNotEqual(process.returncode, 0, "Missing-policy child exited successfully")
                private = self.private_log(log)
                # Inspect locally, with fixed assertion messages so traceback,
                # environment and private child output never become test output.
                expected = ("FileNotFoundError" in private and str(missing) in private
                            and "security_policy.py" in private and "_PATH.open" in private)
                self.assertTrue(expected, "Child exit was not the expected missing-policy import failure")
                self.assert_not_serving(port, body)
            self.assertFalse(missing.exists(), "Failed startup created its missing policy")

            # Explicit new process, original valid policy, no in-process reload or
            # policy substitution. Exercise the actual Uvicorn lifespan and routes.
            with self.child(POLICY) as (process, port, log):
                deadline = time.monotonic() + STARTUP_SECONDS
                while True:
                    self.assertIsNone(process.poll(), "Valid recovery child exited before readiness")
                    health, ready = probe(port, "/health"), probe(port, "/ready")
                    if health is not None and ready is not None and health[0] == ready[0] == 200:
                        break
                    self.assertLess(time.monotonic(), deadline, "Valid recovery child did not become ready")
                    time.sleep(0.05)
                self.assertTrue(json.loads(health[1]) == {"status": "ok"}, "Recovery health payload was unexpected")
                self.assertTrue(json.loads(ready[1]) == {"ready": True}, "Recovery readiness payload was unexpected")
                response = probe(port, BUSINESS, body)
                self.assertTrue(response is not None and response[0] == 200, "Recovery did not accept synthetic replay")
                result = json.loads(response[1])
                self.assertTrue(result.get("modelMetadata") == {"model": "replay", "promptVersion": "KYC-PROMPT-1"},
                                "Recovery did not use the replay adapter")
                self.assertTrue(result.get("proposal", {}).get("status") == "VERIFIED", "Synthetic replay result was unexpected")
                for field in ("requestId", "workflowId", "generation", "runId", "inputSnapshotHash"):
                    self.assertTrue(result.get(field) == body[field], "Replay context binding changed")
                self.private_log(log)
            self.assert_not_serving(port, body)
        self.assertTrue(POLICY.read_bytes() == policy_before, "Startup test changed the original policy")


if __name__ == "__main__":
    unittest.main()
