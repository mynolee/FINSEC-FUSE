"""Isolated real-HTTP smoke: Python KYC + Spring + ephemeral PostgreSQL 16.15.

Run scripts/test-fullstack.sh after installing agent/requirements.txt. JAVA_HOME
or PATH selects Java; PYTHON selects Python in the shell entrypoint. GRADLE_CMD
or --gradle can select an alternative Gradle executable. All services and the
demo client run inside this one invocation, including in isolated CI sandboxes.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
ROLES = tuple(f"customer-{n}" for n in range(101, 105)) + (
    "reviewer", "security", "developer", "service",
)
HTTP = build_opener(ProxyHandler({}))  # Never proxy the loopback readiness probes.


class SmokeFailure(RuntimeError):
    pass


def require_tools() -> str:
    if os.name != "posix":
        raise SmokeFailure("This runner requires a POSIX host (Linux or macOS).")
    if os.geteuid() == 0:
        raise SmokeFailure("Run as a non-root user; PostgreSQL refuses initdb as root.")
    missing = [name for name in ("uvicorn", "fastapi", "pydantic", "httpx")
               if importlib.util.find_spec(name) is None]
    if missing:
        raise SmokeFailure("Missing Python dependencies; run this Python's pip install "
                           "-r agent/requirements.txt first.")
    java_home = os.environ.get("JAVA_HOME")
    java = str(Path(java_home) / "bin" / "java") if java_home else shutil.which("java")
    if not java:
        raise SmokeFailure("Java 21+ is required; set JAVA_HOME or put java on PATH.")
    version = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=15)
    match = re.search(r'version "(\d+)', version.stderr + version.stdout)
    if version.returncode or not match or int(match.group(1)) < 21:
        raise SmokeFailure("Java 21+ is required; check JAVA_HOME and PATH.")
    return java


def isolated_env(tokens: dict[str, str]) -> dict[str, str]:
    # Never let an existing .env/live-model/database configuration enter this run.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("FUSE_", "SPRING_"))
           and key not in ("PORT", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}
    env.update(FUSE_KYC_MODE="replay", FUSE_SERVICE_TOKEN=tokens["service"],
               FUSE_REVIEWER_TOKEN=tokens["reviewer"],
               PYTHONUNBUFFERED="1", NO_PROXY="127.0.0.1,localhost,::1",
               no_proxy="127.0.0.1,localhost,::1")
    for customer in range(101, 105):
        env[f"FUSE_CUSTOMER_{customer}_TOKEN"] = tokens[f"customer-{customer}"]
    env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(ROOT), env.get("PYTHONPATH"))))
    return env


def start(command, log_path, env, *, pass_fds=()):
    with log_path.open("w", encoding="utf-8") as log:
        return subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True, pass_fds=pass_fds)


def stop(process):
    # Let Java run PostgresSupport's shutdown hook before forcing its process group.
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def check_alive(services):
    for name, process in services:
        if process.poll() is not None:
            raise SmokeFailure(f"{name} exited unexpectedly with status {process.returncode}.")


def ready(url, expected):
    try:
        with HTTP.open(url, timeout=1) as response:
            return response.status == 200 and expected(json.load(response))
    except (URLError, TimeoutError, ConnectionError, ValueError):
        return False


def await_ready(services, agent_url, port_file, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_alive(services)
        try:
            port = int(port_file.read_text().strip())
            backend_url = f"http://127.0.0.1:{port}"
            if (0 < port < 65536
                    and ready(agent_url + "/ready", lambda body:
                              body.get("ready") is True)
                    and ready(backend_url + "/actuator/health/readiness",
                              lambda body: body.get("status") == "UP")):
                check_alive(services)
                return backend_url
        except (FileNotFoundError, ValueError):
            pass
        time.sleep(0.25)
    raise SmokeFailure(f"Services did not pass their readiness checks within {timeout:g}s.")


def validate_demo(output):
    try:
        results = [json.loads(line) for line in output.splitlines() if line.strip()]
        by_customer = {result["customer"]: result for result in results}
        valid = len(results) == 2 and set(by_customer) == {101, 102}
        for customer, state, risk in ((101, "BLOCKED", 10), (102, "PAID", 85)):
            result = by_customer[customer]
            valid = valid and result["state"] == state
            valid = valid and result["usedRisk"] == risk and result["reservedRisk"] == 0
        valid = valid and "EVIDENCE_MISSING" in by_customer[101]["reasonCodes"]
        if not valid:
            raise ValueError("Unexpected demo result")
    except (ValueError, KeyError, TypeError) as exc:
        raise SmokeFailure("Demo output did not match the expected states, risk totals, "
                           "and missing-evidence rejection.") from exc
    return results


def print_failure_logs(work, tokens):
    for path in sorted(work.glob("*.log")):
        output = "\n".join(path.read_text(errors="replace").splitlines()[-65:])
        for token in tokens.values():
            output = output.replace(token, "[REDACTED]")
        print(f"--- {path.name} (last 65 lines) ---\n{output}", file=sys.stderr)


def request_json(url, token, body=None):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    data = None
    if body is not None:
        headers["Idempotency-Key"] = str(uuid.uuid4())
        data = json.dumps(body).encode()
    try:
        with HTTP.open(Request(url, data=data, headers=headers), timeout=5) as response:
            return json.load(response)
    except (URLError, TimeoutError, ValueError) as exc:
        raise SmokeFailure(f"Experiment HTTP request failed: {type(exc).__name__}") from exc


def run_experiments(base_url, tokens, services, work, timeout, report_dir):
    print("Running six registered paired replay cases in a separate temporary database...",
          flush=True)
    endpoint = base_url + "/api/v1/experiments"
    started = request_json(endpoint, tokens["developer"], {
        "fixtureSetId": "mvp-security-v1", "caseIds": [], "mode": "PAIRED",
        "modelMode": "REPLAY", "repeatCount": 1,
    })
    if started.get("totalRuns") != 12 or not started.get("experimentId"):
        raise SmokeFailure("Experiment API did not queue the expected 12 paired runs.")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        check_alive(services)
        current = request_json(endpoint + "/" + started["experimentId"], tokens["developer"])
        serialized = json.dumps(current, indent=2)
        for token in tokens.values():
            serialized = serialized.replace(token, "[REDACTED]")
        (work / "experiments.log").write_text(serialized)
        if report_dir is not None:
            report_dir.mkdir(parents=True, exist_ok=True)
            pending = report_dir / "http-experiment-report.pending"
            pending.write_text(serialized + "\n")
            pending.replace(report_dir / "http-experiment-report.json")
        if current.get("status") in ("FAILED", "INTERRUPTED"):
            raise SmokeFailure(f"Paired experiment ended as {current['status']}.")
        if current.get("status") == "COMPLETED":
            outputs = current.get("caseOutputs", [])
            errors = [row for row in outputs if row.get("status") != "COMPLETED"
                      or row.get("decision") == "ERROR" or row.get("exclusionReason")]
            pairs = {(row.get("caseId"), row.get("environment"), row.get("repeat"))
                     for row in outputs}
            if (current.get("totalRuns") != 12 or current.get("completedRuns") != 12
                    or len(outputs) != 12 or len(pairs) != 12 or errors
                    or sum(row.get("environment") == "BASELINE" for row in outputs) != 6
                    or sum(row.get("environment") == "FUSE" for row in outputs) != 6
                    or current.get("metrics", {}).get("excludedPairCount") != 0
                    or current.get("resultsSource") != "JAVA_POSTGRES_EXECUTION"
                    or current.get("syntheticModelOutputs") is not True
                    or current.get("liveRobustnessMeasured") is not False):
                error_details = [{"caseId": row.get("caseId"),
                                  "environment": row.get("environment"),
                                  "reason": row.get("exclusionReason") or row.get("reasonCodes")}
                                 for row in errors]
                raise SmokeFailure("Paired experiment validation failed: " + json.dumps({
                    "totalRuns": current.get("totalRuns"),
                    "completedRuns": current.get("completedRuns"), "outputs": len(outputs),
                    "errors": error_details,
                    "exclusions": current.get("metrics", {}).get("exclusions"),
                }))
            return {"fixtureSetId": "mvp-security-v1", "status": "COMPLETED",
                    "completedRuns": 12, "errorRuns": 0, "excludedPairs": 0,
                    "syntheticModelOutputs": True, "liveRobustnessMeasured": False}
        time.sleep(0.5)
    raise SmokeFailure(f"Paired experiment did not complete within {timeout:g}s.")


def run(args):
    java = require_tools()
    tokens = {role: secrets.token_urlsafe(32) for role in ROLES}
    env = isolated_env(tokens)
    with tempfile.TemporaryDirectory(prefix="finsec-fullstack-") as directory:
        work = Path(directory)
        processes = []
        try:
            classpath_file = work / "classpath.txt"
            gradle = shlex.split(args.gradle) if args.gradle else [str(ROOT / "gradlew")]
            print("Compiling the backend and resolving its test classpath...", flush=True)
            build = start(gradle + ["--no-daemon", "--console=plain", "writeTestClasspath",
                                   f"-PtestClasspathFile={classpath_file}"],
                          work / "gradle.log", env)
            processes.append(build)
            if build.wait(timeout=args.build_timeout) != 0:
                raise SmokeFailure("Gradle test compilation/classpath resolution failed.")
            classpath = classpath_file.read_text().strip()
            config_file = work / "config.json"
            port_file = work / "backend.port"
            java_tmp = work / "java-tmp"
            java_tmp.mkdir()
            # Inherit a bound socket, avoiding a free-port discovery/rebind race.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(128)
                agent_url = f"http://127.0.0.1:{listener.getsockname()[1]}"
                config_file.write_text(json.dumps({**tokens, "agentBaseUrl": agent_url,
                                                   "experiments": args.experiments}))
                config_file.chmod(0o600)
                agent = start([sys.executable, "-m", "uvicorn", "agent.app:app", "--fd",
                               str(listener.fileno()), "--no-access-log"],
                              work / "agent.log", env, pass_fds=(listener.fileno(),))
                processes.append(agent)
            backend = start([java, f"-Djava.io.tmpdir={java_tmp}", "-cp", classpath,
                             "com.finsec.fuse.testing.LocalSmokeServer",
                             str(config_file), str(port_file)], work / "backend.log", env)
            processes.append(backend)
            services = [("Python KYC", agent), ("Spring backend", backend)]
            print("Waiting for replay KYC and Spring readiness...", flush=True)
            env["FUSE_BASE_URL"] = await_ready(services, agent_url, port_file,
                                               args.startup_timeout)
            demo = start([sys.executable, "scripts/run_demo.py"], work / "demo.log", env)
            processes.append(demo)
            deadline = time.monotonic() + args.demo_timeout
            while demo.poll() is None:
                check_alive(services)
                if time.monotonic() >= deadline:
                    raise SmokeFailure(f"HTTP demo exceeded {args.demo_timeout:g}s.")
                time.sleep(0.25)
            if demo.returncode != 0:
                raise SmokeFailure(f"HTTP demo failed with status {demo.returncode}.")
            check_alive(services)
            results = validate_demo((work / "demo.log").read_text())
            experiment_result = None
            if args.experiments:
                experiment_result = run_experiments(env["FUSE_BASE_URL"], tokens,
                                                    services, work, args.experiment_timeout,
                                                    args.report_dir)
            check_alive(services)
        except BaseException:
            print_failure_logs(work, tokens)
            raise
        finally:
            for process in reversed(processes):
                stop(process)
    for result in results:
        print(json.dumps(result, ensure_ascii=False))
    if experiment_result:
        print(json.dumps(experiment_result))
    print("FULLSTACK_HTTP_SMOKE_PASS (synthetic replay; real HTTP and PostgreSQL 16.15)")


def positive_seconds(value):
    seconds = float(value)
    if not 0 < seconds < float("inf"):
        raise argparse.ArgumentTypeError("timeout must be a finite positive number")
    return seconds


def interrupted(*_):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", default=os.environ.get("GRADLE_CMD"),
                        help="Gradle command (default: repository's ./gradlew)")
    parser.add_argument("--startup-timeout", type=positive_seconds, default=120)
    parser.add_argument("--build-timeout", type=positive_seconds, default=600)
    parser.add_argument("--demo-timeout", type=positive_seconds, default=240)
    parser.add_argument("--experiments", action="store_true",
                        help="also execute the registered six-case paired replay over HTTP")
    parser.add_argument("--experiment-timeout", type=positive_seconds, default=240)
    parser.add_argument("--report-dir", type=Path,
                        help="optionally retain a sanitized experiment HTTP report here")
    args = parser.parse_args()
    # SIGTERM must unwind the same cleanup path as Ctrl-C and test failures.
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run(args)
    except KeyboardInterrupt:
        print("Full-stack smoke interrupted; no success claimed.", file=sys.stderr)
        return 130
    except (SmokeFailure, OSError, subprocess.SubprocessError) as exc:
        print(f"FULLSTACK_HTTP_SMOKE_FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
