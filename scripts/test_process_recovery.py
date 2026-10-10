"""Isolated process-crash/outage evidence on real PostgreSQL 16.15.

Requires POSIX, non-root, Java 21+, and the checked-in Gradle wrapper. Uses only
test-classpath Java entry points and fresh temporary databases. No production
runtime hooks, public bypass APIs, real providers, or existing databases.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def java_executable() -> str:
    if os.name != "posix" or os.geteuid() == 0:
        raise RuntimeError("Run on a POSIX host as non-root; PostgreSQL forbids root.")
    home = os.environ.get("JAVA_HOME")
    java = str(Path(home) / "bin" / "java") if home else shutil.which("java")
    if not java:
        raise RuntimeError("Java 21+ is required; set JAVA_HOME.")
    version = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=15)
    match = re.search(r'version "(\d+)', version.stdout + version.stderr)
    if version.returncode or not match or int(match.group(1)) < 21:
        raise RuntimeError("Java 21+ is required; check JAVA_HOME and PATH.")
    return java


def isolated_env() -> dict[str, str]:
    return {key: value for key, value in os.environ.items()
            if not key.startswith(("FUSE_", "SPRING_"))
            and key not in ("PORT", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")}


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        process.terminate()  # Parent Java shutdown hook stops its own Spring/PG children.
        try:
            process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def execute(command: list[str], log: Path, env: dict[str, str], timeout: float) -> int:
    with log.open("w") as output:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=timeout)
        finally:
            stop(process)


def source_digest() -> str:
    digest = hashlib.sha256()
    paths = [ROOT / "build.gradle", ROOT / "scripts/test_process_recovery.py",
             ROOT / "scripts/test-process-recovery.sh"]
    paths += list((ROOT / "backend/src").rglob("*.java"))
    paths += list((ROOT / "backend/src/main/resources").rglob("*"))
    paths += list((ROOT / "evaluation/fixtures").glob("*.json"))
    for path in sorted(path for path in paths if path.is_file()):
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def retain_logs(work: Path, destination: Path) -> None:
    # Private temporary configs/keys/data never leave work; preserve sanitized logs only.
    secrets = []
    for config in work.rglob("*-config.json"):
        try:
            secrets.append(json.loads(config.read_text())["token"])
        except (OSError, KeyError, ValueError):
            pass
    for log in work.rglob("*.log"):
        if "database" in log.relative_to(work).parts:
            continue
        content = log.read_text(errors="replace")
        for secret in secrets:
            content = content.replace(secret, "[REDACTED]")
        output = destination / "logs" / log.relative_to(work)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content)


def run(args: argparse.Namespace) -> None:
    java = java_executable()
    env = isolated_env()
    destination = args.report_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    report = destination / "process-recovery-report.json"
    # A failed build must not leave yesterday's passing report looking current.
    report.write_text(json.dumps({"status": "NOT_RUN", "reason": "Compilation not yet completed"}) + "\n")
    before_hash = source_digest()
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="finsec-process-recovery-") as directory:
        work = Path(directory)
        try:
            if args.classpath_file:
                classpath_file = args.classpath_file.resolve()
            else:
                classpath_file = work / "classpath.txt"
                gradle = shlex.split(args.gradle) if args.gradle else [str(ROOT / "gradlew")]
                code = execute(gradle + ["--no-daemon", "--console=plain", "writeTestClasspath",
                                        f"-PtestClasspathFile={classpath_file}"], work / "gradle.log", env,
                               args.build_timeout)
                if code:
                    raise RuntimeError(f"Test-classpath compilation failed with exit code {code}.")
            classpath = classpath_file.read_text().strip()
            if not classpath:
                raise RuntimeError("Resolved test classpath was empty.")
            java_work = work / "scenarios"
            java_work.mkdir()
            java_tmp = work / "java-tmp"
            java_tmp.mkdir()
            code = execute([java, f"-Djava.io.tmpdir={java_tmp}", "-cp", classpath,
                            "com.finsec.fuse.testing.ProcessRecoveryHarness", str(java_work), str(report)],
                           work / "process-recovery.log", env, args.timeout)
            output = json.loads(report.read_text())
            after_hash = source_digest()
            output.update(command="scripts/test-process-recovery.sh", exitCode=code,
                          seedHash=hashlib.sha256((ROOT / "backend/src/main/resources/fixtures/demo_seed.json").read_bytes()).hexdigest(),
                          sourceHashBefore=before_hash, sourceHashAfter=after_hash,
                          sourceUnchangedDuringRun=before_hash == after_hash,
                          elapsedSeconds=round(time.time() - started, 3))
            if before_hash != after_hash:
                output["status"] = "SOURCE_CHANGED_DURING_RUN"
            report.write_text(json.dumps(output, indent=2) + "\n")
            if code or output.get("status") != "PASS":
                raise RuntimeError(f"Process recovery verification failed; inspect {report} and sanitized logs.")
            print("PROCESS_RECOVERY_PASS: 5/5 scenarios; cleanup verified; synthetic replay, real PostgreSQL 16.15")
            print(f"Evidence: {report}")
        finally:
            retain_logs(work, destination)


def positive(value: str) -> float:
    result = float(value)
    if not 0 < result < float("inf"):
        raise argparse.ArgumentTypeError("Timeout must be finite and positive")
    return result


def interrupted(*_) -> None:
    raise KeyboardInterrupt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", default=os.environ.get("GRADLE_CMD"))
    parser.add_argument("--classpath-file", type=Path,
                        help="Use an already compiled test classpath; caller must ensure it matches current sources")
    parser.add_argument("--report-dir", type=Path, default=ROOT / "backend/build/reports/process-recovery")
    parser.add_argument("--build-timeout", type=positive, default=300)
    parser.add_argument("--timeout", type=positive, default=420)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    run(args)


if __name__ == "__main__":
    main()
