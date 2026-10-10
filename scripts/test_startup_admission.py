"""Run bounded child-JVM startup admission cases on owned ephemeral PostgreSQL 16.15.

Requires POSIX/non-root, Java 21+ and a working Gradle wrapper/dependency cache.
No existing DB, external model, real credentials or production runtime hooks.
Example: python3 scripts/test_startup_admission.py --report-dir /tmp/startup-evidence
The existing writeTestClasspath Gradle task compiles the test-only Java harness.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import tempfile
import time

from test_process_recovery import execute, isolated_env, java_executable, positive

ROOT = Path(__file__).resolve().parents[1]


def diagnostic(destination: Path, stage: str, category: str = "NONE", status: str = "RUNNING") -> None:
    # Call sites supply closed constants only. Never include exception text or command output.
    target = destination / "startup-admission-diagnostic.json"
    target.write_text(json.dumps({"schemaVersion": "FUSE-STARTUP-DIAGNOSTIC-1",
        "status": status, "scenario": "NONE", "stage": stage, "failureCategory": category}) + "\n")
    target.chmod(0o600)


def source_digest() -> str:
    digest = hashlib.sha256()
    files = [ROOT / "build.gradle", Path(__file__).resolve(), ROOT / "scripts/test_process_recovery.py"]
    files += list((ROOT / "backend/src").rglob("*.java"))
    files += [p for p in (ROOT / "backend/src/main/resources").rglob("*") if p.is_file()]
    files += list((ROOT / "evaluation/fixtures").glob("*.json"))
    for path in sorted(set(files)):
        digest.update(str(path.relative_to(ROOT)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def retain_logs(work: Path, destination: Path) -> None:
    secrets = []
    for config in work.rglob("*-config.json"):
        for option in json.loads(config.read_text()).get("options", []):
            name, _, value = option.partition("=")
            if value and ("token" in name.lower() or "password" in name.lower()):
                secrets.append(value)
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
    destination = args.report_dir.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    report = destination / "startup-admission-report.json"
    initial = {"schemaVersion": "FUSE-STARTUP-ADMISSION-1", "status": "NOT_RUN",
               "reason": "Prerequisites and compilation not yet verified", "plannedScenarioCount": 11,
               "passedScenarioCount": 0, "syntheticModelOutputs": True, "liveRobustnessMeasured": False}
    report.write_text(json.dumps(initial, indent=2) + "\n")
    stage = "SOURCE_DIGEST"
    diagnostic(destination, stage)
    before = ""
    started = time.monotonic()
    try:
        before = source_digest()
        stage = "PREREQUISITES"
        diagnostic(destination, stage)
        java = java_executable()
        env = isolated_env()
        env = {k: v for k, v in env.items() if not k.endswith("_API_KEY")
               and not k.startswith(("OPENAI_", "ANTHROPIC_"))}
        with tempfile.TemporaryDirectory(prefix="finsec-startup-admission-") as directory:
            work = Path(directory)
            try:
                # Always compile this source tree. A caller-supplied stale classpath
                # cannot establish current-source startup acceptance.
                stage = "COMPILATION"
                diagnostic(destination, stage)
                classpath_file = work / "classpath.txt"
                gradle = shlex.split(args.gradle) if args.gradle else [str(ROOT / "gradlew")]
                code = execute(gradle + ["--no-daemon", "--console=plain", "writeTestClasspath",
                                        f"-PtestClasspathFile={classpath_file}"],
                               work / "gradle.log", env, args.build_timeout)
                if code:
                    raise RuntimeError(f"Compilation failed with exit code {code}; runtime cases NOT_RUN")
                stage = "CLASSPATH"
                diagnostic(destination, stage)
                classpath = classpath_file.read_text().strip()
                if not classpath:
                    raise RuntimeError("Test runtime classpath is empty")
                scenarios = work / "scenarios"
                scenarios.mkdir()
                java_tmp = work / "java-tmp"
                java_tmp.mkdir()
                stage = "HARNESS"
                diagnostic(destination, stage)
                code = execute([java, f"-Djava.io.tmpdir={java_tmp}", "-cp", classpath,
                                "com.finsec.fuse.testing.StartupAdmissionHarness", str(scenarios), str(report)],
                               work / "startup-admission.log", env, args.timeout)
                stage = "REPORT_VALIDATION" if code == 0 else "HARNESS"
                if code == 0:
                    diagnostic(destination, stage)
                output = json.loads(report.read_text())
                after = source_digest()
                output.update(exitCode=code, sourceHashBefore=before, sourceHashAfter=after,
                              sourceUnchangedDuringRun=before == after,
                              elapsedSeconds=round(time.monotonic() - started, 3),
                              command="python3 scripts/test_startup_admission.py")
                if before != after:
                    output["status"] = "SOURCE_CHANGED_DURING_RUN"
                report.write_text(json.dumps(output, indent=2) + "\n")
                if code or output.get("status") != "PASS" or output.get("passedScenarioCount") != 11:
                    raise RuntimeError(f"Startup acceptance failed or incomplete; inspect {report}")
                diagnostic(destination, "COMPLETE", status="PASS")
                print(f"STARTUP_ADMISSION_PASS: 11/11; real PostgreSQL 16.15, child JVMs, synthetic replay. Evidence: {report}")
            finally:
                try:
                    retain_logs(work, destination)
                except Exception:
                    stage = "LOG_RETENTION"
                    raise
    except BaseException as failure:
        category = ("TIMEOUT" if isinstance(failure, subprocess.TimeoutExpired) else
                    "INTERRUPTED" if isinstance(failure, KeyboardInterrupt) else "EXECUTION_FAILED")
        if stage == "HARNESS":
            # Preserve the child's last fixed stage/scenario. A timeout still gets its own category.
            try:
                value = json.loads((destination / "startup-admission-diagnostic.json").read_text())
                value["status"] = "FAIL"
                if category != "EXECUTION_FAILED" or value.get("failureCategory") == "NONE":
                    value["failureCategory"] = category
                (destination / "startup-admission-diagnostic.json").write_text(json.dumps(value) + "\n")
            except (OSError, ValueError, TypeError):
                diagnostic(destination, stage, category, "FAIL")
        else:
            diagnostic(destination, stage, category, "FAIL")
        output = json.loads(report.read_text())
        if output.get("status") not in ("NOT_RUN", "SOURCE_CHANGED_DURING_RUN"):
            output["status"] = "INCOMPLETE_OR_FAILED"
        # Invalidate terminal success before trying another fallible source read.
        # An unreadable source tree must not preserve a child-written PASS report.
        output.update(reason=type(failure).__name__ + ": " + str(failure), sourceHashBefore=before,
                      sourceHashAfter="", sourceUnchangedDuringRun=False,
                      elapsedSeconds=round(time.monotonic() - started, 3))
        report.write_text(json.dumps(output, indent=2) + "\n")
        try:
            output["sourceHashAfter"] = source_digest()
        except Exception:
            pass
        report.write_text(json.dumps(output, indent=2) + "\n")
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gradle", default=os.environ.get("GRADLE_CMD"))
    parser.add_argument("--report-dir", type=Path, default=ROOT / "backend/build/reports/startup-admission")
    parser.add_argument("--build-timeout", type=positive, default=300)
    parser.add_argument("--timeout", type=positive, default=1200)
    args = parser.parse_args()
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    run(args)


if __name__ == "__main__":
    main()
