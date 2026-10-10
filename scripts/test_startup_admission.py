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
import tempfile
import time

from test_process_recovery import execute, isolated_env, java_executable, positive

ROOT = Path(__file__).resolve().parents[1]


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
    before = source_digest()
    started = time.monotonic()
    try:
        java = java_executable()
        env = isolated_env()
        env = {k: v for k, v in env.items() if not k.endswith("_API_KEY")
               and not k.startswith(("OPENAI_", "ANTHROPIC_"))}
        with tempfile.TemporaryDirectory(prefix="finsec-startup-admission-") as directory:
            work = Path(directory)
            try:
                # Always compile this source tree. A caller-supplied stale classpath
                # cannot establish current-source startup acceptance.
                classpath_file = work / "classpath.txt"
                gradle = shlex.split(args.gradle) if args.gradle else [str(ROOT / "gradlew")]
                code = execute(gradle + ["--no-daemon", "--console=plain", "writeTestClasspath",
                                        f"-PtestClasspathFile={classpath_file}"],
                               work / "gradle.log", env, args.build_timeout)
                if code:
                    raise RuntimeError(f"Compilation failed with exit code {code}; runtime cases NOT_RUN")
                classpath = classpath_file.read_text().strip()
                if not classpath:
                    raise RuntimeError("Test runtime classpath is empty")
                scenarios = work / "scenarios"
                scenarios.mkdir()
                java_tmp = work / "java-tmp"
                java_tmp.mkdir()
                code = execute([java, f"-Djava.io.tmpdir={java_tmp}", "-cp", classpath,
                                "com.finsec.fuse.testing.StartupAdmissionHarness", str(scenarios), str(report)],
                               work / "startup-admission.log", env, args.timeout)
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
                print(f"STARTUP_ADMISSION_PASS: 11/11; real PostgreSQL 16.15, child JVMs, synthetic replay. Evidence: {report}")
            finally:
                retain_logs(work, destination)
    except BaseException as failure:
        output = json.loads(report.read_text())
        if output.get("status") not in ("NOT_RUN", "SOURCE_CHANGED_DURING_RUN"):
            output["status"] = "INCOMPLETE_OR_FAILED"
        output.update(reason=type(failure).__name__ + ": " + str(failure), sourceHashBefore=before,
                      sourceHashAfter=source_digest(), elapsedSeconds=round(time.monotonic() - started, 3))
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
