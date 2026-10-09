#!/usr/bin/env python3
"""Presence gates for independently reviewable feature trees, never a test pass."""
import argparse
import json
import os
from pathlib import Path

COMPONENTS = {
    "backend": (
        "gradlew", "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties",
        "build.gradle", "settings.gradle",
        "backend/src/main/java/com/finsec/fuse/FuseApplication.java",
        "backend/src/main/java/com/finsec/fuse/auth/DemoAuthFilter.java",
        "backend/src/main/java/com/finsec/fuse/policy/EvidenceValidator.java",
        "backend/src/main/java/com/finsec/fuse/workflow/WorkflowService.java",
        "backend/src/main/java/com/finsec/fuse/payment/PaymentTxService.java",
        "backend/src/main/java/com/finsec/fuse/quarantine/QuarantineService.java",
        "backend/src/main/java/com/finsec/fuse/experiments/ExperimentService.java",
        "backend/src/main/java/com/finsec/fuse/experiments/ExperimentPairedInput.java",
        "backend/src/main/java/com/finsec/fuse/experiments/ExperimentArmBinding.java",
        "backend/src/main/resources/db/migration/V1__fuse_core.sql",
        "backend/src/main/resources/db/migration/V5__experiment_arm_bindings.sql",
        "backend/src/test/java/com/finsec/fuse/integration/WorkflowHappyPathIT.java",
        "evaluation/tests/fixtures/metrics-parity.json",
        "evaluation/fixtures/mvp-security-v1.json", "evaluation/fixtures/security-evaluation-v1.json",
    ),
    "agent_harness": (
        "agent/requirements-dev.txt", "agent/requirements.txt", "agent/app.py", "agent/tests/test_agent.py",
        "evaluation/scenario_runner.py", "evaluation/fixture_loader.py", "evaluation/metrics.py",
        "evaluation/export.py", "evaluation/export_labels.json", "evaluation/tests/test_evaluation.py",
        "evaluation/fixtures/security-evaluation-v1.json",
    ),
    "frontend": (
        "frontend/package.json", "frontend/package-lock.json", "frontend/tsconfig.json",
        "frontend/src/App.tsx", "frontend/src/App.test.tsx", "frontend/src/components/Workflows.tsx",
        "frontend/src/components/Quarantine.tsx", "frontend/src/components/Experiments.tsx",
        "frontend/src/experimentExport.ts", "evaluation/export_labels.json",
    ),
    "process_files": (
        "scripts/test-process-recovery.sh", "scripts/test_process_recovery.py", "scripts/ci-process-report.py",
        "backend/src/test/java/com/finsec/fuse/testing/ProcessRecoveryHarness.java",
        "backend/src/test/java/com/finsec/fuse/testing/ProcessRecoveryServer.java",
    ),
    "compose_files": (
        "compose.yaml", ".env.example", ".dockerignore", "backend/Dockerfile", "agent/Dockerfile",
        "frontend/Dockerfile", "frontend/nginx.conf", "scripts/bootstrap-dev.sh", "scripts/init-postgres.sh",
        "scripts/run_demo.py", "scripts/test-fullstack.sh", "scripts/test_fullstack.py",
        "scripts/ci-verify.py", "scripts/ci-test-report.py", "scripts/ci-support-test.py", "scripts/ci-run.py",
        "frontend/playwright.config.ts", "frontend/tests/e2e/console.spec.ts",
        "frontend/tests/e2e/fullstack.spec.ts", "frontend/tests/e2e/safe-reporter.ts",
    ),
}


def inspect(root: Path) -> dict:
    result = {}
    for name, paths in COMPONENTS.items():
        missing = [path for path in paths if not (root / path).is_file()]
        result[name] = {"ready": not missing, "status": "READY_TO_RUN" if not missing else "SKIPPED",
                        "missing": missing}
    process_missing = sorted(set(result["backend"]["missing"] + result["process_files"]["missing"]))
    result["process_recovery"] = {"ready": not process_missing,
                                  "status": "READY_TO_RUN" if not process_missing else "SKIPPED",
                                  "missing": process_missing}
    missing = sorted({path for part in result.values() for path in part["missing"]})
    result["combined"] = {"ready": not missing, "status": "READY_TO_RUN" if not missing else "SKIPPED",
                          "missing": missing}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    results = inspect(args.root)
    summary = ["## Component prerequisites", "Presence is not a passing test. Separate feature PRs can omit other components."]
    for name, result in results.items():
        summary.append(f"- {name}: {result['status']}")
        if result["missing"]:
            summary.extend(f"  - Missing: {path}" for path in result["missing"])
            print(f"::warning title=SKIPPED component::{name}: prerequisites absent; no verification claimed.")
    if not results["combined"]["ready"]:
        summary.append("Combined Compose/browser verification: SKIPPED. Partial-tree green checks do not prove integration.")
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            for name, result in results.items():
                output.write(f"{name}={'true' if result['ready'] else 'false'}\n")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
            output.write("\n".join(summary) + "\n")
    print(json.dumps(results, indent=2))
    return int(args.require_complete and not results["combined"]["ready"])


if __name__ == "__main__":
    raise SystemExit(main())
