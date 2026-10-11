#!/usr/bin/env python3
"""Validate startup evidence and print closed diagnostic IDs, never private log content."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ('MISSING_KEY', 'MISSING_SERVICE_TOKEN', 'INVALID_POLICY', 'MISSING_POLICY',
             'DB_UNAVAILABLE', 'ORDINARY_DEVELOPER_TOKEN', 'MISSING_FUSE', 'MISSING_KYC',
             'MISSING_LOAN', 'MISSING_PAYMENT', 'VALID_REPLAY_NO_MODEL_KEY')
STAGES = ('SOURCE_DIGEST', 'PREREQUISITES', 'COMPILATION', 'CLASSPATH', 'HARNESS',
          'REPORT_VALIDATION', 'LOG_RETENTION', 'COMPLETE', 'DATABASE_START', 'FIXTURE_SETUP', 'PREPARE_START',
          'PREPARE_ADMISSION', 'BASELINE', 'SUBJECT_START', 'READINESS_REFUSAL',
          'REFUSAL_INVARIANTS', 'REPAIR', 'RECOVERY_READINESS', 'RECOVERY_CLAIM',
          'VALID_CONTROL', 'INVALID_EXIT', 'EXPECTED_FAILURE_CAUSE', 'INVALID_INVARIANTS',
          'FINAL_INVARIANTS')
CATEGORIES = ('NONE', 'ASSERTION_FAILED', 'EXECUTION_FAILED', 'TIMEOUT', 'INTERRUPTED')
MAX_BYTES = 1024 * 1024


def fixed(value, choices, fallback='UNKNOWN'):
    # Return canonical constants, not untrusted strings, even on accepted membership.
    return next((candidate for candidate in choices if type(value) is str and value == candidate), fallback)


def summarize(report, diagnostic, current_source_hash):
    data = report if type(report) is dict else {}
    diag = diagnostic if type(diagnostic) is dict else {}
    rows = data.get('scenarios')
    rows = rows if type(rows) is list and len(rows) <= len(SCENARIOS) else []
    statuses = []
    for name in SCENARIOS:
        matching = [row for row in rows if type(row) is dict and row.get('scenario') == name]
        status = fixed(matching[0].get('verdict'), ('PASS', 'FAIL'), 'INVALID') if len(matching) == 1 else 'INVALID' if matching else 'NOT_RUN'
        statuses.append({'scenario': name, 'status': status})
    passed = sum(row['status'] == 'PASS' for row in statuses)
    shape = (data.get('schemaVersion') == 'FUSE-STARTUP-ADMISSION-1' and len(rows) == 11
             and all(row['status'] in ('PASS', 'FAIL') for row in statuses))
    counts = (type(data.get('plannedScenarioCount')) is int and data['plannedScenarioCount'] == 11
              and type(data.get('passedScenarioCount')) is int and data['passedScenarioCount'] == passed)
    source_matches = (type(current_source_hash) is str and re.fullmatch('[a-f0-9]{64}', current_source_hash) is not None
                      and data.get('sourceHashBefore') == current_source_hash and data.get('sourceHashAfter') == current_source_hash
                      and data.get('sourceUnchangedDuringRun') is True)
    scenario = fixed(diag.get('scenario'), ('NONE',) + SCENARIOS)
    stage = fixed(diag.get('stage'), STAGES)
    category = fixed(diag.get('failureCategory'), CATEGORIES)
    diag_status = fixed(diag.get('status'), ('RUNNING', 'FAIL', 'PASS'))
    diag_valid = (diag.get('schemaVersion') == 'FUSE-STARTUP-DIAGNOSTIC-1'
                  and 'UNKNOWN' not in (scenario, stage, category, diag_status))
    exit_success = type(data.get('exitCode')) is int and data['exitCode'] == 0
    success = (shape and counts and passed == 11 and source_matches and exit_success
               and data.get('status') == 'PASS' and data.get('cleanupVerified') is True
               and data.get('resultsSource') == 'REAL_POSTGRES_CHILD_JVM_STARTUP'
               and data.get('syntheticModelOutputs') is True and data.get('liveRobustnessMeasured') is False
               and diag_valid and diag_status == 'PASS' and stage == 'COMPLETE' and category == 'NONE' and scenario == 'NONE')
    return {'schemaVersion': 'FUSE-STARTUP-SUMMARY-1', 'status': 'PASS' if success else 'FAIL',
            'plannedScenarioCount': 11, 'observedScenarioCount': len(rows), 'passedScenarioCount': passed,
            'evidenceShapeVerified': shape and counts, 'sourceUnchangedAndMatchesCurrentTree': source_matches,
            'cleanupVerified': data.get('cleanupVerified') is True, 'exitSuccessful': exit_success,
            'diagnosticVerified': diag_valid, 'scenario': scenario, 'stage': stage, 'failureCategory': category,
            'scenarios': statuses}


def read_private(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        return None
    with path.open('rb') as source:
        payload = source.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        return None
    return json.loads(payload)


def current_digest():
    sys.path.insert(0, str(ROOT / 'scripts'))
    spec = importlib.util.spec_from_file_location('startup_source_digest', ROOT / 'scripts/test_startup_admission.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_digest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'backend/build/reports/startup-admission/startup-admission-report.json')
    parser.add_argument('--diagnostic', type=Path, default=ROOT / 'backend/build/reports/startup-admission/startup-admission-diagnostic.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'safe-artifacts/startup-admission-summary.json')
    args = parser.parse_args()
    try:
        result = summarize(read_private(args.input), read_private(args.diagnostic), current_digest())
    except Exception:
        result = summarize(None, None, '')
    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
        args.output.chmod(0o600)
    except Exception:
        result = summarize(None, None, '')
    print(json.dumps(result))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
