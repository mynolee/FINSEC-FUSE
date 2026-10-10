#!/usr/bin/env python3
"""Verify process-recovery evidence and publish only fixed aggregate fields."""
import argparse
import importlib.util
import json
from pathlib import Path
import re

SCENARIOS = ('KYC_INFLIGHT', 'PAY_CLAIM', 'PAY_RESERVED', 'PAY_COMMITTED', 'DB_UNAVAILABLE')
ROOT = Path(__file__).resolve().parents[1]


def summarize(report: dict | None, current_source_hash: str) -> dict:
    data = report or {}
    raw_rows = data.get('scenarios')
    rows = raw_rows if isinstance(raw_rows, list) else []
    known = [row for row in rows if isinstance(row, dict) and row.get('scenario') in SCENARIOS]
    counts = {name: sum(row.get('scenario') == name for row in known) for name in SCENARIOS}
    statuses = []
    for name in SCENARIOS:
        observed = [row for row in known if row['scenario'] == name]
        verdict = observed[0].get('verdict') if len(observed) == 1 else None
        status = 'NOT_RUN' if not observed else verdict if verdict in {'PASS', 'FAIL'} else 'INVALID'
        statuses.append({'scenario': name, 'status': status})
    passed = sum(row['status'] == 'PASS' for row in statuses)
    hash_valid = bool(re.fullmatch(r'[a-f0-9]{64}', current_source_hash))
    source_matches = (hash_valid and data.get('sourceHashBefore') == current_source_hash
                      and data.get('sourceHashAfter') == current_source_hash
                      and data.get('sourceUnchangedDuringRun') is True)
    shape_valid = len(rows) == 5 and len(known) == 5 and all(count == 1 for count in counts.values())
    count_valid = (type(data.get('plannedScenarioCount')) is int and data['plannedScenarioCount'] == 5
                   and type(data.get('passedScenarioCount')) is int and data['passedScenarioCount'] == passed)
    exit_valid = type(data.get('exitCode')) is int and data['exitCode'] == 0
    clean = data.get('cleanupVerified') is True
    attested = (data.get('resultsSource') == 'REAL_POSTGRES_CHILD_JVM_CRASH_AND_OUTAGE'
                and data.get('syntheticModelOutputs') is True and data.get('liveRobustnessMeasured') is False)
    success = (data.get('status') == 'PASS' and shape_valid and count_valid and passed == 5
               and exit_valid and clean and source_matches and attested)
    return {'schemaVersion': 'FUSE-PROCESS-SUMMARY-1',
            'status': 'NOT_RUN' if report is None or data.get('status') == 'NOT_RUN' else 'PASS' if success else 'FAIL',
            'plannedScenarioCount': 5, 'observedScenarioCount': len(rows), 'passedScenarioCount': passed,
            'cleanupVerified': clean, 'sourceUnchangedAndMatchesCurrentTree': source_matches,
            'sourceHash': current_source_hash if hash_valid else None,
            'exitSuccessful': exit_valid, 'evidenceShapeVerified': shape_valid and count_valid,
            'syntheticReplayAndRealProcessAttestation': attested, 'scenarios': statuses,
            'scope': 'Five real PostgreSQL/child-JVM failure scenarios only; full T12 and LIVE are not claimed.',
            'privacy': 'No database rows, process IDs, HTTP bodies, credentials, paths, or raw logs.'}


def current_digest() -> str:
    path = ROOT / 'scripts/test_process_recovery.py'
    spec = importlib.util.spec_from_file_location('process_recovery_source_digest', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.source_digest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'backend/build/reports/process-recovery/process-recovery-report.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'safe-artifacts/process-recovery-summary.json')
    args = parser.parse_args()
    try:
        report = json.loads(args.input.read_bytes()) if args.input.is_file() else None
        if report is not None and not isinstance(report, dict):
            raise ValueError('Invalid report shape')
        result = summarize(report, current_digest())
    except Exception:
        result = summarize({}, '')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    args.output.chmod(0o600)
    print(json.dumps(result))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
