#!/usr/bin/env python3
"""Publish test COUNTS only, excluding failure text, stdout and raw test reports."""
import argparse
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def summarize(root: Path) -> dict:
    tasks = {}
    for task in ('test', 'integrationTest'):
        files = sorted((root / task).glob('TEST-*.xml'))
        counts = dict(tests=0, failures=0, errors=0, skipped=0)
        for path in files:
            suite = ET.parse(path).getroot()
            for key in counts:
                counts[key] += int(suite.attrib.get(key, 0))
        tasks[task] = {'status': 'NOT_RUN' if not files or counts['tests'] == 0 else
                      'FAIL' if counts['failures'] or counts['errors'] else 'PASS', **counts}
    return {'schemaVersion': 'FUSE-TEST-COUNTS-1', 'tasks': tasks,
            'scope': 'Current checkout only; counts do not replace Compose/browser or LIVE verification.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('backend/build/test-results'))
    parser.add_argument('--output', type=Path, default=Path('safe-artifacts/backend-test-summary.json'))
    args = parser.parse_args()
    summary = summarize(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    return int(any(part['status'] != 'PASS' or part['skipped'] for part in summary['tasks'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
