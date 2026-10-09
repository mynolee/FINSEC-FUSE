#!/usr/bin/env python3
"""Run a check without publishing potentially sensitive stdout/stderr diagnostics."""
import argparse
import os
import re
import subprocess
import sys
import tempfile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,60}', args.label):
        parser.error('label must be a simple check name')
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command is required')
    # Never upload this temporary file. It is deleted on exit, even after a failure.
    with tempfile.TemporaryFile(mode='w+b', dir=os.getenv('RUNNER_TEMP')) as diagnostic:
        try:
            result = subprocess.run(command, stdout=diagnostic, stderr=subprocess.STDOUT)
        except Exception as error:
            print(f'{args.label}: FAIL ({type(error).__name__}); diagnostic body withheld.', file=sys.stderr)
            return 1
    code = result.returncode
    print(f'{args.label}: {"PASS" if code == 0 else "FAIL"} (exit {code}). Raw logs were not published.')
    return code if code >= 0 else 128 - code


if __name__ == '__main__':
    raise SystemExit(main())
