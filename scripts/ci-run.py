#!/usr/bin/env python3
"""Run a check without publishing potentially sensitive stdout/stderr diagnostics."""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile


# Diagnostic bodies stay private. Publish only these fixed booleans, never regex
# captures, exception text, command arguments, paths, environment or matched lines.
# Signals aid diagnosis; they neither establish a root cause nor change the gate.
COMPOSE_SIGNALS = {
    'DAEMON_UNAVAILABLE': rb'cannot connect to the docker daemon|is the docker daemon running|error during connect',
    'CONFIGURATION_INVALID': rb'error while interpolating|invalid interpolation|required variable .{0,200} is missing|validating .{0,200}:|no configuration file provided|unsupported config option|additional propert(?:y|ies) .{0,200} not allowed',
    'IMAGE_FETCH_FAILED': rb'pull access denied|manifest unknown|toomanyrequests|error pulling image|failed to resolve source metadata|failed to fetch oauth token',
    'BUILD_FAILED': rb'failed to solve:|failed to read dockerfile|unable to prepare context|failed to compute cache key',
    'STORAGE_EXHAUSTED': rb'no space left on device|disk quota exceeded',
    'RESOURCE_EXHAUSTED': rb'cannot allocate memory|out of memory|resource temporarily unavailable',
    'PORT_BIND_FAILED': rb'port is already allocated|address already in use|failed to bind host port',
    'CONTAINER_NOT_READY': rb'container .{0,200} is unhealthy|dependency failed to start|did not become healthy|timeout waiting for containers',
    'ACCESS_DENIED': rb'permission denied|operation not permitted',
    'NETWORK_FAILED': rb'no such host|network is unreachable|tls handshake timeout|i/o timeout|connection timed out|certificate signed by unknown authority',
    'CLI_INVALID': rb'unknown (?:command|flag|shorthand flag)|flag provided but not defined|requires (?:at least|exactly) [0-9]+ argument',
    'YAML_INVALID': rb'yaml:|did not find expected key|mapping values are not allowed|found character that cannot start',
    'ENV_FILE_INVALID': rb'failed to read .{0,200}env|env file .{0,200} not found|unexpected character .{0,80} variable name',
    'DEPENDENCY_MISSING': rb'docker: .{0,80} not found|executable file not found|buildx .{0,80} missing|compose .{0,80} is not a docker command',
    'TRANSPORT_INTERRUPTED': rb'unexpected eof|connection reset by peer|remote error: tls|failed to do request|http: server gave http response to https client',
    'REGISTRY_HTTP_REJECTED': rb'429 too many requests|503 service unavailable|502 bad gateway|504 gateway timeout|unexpected status .{0,40}(?:429|50[234])',
}
DIAGNOSTIC_BYTES = 1024 * 1024


def compose_diagnostic_signals(diagnostic):
    """Inspect a bounded head/tail; output is independent of untrusted text."""
    diagnostic.flush()
    size = diagnostic.tell()
    diagnostic.seek(0)
    head = diagnostic.read(DIAGNOSTIC_BYTES)
    # Separate chunks prevent accidental matches across omitted bytes.
    chunks = [head]
    if size > DIAGNOSTIC_BYTES:
        diagnostic.seek(max(DIAGNOSTIC_BYTES, size - DIAGNOSTIC_BYTES))
        chunks.append(diagnostic.read(DIAGNOSTIC_BYTES))
    flags = {key: any(re.search(pattern, chunk, re.IGNORECASE) is not None for chunk in chunks)
             for key, pattern in COMPOSE_SIGNALS.items()}
    return {'signals': flags, 'unclassified': not any(flags.values()),
            'scanTruncated': size > 2 * DIAGNOSTIC_BYTES}


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
        if result.returncode != 0 and command[:2] == ['docker', 'compose']:
            print('compose-failure-observation: ' + json.dumps(compose_diagnostic_signals(diagnostic), sort_keys=True))
    code = result.returncode
    print(f'{args.label}: {"PASS" if code == 0 else "FAIL"} (exit {code}). Raw logs were not published.')
    return code if code >= 0 else 128 - code


if __name__ == '__main__':
    raise SystemExit(main())
