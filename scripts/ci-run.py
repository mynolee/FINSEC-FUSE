#!/usr/bin/env python3
"""Run a check without publishing potentially sensitive stdout/stderr diagnostics."""
import argparse
import json
import os
from pathlib import Path
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
ROOT = Path(__file__).resolve().parents[1]
DOCKERFILES = ('agent/Dockerfile', 'backend/Dockerfile', 'frontend/Dockerfile', 'ingress/Dockerfile')
BASE_IMAGES = {
    'python:3.12.15-slim': 'PYTHON_AGENT',
    'node:24-alpine': 'NODE_BUILD',
    'eclipse-temurin:21-jdk': 'JAVA_BUILD',
    'eclipse-temurin:21-jre': 'JAVA_RUNTIME',
    'nginxinc/nginx-unprivileged:1.28-alpine': 'NGINX_RUNTIME',
}
TRANSIENT_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})
REGISTRY_ERROR_CONTEXT = re.compile(
    rb'\b(?:failed to (?:resolve source metadata|fetch oauth token|authorize|do request|solve)|'
    rb'error pulling image|unexpected (?:http )?status|http status(?: code)?)', re.IGNORECASE)
HTTP_STATUS_PATTERNS = (
    # Do not mistake ports, image tags, byte counts or arbitrary three-digit text for HTTP statuses.
    rb'\b(?:unexpected (?:http )?status(?: code)?|http status(?: code)?)[ \t]*[:=]?[ \t]+([1-5][0-9]{2})(?=[ \t]|$)',
    rb'\bunexpected status from[^\r\n]{0,4096}:[ \t]+([1-5][0-9]{2})(?=[ \t]|$)',
)
HTTP_STATUS_NAMES = {401: b'Unauthorized', 403: b'Forbidden', 404: b'Not Found',
                     429: b'Too Many Requests', 500: b'Internal Server Error',
                     502: b'Bad Gateway', 503: b'Service Unavailable', 504: b'Gateway Timeout'}
STATUS_CONTEXT = re.compile(rb'\b(?:unexpected (?:http )?status(?: code)?|http status(?: code)?)\b', re.IGNORECASE)
DENIAL_PATTERN = re.compile(
    rb'pull access denied|requested access .{0,80} denied|\bunauthorized\b|\bforbidden\b|authentication required|'
    rb'insufficient_scope|repository does not exist|manifest unknown|authorization failed', re.IGNORECASE)


def project_base_images(root=ROOT):
    """Only closed image IDs for reviewed literals actually present in project Dockerfiles."""
    present = {}
    for relative in DOCKERFILES:
        try:
            path = root / relative
            if path.is_symlink() or path.stat().st_size > 65536:
                continue
            for line in path.read_text().splitlines():
                match = re.fullmatch(r'\s*FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?\s*', line, re.IGNORECASE)
                if match and match.group(1) in BASE_IMAGES:
                    image = match.group(1)
                    present[image] = BASE_IMAGES[image]
        except (OSError, UnicodeError):
            continue
    return present


def registry_observation(chunks, truncated, flags, images):
    statuses, identifiers = set(), set()
    incomplete = truncated
    denied = any(DENIAL_PATTERN.search(chunk) is not None for chunk in chunks)
    for chunk in chunks:
        for line in chunk.splitlines():
            # The matching window is bounded and never printed or captured into output strings.
            if len(line) > 8192:
                incomplete = True
                continue
            if REGISTRY_ERROR_CONTEXT.search(line) is None:
                continue
            contexts = list(STATUS_CONTEXT.finditer(line))
            for index, context in enumerate(contexts):
                end = contexts[index + 1].start() if index + 1 < len(contexts) else len(line)
                segment = line[context.start():end]
                if not any(re.search(pattern, segment, re.IGNORECASE) for pattern in HTTP_STATUS_PATTERNS):
                    incomplete = True
            for pattern in HTTP_STATUS_PATTERNS:
                statuses.update(int(value) for value in re.findall(pattern, line, re.IGNORECASE))
            for code, phrase in HTTP_STATUS_NAMES.items():
                pattern = rb'(?<![A-Za-z0-9_])' + str(code).encode() + rb'[ \t]+' + re.escape(phrase) + rb'\b'
                if re.search(pattern, line, re.IGNORECASE):
                    statuses.add(code)
            for image, identifier in images.items():
                if BASE_IMAGES.get(image) != identifier:
                    continue
                encoded = re.escape(image.encode())
                literal = rb'(?<![A-Za-z0-9_./:-])(?:docker\.io/)?(?:library/)?' + encoded + rb'(?=$|[^A-Za-z0-9_.:@/-]|:[ \t])'
                name, tag = image.rsplit(':', 1)
                repository = name if '/' in name else 'library/' + name
                endpoint = re.escape(('/v2/' + repository + '/manifests/' + tag).encode()) + rb'(?=[?"\s]|:[ \t]|$)'
                if re.search(literal, line) or re.search(endpoint, line):
                    identifiers.add(identifier)
    denied = denied or bool(statuses & {401, 403, 404})
    conflicting = any(value for key, value in flags.items()
                      if key not in {'BUILD_FAILED', 'IMAGE_FETCH_FAILED', 'REGISTRY_HTTP_REJECTED'})
    return {'httpStatuses': sorted(statuses), 'knownAccessOrImageDenial': denied,
            'transientOnlyObserved': bool(statuses) and statuses <= TRANSIENT_HTTP_STATUSES
                                     and not denied and not incomplete and not conflicting,
            'baseImageIds': sorted(identifiers), 'statusScanIncomplete': incomplete,
            'automaticRetry': False}


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
    truncated = size > 2 * DIAGNOSTIC_BYTES
    return {'signals': flags, 'unclassified': not any(flags.values()), 'scanTruncated': truncated,
            # A split can bisect a status or denial phrase even when no middle bytes were omitted.
            'registry': registry_observation(chunks, truncated or len(chunks) > 1, flags, project_base_images())}


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
