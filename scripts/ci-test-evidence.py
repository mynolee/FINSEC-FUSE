#!/usr/bin/env python3
"""Bind sanitized JUnit evidence to an explicit, clean checkout and CI identity.

Integrity binding is not a signature or proof that tests ran. Consumers must obtain
expected HEAD/run/attempt independently from their trusted CI context. Never use
an enclosing workspace repository as the public project checkout.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

SCHEMA = 'FUSE-TEST-EVIDENCE-1'
PAYLOADS = ('backend-test-inventory.json', 'backend-test-summary.json')
EVIDENCE = 'backend-test-evidence.json'
TASKS = {'test', 'integrationTest'}
STATES = {'passed', 'failed', 'error', 'skipped'}
LIMIT = 8 * 1024 * 1024
TOTAL = 128 * 1024 * 1024
MAX_FILES = 10000
SCOPE = 'Current checkout only; counts do not replace Compose/browser or LIVE verification.'


class Invalid(ValueError):
    pass


def require(condition):
    if not condition:
        raise Invalid()


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected))


def number(value, maximum=1000000):
    require(type(value) is int and 0 <= value <= maximum)
    return value


def safe_open(path, directory=False):
    path = Path(path).absolute()
    require('..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if directory or index < len(path.parts) - 2:
                flags |= os.O_DIRECTORY
            new = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = new
        mode = os.fstat(fd).st_mode
        require(stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode))
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path):
    with os.fdopen(safe_open(path), 'rb') as stream:
        require(os.fstat(stream.fileno()).st_size <= LIMIT)
        data = stream.read(LIMIT + 1)
    require(len(data) <= LIMIT)
    return data


def digest(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result)
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Invalid()))


def git(root, *args):
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0')
    # Caller-selected repository must not be overridden by inherited Git context.
    for key in list(env):
        if key.startswith('GIT_') and key not in {'GIT_NO_REPLACE_OBJECTS', 'GIT_CONFIG_NOSYSTEM', 'GIT_CONFIG_GLOBAL', 'GIT_OPTIONAL_LOCKS'}:
            del env[key]
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(['git', '-C', str(root), *args], stdout=output,
                                stderr=subprocess.DEVNULL, env=env, timeout=30, check=False)
        require(result.returncode == 0 and output.tell() <= LIMIT)
        output.seek(0)
        return output.read(LIMIT + 1)


def checkout(root, expected):
    os.close(safe_open(root, True))
    require(git(root, 'rev-parse', '--show-toplevel').decode().strip() == str(Path(root).absolute()))
    head = git(root, 'rev-parse', '--verify', 'HEAD').decode().strip()
    require(head == expected)
    tree = git(root, 'rev-parse', 'HEAD^{tree}').decode().strip()
    require(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', tree))
    # Compare working bytes directly to committed blobs, independent of index
    # assume-unchanged/skip-worktree bits and clean/smudge filters.
    listing = git(root, 'ls-tree', '-rz', '--full-tree', 'HEAD').split(b'\0')
    manifest, budget = [], 0
    require(len(listing) <= MAX_FILES + 1)
    for entry in listing:
        if not entry:
            continue
        meta, rawpath = entry.split(b'\t', 1)
        mode, kind, oid = meta.decode('ascii').split()
        require(mode in ('100644', '100755') and kind == 'blob')
        path = rawpath.decode('ascii')
        require(len(path) <= 512 and re.fullmatch(r'[A-Za-z0-9_.@+/-]+', path))
        require(all(part not in ('', '.', '..', '.git') for part in path.split('/')))
        data = read(Path(root) / path)
        budget += len(data)
        require(budget <= TOTAL and git(root, 'cat-file', '-s', oid).strip() == str(len(data)).encode())
        require(git(root, 'cat-file', 'blob', oid) == data)
        manifest.append({'path': path, **digest(data)})
    require(bool(manifest))
    return {'head': head, 'tree': tree, 'files': sorted(manifest, key=lambda item: item['path'])}


def count_map(value):
    keys(value, STATES)
    for item in value.values():
        number(item)
    require(sum(value.values()) <= 1000000)


def reports(summary, inventory, root, tracked):
    keys(summary, {'schemaVersion', 'tasks', 'scope'})
    keys(inventory, {'schemaVersion', 'tasks'})
    require(summary['schemaVersion'] == 'FUSE-TEST-COUNTS-1' and summary['scope'] == SCOPE)
    require(inventory['schemaVersion'] == 'FUSE-TEST-INVENTORY-1')
    keys(summary['tasks'], TASKS)
    keys(inventory['tasks'], TASKS)
    spec = importlib.util.spec_from_file_location('inventory_validator', Path(__file__).with_name('ci-test-inventory.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source_root = Path(root) / 'backend/src/test/java'
    # Inventory parsing must never acquire identities from untracked additions.
    pending, visited = [(source_root, 0)], 0
    try:
        while pending:
            directory, depth = pending.pop()
            require(depth <= 16)
            for name, is_directory in module.entries(directory):
                visited += 1
                require(visited <= MAX_FILES)
                path = directory / name
                if is_directory:
                    pending.append((path, depth + 1))
                else:
                    require(path.relative_to(root).as_posix() in tracked)
    except FileNotFoundError:
        require(not any(path.startswith('backend/src/test/java/') for path in tracked))
    line_spec = importlib.util.spec_from_file_location('count_validator', Path(__file__).with_name('ci-test-report.py'))
    line_module = importlib.util.module_from_spec(line_spec)
    line_spec.loader.exec_module(line_module)
    line_module.SOURCE_ROOT = source_root
    line_manifest = line_module.source_manifest()
    try:
        source = module.source_manifest(source_root)
        source_ok = True
    except (OSError, ValueError, UnicodeError):
        source, source_ok = {}, False
    complete = True
    for name in sorted(TASKS):
        s, i = summary['tasks'][name], inventory['tasks'][name]
        keys(s, {'status', 'tests', 'failures', 'errors', 'skipped', 'failureIds', 'unknownFailureIds', 'omittedFailureIds'})
        keys(i, {'status', 'complete', 'counts', 'mapped', 'unmapped', 'rows', 'diagnostics'})
        for key in ('tests', 'failures', 'errors', 'skipped', 'unknownFailureIds', 'omittedFailureIds'):
            number(s[key])
        require(s['status'] in ('PASS', 'FAIL', 'NOT_RUN', 'INVALID_REPORT'))
        require(type(s['failureIds']) is list and len(s['failureIds']) <= 32)
        for item in s['failureIds']:
            keys(item, {'class', 'method', 'sourceLine'})
            require(type(item['class']) is str and type(item['method']) is str)
            require(item['method'] in source.get(item['class'], {}))
            if item['sourceLine'] is not None:
                location = line_manifest.get(item['class'], {}).get(item['method'])
                require(location is not None and type(item['sourceLine']) is int and location[0] <= item['sourceLine'] <= location[1])
        require(len(s['failureIds']) + s['unknownFailureIds'] + s['omittedFailureIds'] == s['failures'] + s['errors'])
        for field in ('counts', 'mapped', 'unmapped'):
            count_map(i[field])
        require(all(i['counts'][k] == i['mapped'][k] + i['unmapped'][k] for k in STATES))
        require(type(i['rows']) is list and len(i['rows']) <= 10000)
        seen, totals = set(), dict.fromkeys(STATES, 0)
        order = []
        for row in i['rows']:
            keys(row, {'class', 'method', 'status', 'count'})
            require(all(type(row[k]) is str for k in ('class', 'method', 'status')))
            require(row['method'] in source.get(row['class'], {}) and row['status'] in STATES)
            require(number(row['count']) > 0)
            key = (row['class'], row['method'], row['status'])
            require(key not in seen)
            seen.add(key)
            order.append(key)
            totals[row['status']] += row['count']
        require(order == sorted(order) and totals == i['mapped'])
        available_failures = {}
        for row in i['rows']:
            if row['status'] in ('failed', 'error'):
                key = (row['class'], row['method'])
                available_failures[key] = available_failures.get(key, 0) + row['count']
        for item in s['failureIds']:
            key = (item['class'], item['method'])
            require(available_failures.get(key, 0) > 0)
            available_failures[key] -= 1
        require(type(i['complete']) is bool and i['status'] in ('VALID', 'NOT_RUN', 'INVALID_REPORT'))
        require(type(i['diagnostics']) is list and len(i['diagnostics']) <= 2)
        if i['status'] == 'VALID':
            require(sum(i['counts'].values()) > 0)
            expected_diagnostics = ([] if source_ok else ['SOURCE_UNAVAILABLE']) + (['UNMAPPED_IDENTITIES'] if sum(i['unmapped'].values()) else [])
            require(i['diagnostics'] == expected_diagnostics)
            require(i['complete'] == (source_ok and not sum(i['unmapped'].values())))
            require(s['status'] == ('FAIL' if i['counts']['failed'] + i['counts']['error'] else 'PASS'))
        else:
            require(not i['complete'] and not sum(i['counts'].values()) and not i['rows'])
            require(i['diagnostics'] in ([ 'REPORTS_MISSING'], ['CASES_MISSING']) if i['status'] == 'NOT_RUN' else i['diagnostics'] == ['REPORT_REJECTED'])
            require(s['status'] == i['status'])
        require((s['tests'], s['failures'], s['errors'], s['skipped']) ==
                (sum(i['counts'].values()), i['counts']['failed'], i['counts']['error'], i['counts']['skipped']))
        complete = complete and i['complete']
    return complete


def execute(command, root, artifacts, head, run_id, attempt):
    require(type(head) is str and re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', head))
    require(all(type(item) is str and re.fullmatch(r'[1-9][0-9]{0,19}', item) for item in (run_id, attempt)))
    root, artifacts = Path(root).absolute(), Path(artifacts).absolute()
    fd = safe_open(artifacts, True)
    try:
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                require(len(names) < 4 and entry.is_file(follow_symlinks=False) and not entry.is_symlink())
                names.append(entry.name)
    finally:
        os.close(fd)
    require(set(names) == set(PAYLOADS) | ({EVIDENCE} if command == 'verify' else set()))
    source = checkout(root, head)
    tracked = {item['path'] for item in source['files']}
    require(not any(artifacts == (root / path).parent or artifacts in (root / path).parents for path in tracked))
    payloads = {name: read(artifacts / name) for name in PAYLOADS}
    complete = reports(parse(payloads[PAYLOADS[1]]), parse(payloads[PAYLOADS[0]]), root, tracked)
    expected = {'schemaVersion': SCHEMA, 'revision': source, 'run': {'id': run_id, 'attempt': attempt},
                'artifacts': {name: digest(data) for name, data in payloads.items()}, 'complete': complete}
    if command == 'verify':
        actual = parse(read(artifacts / EVIDENCE))
        require(actual == expected)
        # Python equates booleans with integers; canonical JSON does not.
        require(json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True))
    else:
        output = (json.dumps(expected, sort_keys=True, indent=2) + '\n').encode()
        require(len(output) <= LIMIT)
        parent = safe_open(artifacts, True)
        try:
            descriptor = os.open(EVIDENCE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(output)
        finally:
            os.close(parent)
    return complete


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Invalid()


def main():
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('command', choices=('bind', 'verify'))
        parser.add_argument('--repository', required=True)
        parser.add_argument('--artifacts', required=True)
        parser.add_argument('--head', required=True)
        parser.add_argument('--run-id', required=True)
        parser.add_argument('--run-attempt', required=True)
        args = parser.parse_args()
        complete = execute(args.command, args.repository, args.artifacts, args.head, args.run_id, args.run_attempt)
        print('EVIDENCE_COMPLETE' if complete else 'EVIDENCE_INCOMPLETE')
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError, subprocess.SubprocessError):
        print('EVIDENCE_REJECTED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
