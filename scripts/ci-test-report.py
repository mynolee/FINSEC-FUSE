#!/usr/bin/env python3
"""Publish counts and bounded, source-validated test IDs; never raw failure content."""
import argparse
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

MAX_FILES = 512
MAX_XML_BYTES = 8 * 1024 * 1024
MAX_COUNT = 1_000_000
MAX_FAILURE_IDS = 32
SOURCE_ROOT = Path(__file__).resolve().parents[1] / 'backend/src/test/java'
IDENT = r'[A-Za-z_][A-Za-z_0-9]{0,159}'


@lru_cache(maxsize=1)
def inventory_module():
    """Share the inventory's exact source and report-name identity policy."""
    spec = importlib.util.spec_from_file_location('report_inventory', Path(__file__).with_name('ci-test-inventory.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_locations() -> dict:
    """Optional line bounds only; this parser cannot authorize an identity.

    Unsupported declarations have no line bounds. Strip
    comments and literals before matching declarations, preserving line numbers.
    """
    result = {}
    literal = re.compile(r'//[^\n]*|/\*.*?\*/|""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    for path in sorted(SOURCE_ROOT.rglob('*.java')):
        if path.is_symlink() or path.stat().st_size > MAX_XML_BYTES:
            continue
        source = path.read_text(encoding='utf-8')
        # Java Unicode escapes are processed before lexical analysis. Do not
        # approximate their semantics with this deliberately narrow parser.
        if re.search(r'\\u+[0-9a-fA-F]{4}', source):
            continue
        code = literal.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), source)
        package = re.search(r'^\s*package\s+(com\.finsec\.fuse(?:\.' + IDENT + r')*)\s*;', code)
        classes = re.findall(r'\b(?:class|interface|record|enum)\s+(' + IDENT + r')\b', code)
        if not package or not classes or classes[0] != path.stem:
            continue
        classname = package[1] + '.' + path.stem
        if path.relative_to(SOURCE_ROOT).as_posix() != classname.replace('.', '/') + '.java':
            continue
        methods = {}
        for match in re.finditer(r'@(Test|ParameterizedTest)(?:\s*\([^()]*\))?\s*'
                                 r'(?:@(?:ValueSource|MethodSource|CsvSource|EnumSource)\s*\([^()]*\)\s*)*'
                                 r'(?:public\s+)?void\s+(' + IDENT + r')\s*\(([^()]*)\)\s*'
                                 r'(?:throws\s+[\w.,\s]+)?\{', code):
            prefix = code[:match.start()]
            if prefix.count('{') - prefix.count('}') != 1:
                continue  # Nested class methods are not the outer class's tests.
            parameters = match[3].strip()
            signature = []
            if parameters:
                for parameter in parameters.split(','):
                    typed = re.fullmatch(r'\s*(' + IDENT + r')\s+' + IDENT + r'\s*', parameter)
                    if not typed:
                        break
                    signature.append(typed[1])
                else:
                    parameters = ''
                if parameters:
                    continue
            if match[1] == 'Test' and signature:
                continue
            depth, end = 1, match.end()
            while end < len(code) and depth:
                depth += (code[end] == '{') - (code[end] == '}')
                end += 1
            if not depth:
                methods[match[2]] = (code.count('\n', 0, match.start()) + 1,
                                     code.count('\n', 0, end) + 1,
                                     ', '.join(signature) if match[1] == 'ParameterizedTest' else None)
        result[classname] = methods
    return result


def source_manifest() -> dict:
    """Use only inventory-approved identities, with optional source line bounds."""
    try:
        identities = inventory_module().source_manifest(SOURCE_ROOT)
    except (OSError, UnicodeError, ValueError):
        return {}  # Missing source diagnostics never change aggregate counts.
    try:
        locations = source_locations()
    except (OSError, UnicodeError, ValueError):
        locations = {}  # Optional locations cannot remove a proven identity.
    return {classname: {method: (*locations.get(classname, {}).get(method, (None, None))[:2], signature)
                        for method, signature in methods.items()}
            for classname, methods in identities.items()}


def failure_id(case, manifest):
    """Return canonical source values only. XML display names are never emitted."""
    classname = case.get('classname', '')
    name = case.get('name', '')
    methods = manifest.get(classname)
    if not methods:
        return None
    canonical_class = next(key for key in manifest if key == classname)
    identities = {canonical_class: {method: signature for method, (_, _, signature) in methods.items()}}
    resolved = inventory_module().identity(classname, name, identities)
    if resolved is None:
        return None
    canonical_class, canonical_method, _ = resolved
    low, high, _ = methods[canonical_method]
    line = None
    frame = re.compile(r'\s*at ' + re.escape(canonical_class + '.' + canonical_method) +
                       r'\(' + re.escape(canonical_class.rsplit('.', 1)[1] + '.java') + r':([1-9][0-9]{0,5})\)\s*')
    for failure in list(case.findall('failure')) + list(case.findall('error')):
        for text in (failure.text or '').splitlines():
            match = frame.fullmatch(text)
            if match and low is not None and high is not None and low <= int(match[1]) <= high:
                line = int(match[1])
                break
        if line is not None:
            break
    return {'class': canonical_class, 'method': canonical_method, 'sourceLine': line}


def summarize(root: Path) -> dict:
    tasks = {}
    try:
        manifest = source_manifest()
    except (OSError, UnicodeError, ValueError):
        manifest = {}  # Count gate remains independent of source diagnostics.
    for task in ('test', 'integrationTest'):
        counts = dict(tests=0, failures=0, errors=0, skipped=0)
        ids, unknown, omitted = [], 0, 0
        invalid = False
        files = []
        try:
            # Bound iteration as well as parsing. Filenames never reach output.
            for path in (root / task).glob('TEST-*.xml'):
                files.append(path)
                if len(files) > MAX_FILES:
                    raise ValueError()
            for path in sorted(files):
                if path.is_symlink():
                    raise ValueError()
                with path.open('rb') as stream:
                    payload = stream.read(MAX_XML_BYTES + 1)
                if len(payload) > MAX_XML_BYTES:
                    raise ValueError()
                text = payload.decode('utf-8')
                if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
                    raise ValueError()
                suite = ET.fromstring(text)
                if suite.tag != 'testsuite':
                    raise ValueError()
                for key in counts:
                    raw = suite.get(key, '0')
                    if not re.fullmatch(r'[0-9]{1,7}', raw):
                        raise ValueError()
                    counts[key] += int(raw)
                    if counts[key] > MAX_COUNT:
                        raise ValueError()
                cases = suite.findall('testcase')
                if len(cases) > int(suite.get('tests', '0')):
                    raise ValueError()
                for tag, key in (('failure', 'failures'), ('error', 'errors'), ('skipped', 'skipped')):
                    if sum(case.find(tag) is not None for case in cases) > int(suite.get(key, '0')):
                        raise ValueError()
                for case in cases:
                    if case.find('failure') is None and case.find('error') is None:
                        continue
                    identifier = failure_id(case, manifest)
                    if identifier is None:
                        unknown += 1
                    elif len(ids) < MAX_FAILURE_IDS:
                        ids.append(identifier)
                    else:
                        omitted += 1
                    if unknown + omitted + len(ids) > MAX_COUNT:
                        raise ValueError()
        except (OSError, UnicodeError, ValueError, ET.ParseError):
            invalid = True
            counts = dict(tests=0, failures=0, errors=0, skipped=0)
            ids, unknown, omitted = [], 0, 0
        tasks[task] = {'status': 'INVALID_REPORT' if invalid else
                      'NOT_RUN' if not files or counts['tests'] == 0 else
                      'FAIL' if counts['failures'] or counts['errors'] else 'PASS', **counts,
                      'failureIds': ids, 'unknownFailureIds': unknown, 'omittedFailureIds': omitted}
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
