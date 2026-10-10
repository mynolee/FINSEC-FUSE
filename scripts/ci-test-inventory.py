#!/usr/bin/env python3
"""Bounded checkout-derived JUnit inventory; never publish report diagnostics.

This independent identity artifact does not replace the aggregate count verdict.
Only a narrow, unambiguous Java/Jupiter subset is recognized. Unsupported source
or display-name conventions remain unmapped, including all dynamic-test classes.
Ordinary project fixture inheritance is allowed only through fully validated
source ancestors without tests; inherited test methods remain unsupported.
Indistinguishable unknown nodes are counted, not deduplicated: XML cannot prove
whether two bare parameter display names are separate methods or duplicate runs.
complete means all observed testcase identities mapped; it is not source coverage.
File/byte/node limits apply per task; source discovery has its own bounded budget.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import xml.etree.ElementTree as ET

SCHEMA = 'FUSE-TEST-INVENTORY-1'
SOURCE_ROOT = Path(__file__).absolute().parents[1] / 'backend/src/test/java'
STATUSES = ('passed', 'failed', 'error', 'skipped')
MAX_FILES = 512
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 16
MAX_ENTRIES = 10_000
MAX_COUNT = 1_000_000
IDENT = r'[A-Za-z_][A-Za-z_0-9]{0,159}'


class Invalid(ValueError):
    """Intentionally contains no input data."""


def safe_open(path, directory=False):
    """Walk every component with O_NOFOLLOW, including all ancestor directories."""
    path = Path(path).absolute()
    if '..' in path.parts:
        raise Invalid()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(path.parts) - 2 or directory:
                flags |= os.O_DIRECTORY
            new = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = new
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise Invalid()
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_bytes(path, budget):
    fd = safe_open(path)
    with os.fdopen(fd, 'rb') as stream:
        if os.fstat(stream.fileno()).st_size > MAX_FILE_BYTES:
            raise Invalid()
        data = stream.read(MAX_FILE_BYTES + 1)
    budget[0] += len(data)
    if len(data) > MAX_FILE_BYTES or budget[0] > MAX_TOTAL_BYTES:
        raise Invalid()
    return data


def entries(path):
    fd = safe_open(path, True)
    try:
        with os.scandir(fd) as iterator:
            result = []
            for entry in iterator:
                if len(result) >= MAX_ENTRIES or entry.is_symlink():
                    raise Invalid()
                result.append((entry.name, entry.is_dir(follow_symlinks=False)))
        return sorted(result)
    finally:
        os.close(fd)


def scrub_java(source):
    # Unicode escapes alter Java tokenization before comments are recognized.
    if re.search(r'\\u', source):
        raise Invalid()
    token = re.compile(r'//[^\n]*|/\*.*?\*/|""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    code = token.sub(lambda m: ' ' * len(m[0]), source)
    if '"' in code or "'" in code or '/*' in code:
        raise Invalid()
    return code


def source_methods(code, stem, relative):
    package = re.match(r'\s*package\s+(com\.finsec\.fuse(?:\.' + IDENT + r')*)\s*;', code)
    if not package:
        return None
    classname = package[1] + '.' + stem
    if relative != classname.replace('.', '/') + '.java':
        return None
    # A factory/display generator can assign another method's apparent identity.
    if re.search(r'@(?:[\w.]+\.)?(?:TestFactory|TestTemplate|RepeatedTest|DisplayName|DisplayNameGeneration)\b', code):
        return classname, None
    if re.search(r'@(?:[\w.]+\.)?ParameterizedTest\s*\(', code):
        return classname, None  # A custom display template can impersonate another method.
    declaration = re.search(r'\bclass\s+' + re.escape(stem) + r'\b[^{};]*\{', code)
    if not declaration or '{' in code[:declaration.start()]:
        return classname, None
    # Only an ordinary, single superclass is supported. No generic, interface,
    # anonymous or qualified nested-type inheritance is inferred.
    header = re.fullmatch(r'class\s+' + re.escape(stem) +
                          r'\s*(?:extends\s+(' + IDENT + r'))?\s*\{', declaration[0])
    if not header:
        return classname, None
    parent = header[1]
    if parent and re.search(r'\b(?:class|interface|enum|record)\s+' +
                            re.escape(parent.rsplit('.', 1)[-1]) + r'\b', code):
        return classname, None
    if re.search(r'\b(?:class|interface|enum|record)\s+(?:Test|ParameterizedTest)\b', code):
        return classname, None
    declared_types = set(re.findall(r'\b(?:class|interface|enum|record)\s+(' + IDENT + r')\b', code))
    imports = set(re.findall(r'\bimport\s+(?!static\b)([\w.*]+)\s*;', code))
    # Unresolved/composed annotations may hide dynamic test factories. Only
    # known framework annotations are trusted as non-composed source metadata.
    trusted = {
        'org.junit.jupiter.api.' + name for name in
        ('Test', 'BeforeEach', 'AfterEach', 'BeforeAll', 'AfterAll', 'Timeout', 'Tag', 'Disabled')
    } | {'org.junit.jupiter.params.ParameterizedTest', 'org.junit.jupiter.api.io.TempDir'} | {
        'org.junit.jupiter.params.provider.' + name for name in
        ('ValueSource', 'CsvSource', 'EnumSource', 'MethodSource')
    } | {
        'org.springframework.context.annotation.' + name for name in ('Import', 'Bean', 'Primary', 'Profile')
    } | {
        'org.springframework.beans.factory.annotation.Autowired', 'org.springframework.beans.factory.annotation.Value',
        'org.springframework.boot.test.context.TestConfiguration', 'org.springframework.boot.test.context.SpringBootTest',
        'org.springframework.test.annotation.DirtiesContext', 'org.springframework.test.context.DynamicPropertySource',
        'org.springframework.test.context.ActiveProfiles',
    } | {
        'org.springframework.web.bind.annotation.' + name for name in
        ('RestController', 'GetMapping', 'PostMapping', 'PathVariable', 'RequestParam', 'RequestHeader')
    }
    implicit = {'Override', 'SuppressWarnings', 'Deprecated', 'SafeVarargs', 'FunctionalInterface'}
    for annotation in re.findall(r'@([\w.]+)', code):
        # Simple java.lang names can be shadowed by explicit/wildcard imports,
        # package types, or nested types inherited from another fixture. This
        # bounded parser does not implement Java's type-resolution precedence.
        # Even an explicit java.lang import cannot rule out a member shadow.
        if annotation in implicit or annotation in declared_types:
            return classname, None
        if '.' in annotation:
            # Even a qualified annotation may begin with a shadowing type,
            # including one outside this bounded source tree. Do not guess.
            return classname, None
        else:
            resolved = [item for item in imports if item.endswith('.' + annotation)]
            # Wildcard imports cannot establish absence of a same-package
            # custom annotation outside the bounded test-source tree.
            # Require an explicit trusted import.
        if len(resolved) != 1 or resolved[0] not in trusted:
            return classname, None
    def known(annotation):
        package_name = 'org.junit.jupiter.params' if annotation == 'ParameterizedTest' else 'org.junit.jupiter.api'
        conflicting = any(x.endswith('.' + annotation) and x != package_name + '.' + annotation for x in imports)
        return not conflicting and (package_name + '.' + annotation in imports or package_name + '.*' in imports)
    # Remove balanced annotation arguments before measuring class/method braces.
    flat = list(code)
    for match in re.finditer(r'@([\w.]+)\s*', code):
        pos = match.end()
        if pos < len(code) and code[pos] == '(':
            depth, end = 1, pos + 1
            while end < len(code) and depth:
                depth += (code[end] == '(') - (code[end] == ')')
                end += 1
            if depth:
                return classname, None
            flat[pos:end] = ' ' * (end - pos)
    flat = ''.join(flat)
    depth = 0
    depths = []
    for char in flat:
        depths.append(depth)
        depth += (char == '{') - (char == '}')
        if depth < 0:
            return classname, None
    if depth:
        return classname, None
    signatures = Counter()
    for match in re.finditer(r'\b(' + IDENT + r')\s*\([^()]*\)\s*(?:throws\s+[\w.,\s]+)?\{', flat):
        if depths[match.start()] == 1:
            signatures[match[1]] += 1
    result = {}
    pattern = (r'((?:@[\w.]+\s*)+)(?:public\s+|protected\s+)?void\s+(' + IDENT +
               r')\s*\(([^()]*)\)\s*(?:throws\s+[\w.,\s]+)?\{')
    permitted = {'Test', 'ParameterizedTest', 'ValueSource', 'CsvSource', 'EnumSource', 'MethodSource', 'Timeout', 'Tag', 'Disabled'}
    for match in re.finditer(pattern, flat):
        annotations = re.findall(r'@([\w.]+)', match[1])
        test = [a for a in annotations if a in ('Test', 'ParameterizedTest')]
        if depths[match.start()] != 1 or len(test) != 1 or not known(test[0]) or not set(annotations) <= permitted:
            continue
        name = match[2]
        if signatures[name] != 1:
            continue
        types = []
        valid = True
        if match[3].strip():
            for parameter in match[3].split(','):
                typed = re.fullmatch(r'\s*(' + IDENT + r')\s+' + IDENT + r'\s*', parameter)
                if not typed:
                    valid = False
                    break
                types.append(typed[1])
        if not valid or (test[0] == 'Test' and types):
            continue
        result[name] = None if test[0] == 'Test' else ', '.join(types)
    return classname, dict(methods=result, parent=parent, imports=imports,
                           has_member_types=bool(declared_types - {stem}),
                           has_tests=bool(re.search(r'@(?:[\w.]+\.)?(?:Test|ParameterizedTest)\b', code)))


def source_manifest(root):
    manifest, pending, budget, visited, count = {}, [(Path(root), 0)], [0], 0, 0
    while pending:
        directory, depth = pending.pop()
        if depth > MAX_DEPTH:
            raise Invalid()
        for name, is_directory in entries(directory):
            visited += 1
            if visited > MAX_ENTRIES:
                raise Invalid()
            path = directory / name
            if is_directory:
                pending.append((path, depth + 1))
            elif name.endswith('.java'):
                count += 1
                if count > MAX_FILES:
                    raise Invalid()
                source = read_bytes(path, budget).decode('utf-8')
                try:
                    parsed = source_methods(scrub_java(source), path.stem, path.relative_to(root).as_posix())
                except Invalid:
                    continue  # Unsupported lexical source never becomes an identity.
                if parsed:
                    if parsed[0] in manifest:
                        raise Invalid()
                    manifest[parsed[0]] = parsed[1]
    # Validate the whole chain, including fixtures with no recognized methods.
    # At most MAX_FILES * MAX_DEPTH nodes are visited; no recursion or graph
    # ordering can turn an over-depth or cyclic chain into a valid identity.
    def safe_ancestry(classname):
        seen = set()
        for _ in range(MAX_DEPTH):
            if classname in seen:
                return False
            seen.add(classname)
            info = manifest.get(classname)
            if info is None:
                return False
            parent = info['parent']
            if not parent:
                return True
            candidates = {item for item in info['imports'] if item.endswith('.' + parent)}
            local = classname.rsplit('.', 1)[0] + '.' + parent
            if local in manifest:
                candidates.add(local)
            # Wildcard imports are not searched: the bounded test-source
            # tree cannot establish absence of conflicting external types.
            if len(candidates) != 1:
                return False
            classname = next(iter(candidates))
            base = manifest.get(classname)
            # Inherited tests need Java override/visibility resolution and
            # remain unsupported. Ordinary non-test fixture chains suffice.
            if base is None or base['has_tests'] or base['has_member_types']:
                return False
        return False

    return {name: info['methods'] if safe_ancestry(name) else {}
            for name, info in manifest.items()}


def zero():
    return dict.fromkeys(STATUSES, 0)


def empty(status, diagnostic):
    return dict(status=status, complete=False, counts=zero(), mapped=zero(), unmapped=zero(), rows=[], diagnostics=[diagnostic])


def xml_report(data):
    text = data.decode('utf-8')
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)\b', text, re.I):
        raise Invalid()
    parser = ET.XMLPullParser(events=('start', 'end', 'comment', 'pi'))
    depth = nodes = 0
    root = None
    for offset in range(0, len(text), 4096):
        parser.feed(text[offset:offset + 4096])
        for event, element in parser.read_events():
            if event == 'start':
                root = element if root is None else root
                nodes += 1
                depth += 1
                if nodes > MAX_NODES or depth > MAX_DEPTH:
                    raise Invalid()
            elif event == 'end':
                depth -= 1
            else:
                raise Invalid()
    parser.close()
    if root is None or root.tag != 'testsuite':
        raise Invalid()
    attributes = {
        'testsuite': {'name', 'tests', 'failures', 'errors', 'skipped', 'time', 'timestamp', 'hostname', 'id', 'package'},
        'testcase': {'name', 'classname', 'time'},
        'failure': {'message', 'type'}, 'error': {'message', 'type'}, 'skipped': {'message', 'type'},
        'system-out': set(), 'system-err': set(), 'properties': set(), 'property': {'name', 'value'},
    }
    children = {'testsuite': {'testcase', 'properties', 'system-out', 'system-err'},
                'testcase': {'failure', 'error', 'skipped', 'system-out', 'system-err'}, 'properties': {'property'}}
    for element in root.iter():
        if element.tag not in attributes or not set(element.attrib) <= attributes[element.tag]:
            raise Invalid()
        if any(len(value) > 8192 for value in element.attrib.values()):
            raise Invalid()
        if element.tail and element.tail.strip():
            raise Invalid()
        if element.tag in children and element.text and element.text.strip():
            raise Invalid()
        if any(child.tag not in children.get(element.tag, set()) for child in element):
            raise Invalid()
        if element.tag == 'property' and set(element.attrib) != {'name', 'value'}:
            raise Invalid()
        if 'time' in element.attrib and not re.fullmatch(r'[0-9]{1,12}(?:\.[0-9]{1,12})?', element.attrib['time']):
            raise Invalid()
    if not root.get('name'):
        raise Invalid()
    declared = {}
    for key in ('tests', 'failures', 'errors', 'skipped'):
        value = root.get(key, '')
        if not re.fullmatch(r'0|[1-9][0-9]{0,6}', value) or int(value) > MAX_COUNT:
            raise Invalid()
        declared[key] = int(value)
    cases, counts = [], zero()
    for case in root.findall('testcase'):
        if not case.get('name') or not case.get('classname'):
            raise Invalid()
        markers = [child.tag for child in case if child.tag in ('failure', 'error', 'skipped')]
        if len(markers) > 1:
            raise Invalid()
        outcome = {'failure': 'failed', 'error': 'error', 'skipped': 'skipped'}.get(markers[0] if markers else '', 'passed')
        counts[outcome] += 1
        cases.append((case.get('classname'), case.get('name'), outcome))
    if (sum(counts.values()), counts['failed'], counts['error'], counts['skipped']) != tuple(declared[k] for k in ('tests', 'failures', 'errors', 'skipped')):
        raise Invalid()
    # Singleton containers are not a second channel for hidden/ambiguous evidence.
    for parent in root.iter():
        for tag in ('properties', 'system-out', 'system-err'):
            if len(parent.findall(tag)) > 1:
                raise Invalid()
    return root.get('name'), cases


def identity(classname, name, manifest):
    methods = manifest.get(classname, {})
    matches = []
    for method, signature in methods.items():
        if signature is None:
            if name in (method, method + '()'):
                matches.append((method, 'single'))
        else:
            match = re.fullmatch(re.escape(method + '(' + signature + ')') + r'\[([1-9][0-9]{0,5})\](?: [^\r\n]{0,1024})?', name)
            if match:
                matches.append((method, match[1]))
    if len(matches) != 1:
        return None
    # Emit only keys from the checkout, never strings sourced from the XML.
    canonical_class = next(key for key in manifest if key == classname)
    return canonical_class, matches[0][0], matches[0][1]


def summarize_task(root, task, manifest, source_ok):
    try:
        files = [Path(root) / task / name for name, directory in entries(Path(root) / task)
                 if not directory and name.startswith('TEST-') and name.endswith('.xml')]
        if not files:
            return empty('NOT_RUN', 'REPORTS_MISSING')
        if len(files) > MAX_FILES:
            raise Invalid()
        seen_reports, seen_suites, seen_ids = set(), set(), set()
        counts, mapped, unmapped, rows, budget = zero(), zero(), zero(), Counter(), [0]
        for path in files:
            payload = read_bytes(path, budget)
            digest = hashlib.sha256(payload).digest()
            suite, cases = xml_report(payload)
            if digest in seen_reports or suite in seen_suites:
                raise Invalid()
            seen_reports.add(digest)
            seen_suites.add(suite)
            for classname, name, outcome in cases:
                counts[outcome] += 1
                if sum(counts.values()) > MAX_COUNT:
                    raise Invalid()
                resolved = identity(classname, name, manifest)
                if resolved:
                    if resolved in seen_ids:
                        raise Invalid()
                    seen_ids.add(resolved)
                    canonical_class, method, _ = resolved
                    mapped[outcome] += 1
                    rows[(canonical_class, method, outcome)] += 1
                else:
                    unmapped[outcome] += 1
        if not sum(counts.values()):
            return empty('NOT_RUN', 'CASES_MISSING')
        diagnostics = ([] if source_ok else ['SOURCE_UNAVAILABLE']) + (['UNMAPPED_IDENTITIES'] if sum(unmapped.values()) else [])
        return dict(status='VALID', complete=source_ok and not sum(unmapped.values()), counts=counts,
                    mapped=mapped, unmapped=unmapped,
                    rows=[dict(zip(('class', 'method', 'status', 'count'), (*key, value))) for key, value in sorted(rows.items())],
                    diagnostics=diagnostics)
    except FileNotFoundError:
        return empty('NOT_RUN', 'REPORTS_MISSING')
    except (OSError, UnicodeError, ValueError, ET.ParseError):
        return empty('INVALID_REPORT', 'REPORT_REJECTED')


def summarize(root, source_root=SOURCE_ROOT):
    try:
        manifest, source_ok = source_manifest(Path(source_root)), True
    except (OSError, UnicodeError, ValueError):
        manifest, source_ok = {}, False
    return {'schemaVersion': SCHEMA, 'tasks': {task: summarize_task(root, task, manifest, source_ok)
            for task in ('test', 'integrationTest')}}


def main():
    class PrivateParser(argparse.ArgumentParser):
        def error(self, message):
            self.exit(2, 'INVENTORY_ARGUMENTS_REJECTED\n')
    parser = PrivateParser(description=__doc__)
    parser.add_argument('report_root', type=Path)
    parser.add_argument('--source-root', type=Path, default=SOURCE_ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = summarize(args.report_root, args.source_root)
    rendered = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.output:
        try:
            # Output parents are checked; an existing output symlink is forbidden.
            parent = safe_open(args.output.absolute().parent, True)
            try:
                fd = os.open(args.output.name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
                with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                        raise Invalid()
                    stream.write(rendered)
            finally:
                os.close(parent)
        except (OSError, ValueError):
            print('INVENTORY_OUTPUT_REJECTED')
            return 1
    else:
        print(rendered, end='')
    return int(any(task['status'] != 'VALID' for task in result['tasks'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
