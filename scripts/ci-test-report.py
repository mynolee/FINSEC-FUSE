#!/usr/bin/env python3
"""Publish counts and bounded, source-validated test IDs; never raw failure content."""
import argparse
import hashlib
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


# Advisory fixed-vocabulary diagnostics only; never evidence of a passing test.
API_DIAGNOSTIC_CLASS = 'com.finsec.fuse.integration.PublicApiCanonicalPathGuardIT'
API_DIAGNOSTIC_SOURCE_SHA256 = '8a580cb0b409f6f20630fc7c8c539867cdb67aa51eb5db396d70a91b29799828'
API_DIAGNOSTIC_METHODS = (
    'aliasAnonymousSaturationDoesNotBlockValidCanonicalCallerOnSameIp',
    'canonicalAndAliasHeaderChecksRemainAheadOfBodies',
    'canonicalOversizedBodiesEnforceLengthAndStreamingBoundsBeforeMvc',
    'unauthenticatedCanonicalAndAliasesRejectBeforeAnyBodyParsing',
    'validBearerAliasesRemainOutsideRawAllowlistForBothFramings',
)
# These exact frame locations describe the unchanged, hash-pinned test source.
# A line with several assertions deliberately has a combined stage, not a guessed cause.
API_DIAGNOSTIC_STAGES = {
    ('prepare', 227): 'PREPARE_BOOT_OR_SPRING_VERSION',
    ('prepare', 228): 'PREPARE_TOMCAT_VERSION',
    ('prepare', 229): 'PREPARE_BIND_ADDRESS',
    ('prepare', 230): 'PREPARE_WORKER_DISABLED',
    ('prepare', 231): 'PREPARE_TEST_PROFILE',
    ('prepare', 238): 'PREPARE_ROOT_CONTEXT',
    ('prepare', 239): 'PREPARE_SERVLET_MAPPING',
    ('prepare', 240): 'PREPARE_PORT_OR_BODY_MINIMUM',
    ('prepare', 241): 'PREPARE_BODY_MAXIMUM',
    ('prepare', 244): 'PREPARE_SEED_WORKFLOW',
    ('prepare', 246): 'PREPARE_DEVELOPER_TOKEN',
    ('prepare', 248): 'PREPARE_READER_TOKEN',
    ('prepare', 249): 'PREPARE_SNAPSHOT',
    ('prepare', 251): 'PREPARE_NONEMPTY_SEEDED_TABLES',
    ('request', 256): 'REQUEST_CLIENT_RAW_PATH',
    ('request', 267): 'REQUEST_HTTP_SEND',
    ('request', 268): 'REQUEST_PASSIVE_OBSERVER',
    ('request', 269): 'REQUEST_OBSERVER_COMPLETION',
    ('request', 270): 'REQUEST_SERVER_RAW_PATH',
    ('request', 271): 'REQUEST_CONTEXT_OR_MAPPING',
    ('request', 272): 'REQUEST_REMOTE_ADDRESS',
    ('request', 273): 'REQUEST_ALIAS_SERVLET_PATH',
    ('request', 275): 'REQUEST_CONTENT_LENGTH',
    ('request', 276): 'REQUEST_CHUNKED_FRAMING',
    ('request', 277): 'REQUEST_FIXED_FRAMING',
    ('rejected', 282): 'REJECTION_STATUS',
    ('rejected', 283): 'REJECTION_CACHE_HEADER',
    ('rejected', 284): 'REJECTION_CONTENT_TYPE_HEADER',
    ('rejected', 285): 'REJECTION_APPLICATION_BYTES',
    ('rejected', 286): 'REJECTION_HANDLER_ENTRY',
    ('rejected', 287): 'REJECTION_CONVERSION',
    ('unchanged', 307): 'UNCHANGED_DATABASE_SNAPSHOT',
    ('unchanged', 308): 'UNCHANGED_GATEWAY_CALLS',
    ('prepare', 232): 'PREPARE_EXPERIMENT_ENABLED',
    ('prepare', 233): 'PREPARE_EXPERIMENT_CONTROLLER',
    ('prepare', 235): 'PREPARE_EXPERIMENT_POST_MAPPING',
    ('prepare', 237): 'PREPARE_EXPERIMENT_POST_MAPPING',
}


API_DIAGNOSTIC_DIRECT_METHOD = 'canonicalAndAliasHeaderChecksRemainAheadOfBodies'
API_DIAGNOSTIC_DIRECT_STAGES = {
    357: 'POSITIVE_CONTROL_STATUS',
    358: 'POSITIVE_CONTROL_HANDLER',
    359: 'POSITIVE_CONTROL_CONVERSION',
    360: 'POSITIVE_CONTROL_BODY_BYTES',
}


def api_guard_diagnostic(case, manifest):
    """Project only fixed source-owned IDs; untrusted text is never returned."""
    if case.get('classname') != API_DIAGNOSTIC_CLASS:
        return None
    identity = failure_id(case, manifest)
    if identity is None or identity['method'] not in API_DIAGNOSTIC_METHODS:
        return None
    source = SOURCE_ROOT / (API_DIAGNOSTIC_CLASS.replace('.', '/') + '.java')
    try:
        if any(p.is_symlink() for p in (source, *source.parents)):
            return None
        with source.open('rb') as stream:
            payload = stream.read(MAX_XML_BYTES + 1)
        if len(payload) > MAX_XML_BYTES or hashlib.sha256(payload).hexdigest() != API_DIAGNOSTIC_SOURCE_SHA256:
            return None
    except OSError:
        return None
    frame = re.compile(r'\s*at (?:app//)?' + re.escape(API_DIAGNOSTIC_CLASS) +
                       r'\.(prepare|request|rejected|unchanged)\(PublicApiCanonicalPathGuardIT\.java:([1-9][0-9]{0,5})\)\s*')
    matches = []
    for failure in list(case.findall('failure')) + list(case.findall('error')):
        for line in (failure.text or '').splitlines():
            match = frame.fullmatch(line)
            if match:
                stage = API_DIAGNOSTIC_STAGES.get((match[1], int(match[2])))
                matches.append(stage)
    # A helper frame, even unmapped/ambiguous, takes precedence over its test callsite.
    direct = False
    if not matches and identity['method'] == API_DIAGNOSTIC_DIRECT_METHOD:
        direct = True
        direct_frame = re.compile(r'\s*at (?:app//)?' + re.escape(API_DIAGNOSTIC_CLASS + '.' +
                                  API_DIAGNOSTIC_DIRECT_METHOD) +
                                  r'\(PublicApiCanonicalPathGuardIT\.java:([1-9][0-9]{0,5})\)\s*')
        for failure in list(case.findall('failure')) + list(case.findall('error')):
            for line in (failure.text or '').splitlines():
                match = direct_frame.fullmatch(line)
                if match:
                    matches.append(API_DIAGNOSTIC_DIRECT_STAGES.get(int(match[1])))
    # Multiple recognized frames, including duplicates, are ambiguous.
    reason = ('NO_TARGET_FRAME' if not matches else 'MULTIPLE_TARGET_FRAMES' if len(matches) != 1
              else 'UNMAPPED_LINE' if matches[0] is None else
              'MATCHED_DIRECT_FRAME' if direct else 'MATCHED_FRAME')
    return {'method': identity['method'],
            'stage': matches[0] if reason in {'MATCHED_FRAME', 'MATCHED_DIRECT_FRAME'} else 'UNKNOWN',
            'reason': reason}


# Advisory only: reviewed source hashes authorize this small fixed vocabulary.
# Do not relax the generic inventory parser or replace its unknown-failure counts.
MIGRATION_DIAGNOSTIC_SOURCES = {
    'com.finsec.fuse.migration.DatabaseMigratorIT': (
        '4ea606eed524a1871d6d13a1b415f03019c554cf9d36cff473debf91123e6642', (
            'fixedSnapshotQueriesCoverExactlyTheReviewedTablesAndExplicitFixture',
            'freshMigrationLeavesOnlyStructuralRowsAndReadOnlyHistoryPrivileges',
            'nonemptyHistoryFunctionTypeCollationOperatorAndExtraSchemaAreNotFresh',
            'invalidBootstrapRuntimeAuthorityIsRejectedBeforeAnyMigration',
            'everyValidatorConnectionIsServerReadOnlyIncludingAutocommitAndCannotUnwrap',
            'historyMutationMissingObjectsWrongSchemaAndNoInheritOwnerMembershipFailClosed',
        )),
    'com.finsec.fuse.migration.ShippedEntrypointsIT': (
        '4ca52aece4f9350b1df70b1ec6be2a0dedc39061aa4f5eb230f9b9e0a2a51a51', (
            'manifestsSelectSeparateMainsAndZeroArgumentAdminsFailWithoutServices',
            'shippedMigrationCompletesWithoutApplicationStartupAndConcurrentFreshAttemptRefuses',
            'shippedWebMainRejectsAbsentSchemaAndOverrideBeforeSeedRecoveryOrHttp',
            'failedMigrationAndKilledProcessNeverReportCompletionOrIssueAuthority',
            'lossOfCooperativeLockIsNotSuccessEvenWhenMigrationCommits',
        )),
    'com.finsec.fuse.migration.MigrationContractTest': (
        '6242643a2a088ca2422989b5ca3a15c0c583b694a6881d596ce04a0d233551ef', (
            'canonicalEffectiveRuntimeConfigurationIsPrivateAndHasNoFallback',
            'migrationsSqlInitializersAndAlternateTargetsCannotBypassTheMainGate',
            'finalPropertyPrecedenceIsValidatedAndProfilesNeverDisableTheGate',
            'urlPropertiesCredentialsAndAmbiguousTargetsAreRejected',
            'unsupportedOperationsFailBeforeAnyConnectionOrCredentialUse',
            'theResourceBoundaryContainsOnlyTheReviewedSevenSqlMigrations',
            'pinnedFlywayOptionsUseExplicitEmptyArraysWithoutOpeningAConnection',
            'fixedEmptyDataQueryCoversEveryReviewedNonstructuralTableExactlyOnce',
        )),
    'com.finsec.fuse.integration.RuntimeDatabaseRoleIT': (
        'a3af21ae583b4d09774767e5bd17cc4a3304113e80ca243cd2f5fc3b3502fd69', (
            'runtimeCanReadButCannotMutateMigrationHistory',
        )),
}


def migration_diagnostic(case):
    """Return source-owned IDs/line numbers only; never echo report text or paths."""
    classname = case.get('classname', '')
    expected = MIGRATION_DIAGNOSTIC_SOURCES.get(classname)
    if expected is None or case.find('skipped') is not None:
        return None
    matches = [method for method in expected[1] if case.get('name') == method + '()']
    failures, errors = case.findall('failure'), case.findall('error')
    if len(matches) != 1 or len(failures) + len(errors) != 1:
        return None
    canonical_class = next(key for key in MIGRATION_DIAGNOSTIC_SOURCES if key == classname)
    method = matches[0]
    source = SOURCE_ROOT / (canonical_class.replace('.', '/') + '.java')
    try:
        raw = inventory_module().read_bytes(source, [0])
        if hashlib.sha256(raw).hexdigest() != expected[0]:
            return None
        bounds = source_locations().get(canonical_class, {}).get(method)
    except (OSError, UnicodeError, ValueError):
        return None
    line = None
    if bounds is not None:
        frame = re.compile(r'\s*at (?:app//)?' + re.escape(canonical_class + '.' + method) +
                           r'\(' + re.escape(source.name) + r':([1-9][0-9]{0,5})\)\s*')
        for text in ((failures + errors)[0].text or '').splitlines():
            match = frame.fullmatch(text)
            if match and bounds[0] <= int(match[1]) <= bounds[1]:
                line = int(match[1]); break
    return {'class': canonical_class, 'method': method, 'status': 'failed' if failures else 'error',
            'count': 1, 'sourceLine': line, 'sourceSha256': expected[0]}


def summarize(root: Path, api_diagnostics=None, migration_diagnostics=None) -> dict:
    tasks = {}
    migration_all_rows, migration_seen = [], {}
    try:
        manifest = source_manifest()
    except (OSError, UnicodeError, ValueError):
        manifest = {}  # Count gate remains independent of source diagnostics.
    for task in ('test', 'integrationTest'):
        counts = dict(tests=0, failures=0, errors=0, skipped=0)
        ids, unknown, omitted = [], 0, 0
        diagnostic_rows = []
        migration_rows = []
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
                    if migration_diagnostics is not None:
                        expected = MIGRATION_DIAGNOSTIC_SOURCES.get(case.get('classname', ''))
                        if expected is not None:
                            for method in expected[1]:
                                if case.get('name') == method + '()':
                                    identity = (case.get('classname'), method)
                                    migration_seen[identity] = migration_seen.get(identity, 0) + 1
                        diagnostic = migration_diagnostic(case)
                        if diagnostic is not None and len(migration_rows) < MAX_FAILURE_IDS:
                            migration_rows.append(diagnostic)
                    if case.find('failure') is None and case.find('error') is None:
                        continue
                    if task == 'integrationTest' and api_diagnostics is not None and len(diagnostic_rows) < MAX_FAILURE_IDS:
                        diagnostic = api_guard_diagnostic(case, manifest)
                        if diagnostic is not None:
                            diagnostic_rows.append(diagnostic)
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
        if not invalid and api_diagnostics is not None:
            api_diagnostics.extend(diagnostic_rows)
        if not invalid and migration_diagnostics is not None:
            migration_all_rows.extend(migration_rows)
        tasks[task] = {'status': 'INVALID_REPORT' if invalid else
                      'NOT_RUN' if not files or counts['tests'] == 0 else
                      'FAIL' if counts['failures'] or counts['errors'] else 'PASS', **counts,
                      'failureIds': ids, 'unknownFailureIds': unknown, 'omittedFailureIds': omitted}
    if migration_diagnostics is not None:
        migration_diagnostics.extend([row for row in migration_all_rows
            if migration_seen[(row['class'], row['method'])] == 1][:MAX_FAILURE_IDS])
    return {'schemaVersion': 'FUSE-TEST-COUNTS-1', 'tasks': tasks,
            'scope': 'Current checkout only; counts do not replace Compose/browser or LIVE verification.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=Path('backend/build/test-results'))
    parser.add_argument('--output', type=Path, default=Path('safe-artifacts/backend-test-summary.json'))
    args = parser.parse_args()
    diagnostics = []
    migration_diagnostics = []
    summary = summarize(args.input, diagnostics, migration_diagnostics)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))
    if diagnostics:
        print(json.dumps({'schemaVersion': 'FUSE-API-PATH-GUARD-DIAGNOSTICS-1',
                          'sourceSha256': API_DIAGNOSTIC_SOURCE_SHA256,
                          'class': API_DIAGNOSTIC_CLASS, 'failures': diagnostics,
                          'scope': 'Advisory failed-test stack stage only; no assertion cause or PASS claim.'}))
    if migration_diagnostics:
        print(json.dumps({'schemaVersion': 'FUSE-MIGRATION-TEST-DIAGNOSTICS-1',
                          'failures': migration_diagnostics,
                          'scope': 'Advisory source-hash-bound failed-test IDs only; original counts and unknown IDs are unchanged.'}))
    return int(any(part['status'] != 'PASS' or part['skipped'] for part in summary['tasks'].values()))


if __name__ == '__main__':
    raise SystemExit(main())
