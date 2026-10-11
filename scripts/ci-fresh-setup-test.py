#!/usr/bin/env python3
"""Offline scope/report regression tests. These do not execute Docker, Java or PostgreSQL."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fresh_setup', Path(__file__).with_name('ci-fresh-setup.py'))
fresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fresh)
SECURITY_SPEC = importlib.util.spec_from_file_location('fresh_security_projection', Path(__file__).with_name('security-scan.py'))
security = importlib.util.module_from_spec(SECURITY_SPEC)
SECURITY_SPEC.loader.exec_module(security)


class ScopeTests(unittest.TestCase):
    def environment(self):
        return dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', GITHUB_WORKSPACE=str(fresh.ROOT),
                    GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='1' * 40,
                    COMPOSE_PROJECT_NAME='fuse-fresh-123-1', COMPOSE_FILE='compose.yaml:compose.admin.yaml')

    def test_exact_disposable_scope_is_required(self):
        self.assertEqual('fuse-fresh-123-1', fresh.scope(self.environment(), uid=1001, gid=1001))
        for field, value in (('GITHUB_ACTIONS', 'false'), ('RUNNER_ENVIRONMENT', 'self-hosted'),
                             ('GITHUB_WORKSPACE', '/another/project'), ('GITHUB_SHA', 'branch'),
                             ('COMPOSE_PROJECT_NAME', 'finsec-fuse'), ('COMPOSE_FILE', 'compose.live.yaml'),
                             ('DOCKER_HOST', 'tcp://other'), ('DOCKER_CONTEXT', 'remote'),
                             ('DOCKER_CONFIG', '/other'), ('COMPOSE_PROFILES', 'admin'),
                             ('FUSE_DB_URL', 'jdbc:postgresql://other:5432/fuse'), ('SPRING_PROFILES_ACTIVE', 'test'),
                             ('JAVA_TOOL_OPTIONS', '-Dsomething=true')):
            with self.subTest(field=field), self.assertRaises(fresh.Failure):
                fresh.scope({**self.environment(), field: value}, uid=1001, gid=1001)
        for uid, gid in ((0, 1001), (1001, 0), (10001, 10001)):
            with self.assertRaises(fresh.Failure):
                fresh.scope(self.environment(), uid=uid, gid=gid)

    def test_command_errors_never_include_child_diagnostics(self):
        class Child:
            returncode = 1
        def process(*args, **kwargs):
            kwargs['stdout'].write(b'PRIVATE_URL_CANARY')
            kwargs['stderr'].write(b'PRIVATE_PASSWORD_CANARY')
            return Child()
        with patch.object(fresh.subprocess, 'run', side_effect=process):
            with self.assertRaises(fresh.Failure) as failure:
                fresh.run(['synthetic-command'])
        self.assertEqual('COMMAND_FAILED', str(failure.exception))

    def test_prepared_and_committed_new_tokens_are_rescanned_privately(self):
        token = 'A' * 43
        for status in ('PREPARED', 'COMMITTED'):
            raw = ('# status=' + status + '\nFUSE_CUSTOMER_101_TOKEN=' + token + '\n').encode()
            self.assertEqual([token], fresh.prepared_canaries(raw))
            with self.assertRaises(fresh.Failure):
                fresh.no_canaries(('leaked ' + token).encode(), fresh.prepared_canaries(raw))

    def test_canary_scanner_refuses_either_stream(self):
        with self.assertRaises(fresh.Failure):
            fresh.no_canaries(b'prefix PRIVATE_CANARY suffix', ['PRIVATE_CANARY'])
        fresh.no_canaries(b'fixed sanitized receipt', ['PRIVATE_CANARY'])


class PublicReceiptTests(unittest.TestCase):
    def report(self):
        return dict(schemaVersion='FUSE-SHIPPED-FRESH-SETUP-1', status='PASS', head='1' * 40,
                    checks=dict.fromkeys(fresh.CHECKS, 'PASS'),
                    imageIds={key: 'sha256:' + '2' * 64 for key in ('backend', 'migration', 'token-admin')},
                    sourceHashBefore='3' * 64, sourceHashAfter='3' * 64,
                    ownsProject=True, cleanupVerified=True, failure=None)

    def test_complete_exact_receipt_is_accepted(self):
        report = self.report()
        self.assertEqual(report, json.loads(fresh.public_report(report)))

    def test_extra_fields_raw_diagnostics_missing_checks_and_unconfirmed_cleanup_refuse(self):
        bad = []
        report = self.report(); report['rawLog'] = 'PRIVATE_CANARY'; bad.append(report)
        report = self.report(); report['imageIds']['backend'] = 'PRIVATE_CANARY'; bad.append(report)
        report = self.report(); report['failure'] = 'PRIVATE_CANARY'; bad.append(report)
        report = self.report(); report['checks'].pop('fresh_migration'); bad.append(report)
        report = self.report(); report['checks']['fresh_migration'] = 'NOT_RUN'; bad.append(report)
        report = self.report(); report['cleanupVerified'] = False; bad.append(report)
        report = self.report(); report['sourceHashAfter'] = '4' * 64; bad.append(report)
        for report in bad:
            with self.assertRaises(fresh.Failure):
                fresh.public_report(report)

    def test_failure_receipt_cannot_claim_unobserved_checks(self):
        report = self.report(); report.update(status='FAIL', failure='COMMAND_FAILED', cleanupVerified=False)
        report['checks'] = dict.fromkeys(fresh.CHECKS, 'NOT_RUN')
        self.assertEqual('FAIL', json.loads(fresh.public_report(report))['status'])


class SourceWiringTests(unittest.TestCase):
    def test_shipped_paths_and_bounded_cleanup_are_not_test_classpath_bootstrap(self):
        source = Path(fresh.__file__).read_text()
        self.assertNotIn('ComposeCiAuthBootstrap', source)
        self.assertNotIn('writeTestClasspath', source)
        self.assertNotIn('.provision(', source)
        self.assertIn("['migrate-fresh', '--new-install']", source)
        self.assertIn("['init-fresh', '--new-install', '--output', '/private-output/issued.env']", source)
        self.assertIn("ci-fresh-attempt.json", source)
        self.assertIn("observed == marker(project)", source)
        self.assertIn("['stop', *RUNTIME_SERVICES]", source)
        self.assertIn("['start', *RUNTIME_SERVICES]", source)
        self.assertIn("authority_snapshot(project) == authority", source)
        self.assertIn("log_out + log_err", source)
        self.assertIn("no_canaries(issued_diagnostics, list(tokens.values()))", source)

    def test_custom_archives_use_the_java_toolchain_target_and_shipped_headers_are_checked(self):
        build = (fresh.ROOT / 'build.gradle').read_text()
        for task, following in [('databaseMigrationJar', 'def tokenAdminJar'), ('tokenAdminJar', 'integrationTest.configure')]:
            block = build.split('def ' + task + ' = tasks.register(', 1)[1].split(following, 1)[0]
            self.assertEqual(1, block.count('targetJavaVersion = provider { java.targetCompatibility }'))
        main = build.split("tasks.named('bootJar') {", 1)[1].split('}', 1)[0]
        self.assertEqual("mainClass = 'com.finsec.fuse.FuseApplication'", main.strip())
        source = (fresh.ROOT / 'backend/src/test/java/com/finsec/fuse/migration/ShippedEntrypointsIT.java').read_text()
        self.assertIn('assertEquals("21", jar.getManifest().getMainAttributes().getValue("Build-Jdk-Spec"))', source)

    def test_ci_job_only_uploads_validated_aggregate(self):
        workflow = (fresh.ROOT / '.github/workflows/ci.yml').read_text()
        job = workflow.split('  shipped-fresh-setup:\n', 1)[1].split('\n  combined-compose-browser:', 1)[0]
        self.assertIn("if: needs.prerequisites.outputs.combined == 'true'", job)
        self.assertIn('python -I -B scripts/ci-fresh-setup.py execute', job)
        self.assertIn('python -I -B scripts/ci-fresh-setup.py cleanup', job)
        self.assertIn('path: safe-artifacts/fresh-setup-summary.json', job)
        self.assertNotIn('continue-on-error:', job)
        self.assertNotIn('path: safe-artifacts/\n', job)
        self.assertNotIn('.secrets', job)


class RestartIdentityTests(unittest.TestCase):
    project = 'fuse-fresh-123-1'

    def fixture(self):
        ids = {service: format(index + 1, '064x') for index, service in enumerate(fresh.RUNTIME_SERVICES)}
        name = self.project + '_pgdata'
        mount = dict(Type='volume', Name=name, Source='/synthetic/' + name,
                     Destination='/var/lib/postgresql/data', RW=True)
        rows = {service: dict(Id=ids[service], Config={'Labels': {
                    'com.docker.compose.project': self.project, 'com.docker.compose.service': service}},
                    State=dict(Running=True, Health={'Status': 'healthy'}), Mounts=[mount] if service == 'postgres' else [])
                for service in ids}
        volume = dict(Name=name, CreatedAt='2026-10-11T00:00:00Z', Driver='local', Scope='local',
                      Mountpoint=mount['Source'], Labels={'com.docker.compose.project': self.project,
                                                       'com.docker.compose.volume': 'pgdata'})
        return ids, rows, volume

    def snapshot(self, ids, rows, volume, *, running=True):
        def inspect(*args, **kwargs):
            if args[:2] == ('volume', 'inspect'):
                return json.dumps([volume]).encode()
            self.assertEqual(args[0], 'inspect')
            return json.dumps([next(row for row in rows.values() if row['Id'] == args[1])]).encode()
        with patch.object(fresh, 'quiet', side_effect=lambda args: (ids[args[-1]] + '\n').encode()), \
                patch.object(fresh, 'docker', side_effect=inspect):
            return fresh.runtime_identity(self.project, running=running)

    def test_exact_ids_and_volume_creation_mount_binding_are_preserved(self):
        ids, rows, volume = self.fixture()
        active = self.snapshot(ids, rows, volume)
        for row in rows.values(): row['State']['Running'] = False
        self.assertEqual(active, self.snapshot(ids, rows, volume, running=False))
        self.assertEqual(active['containers'], ids)
        self.assertEqual(active['volume']['CreatedAt'], volume['CreatedAt'])
        self.assertEqual(active['mount']['Source'], volume['Mountpoint'])

    def test_malformed_duplicate_labels_health_and_volume_changes_refuse_without_private_text(self):
        mutations = [lambda ids, rows, volume: ids.update(postgres=''),
                     lambda ids, rows, volume: ids.update(postgres=ids['postgres'] + '\n' + ids['postgres']),
                     lambda ids, rows, volume: rows['backend']['Config']['Labels'].update({'com.docker.compose.project': 'PRIVATE_CANARY'}),
                     lambda ids, rows, volume: rows['agent']['Config']['Labels'].update({'com.docker.compose.service': 'postgres'}),
                     lambda ids, rows, volume: rows['backend']['State'].update(Running=False),
                     lambda ids, rows, volume: rows['agent']['State']['Health'].update(Status='unhealthy'),
                     lambda ids, rows, volume: volume.update(Name='PRIVATE_CANARY'),
                     lambda ids, rows, volume: volume.update(Mountpoint='/PRIVATE_CANARY'),
                     lambda ids, rows, volume: rows['postgres']['Mounts'].append(dict(rows['postgres']['Mounts'][0]))]
        for mutate in mutations:
            ids, rows, volume = self.fixture(); mutate(ids, rows, volume)
            with self.assertRaises(fresh.Failure) as failure:
                self.snapshot(ids, rows, volume)
            self.assertEqual('CONFIG_REJECTED', str(failure.exception))

    def test_pinned_compose_2382_commands_use_existing_services_and_bounded_readiness(self):
        identity = {'synthetic': 'identity'}; calls = []
        with patch.object(fresh, 'runtime_identity', return_value=identity) as snapshots, \
                patch.object(fresh, 'quiet', side_effect=lambda args, **kwargs: calls.append((args, kwargs))), \
                patch.object(fresh, 'readiness') as ready:
            fresh.restart_existing(self.project, 'checks')
        prefix = fresh.compose(self.project)
        self.assertEqual(calls, [(prefix + ['stop', *fresh.RUNTIME_SERVICES], {'timeout': 90}),
                                (prefix + ['start', *fresh.RUNTIME_SERVICES], {'timeout': 90})])
        self.assertEqual([call.kwargs for call in snapshots.call_args_list],
                         [{'running': True}, {'running': False}, {'running': True}])
        ready.assert_called_once_with('checks')
        for name in ('README.md', 'docs/runtime-security.md'):
            source = (fresh.ROOT / name).read_text()
            self.assertIn('docker compose start postgres agent backend frontend ingress', source)
            self.assertNotIn('docker compose start --wait', source)

    def test_replaced_container_or_named_volume_identity_fails_restart(self):
        ids, rows, volume = self.fixture(); original = self.snapshot(ids, rows, volume)
        for changed in ('containers', 'volume', 'mount'):
            altered = copy.deepcopy(original)
            key = next(iter(altered[changed])); altered[changed][key] = 'PRIVATE_CANARY'
            with patch.object(fresh, 'runtime_identity', side_effect=[original, original, altered]), \
                    patch.object(fresh, 'quiet'), patch.object(fresh, 'readiness'), self.assertRaises(fresh.Failure):
                fresh.restart_existing(self.project, 'checks')

    def test_readiness_failure_cannot_report_success_or_change_identity(self):
        with patch.object(fresh, 'runtime_identity', return_value={'same': True}) as snapshots, \
                patch.object(fresh, 'quiet'), patch.object(fresh, 'readiness', side_effect=fresh.Failure('ASSERTION_FAILED')), \
                self.assertRaises(fresh.Failure):
            fresh.restart_existing(self.project, 'checks')
        self.assertEqual(2, snapshots.call_count)


class DiagnosticProjectionTests(unittest.TestCase):
    def security_report(self):
        return dict(schemaVersion=1, observedAt='2026-10-11T00:00:00+00:00', scope=list(security.SCOPE),
            excluded=['private inputs', 'private prompts', 'environment files', 'caches', 'generated outputs'],
            exceptions=[], exceptionExpiry=None,
            tools={**{name: dict(expected=version, observed=version, versionMatched=True)
                      for name, version in {**security.TOOLS, 'npm': '11.9.0'}.items()},
                   'maven-sca': {'observed': 'OSV API v1; local coordinate adapter 1'}},
            checks={name: security.verdict(1, 0, 0, 0) for name in security.DIAGNOSTIC_CHECKS},
            limitations=['Targeted local SAST rules are not comprehensive.',
                        'Scanners do not replace API, database, browser or independent security review.'],
            commit='1' * 40, treeBinding='candidateSha256 and manifestSha256 bind the actual working tree; commit alone does not',
            candidateFiles=1, candidateSha256='2' * 64,
            manifestSha256={name: '3' * 64 for name in security.MANIFESTS}, status='PASS')

    def assert_invalid_output(self, module, report, schema):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertFalse(module.print_diagnostic(report))
        self.assertEqual({'schemaVersion': schema, 'status': 'INVALID'}, json.loads(output.getvalue()))
        self.assertEqual('', error.getvalue())
        self.assertNotIn('PRIVATE_CANARY', output.getvalue())

    def test_fresh_log_projection_is_closed_and_excludes_all_source_and_image_identifiers(self):
        report = PublicReceiptTests().report()
        result = json.loads(fresh.diagnostic_report(report))
        self.assertEqual({'schemaVersion', 'status', 'failure', 'checks', 'planned', 'passed', 'notRun', 'cleanup'}, set(result))
        self.assertEqual(len(fresh.CHECKS), result['planned'])
        self.assertEqual(len(fresh.CHECKS), result['passed'])
        self.assertEqual(0, result['notRun'])
        for marker in [report['head'], report['sourceHashBefore'], *report['imageIds'].values()]:
            self.assertNotIn(marker, json.dumps(result))
        report.update(status='FAIL', failure='COMMAND_FAILED', cleanupVerified=False)
        report['checks']['fresh_migration'] = 'NOT_RUN'
        result = json.loads(fresh.diagnostic_report(report))
        self.assertEqual(('COMMAND_FAILED', 1, 'NOT_CONFIRMED'), (result['failure'], result['notRun'], result['cleanup']))

    def test_fresh_invalid_missing_extra_nested_and_unknown_values_only_print_invalid(self):
        mutations = [lambda r: r.update(rawLog='PRIVATE_CANARY'), lambda r: r.pop('head'),
            lambda r: r.update(status='PRIVATE_CANARY'), lambda r: r.update(failure='PRIVATE_CANARY'),
            lambda r: r.update(checks=['PRIVATE_CANARY']), lambda r: r['checks'].pop('images'),
            lambda r: r['checks'].update(unexpected='PRIVATE_CANARY'),
            lambda r: r['checks'].update(images='PRIVATE_CANARY'),
            lambda r: r.update(cleanupVerified=1), lambda r: r.update(imageIds={'backend': '/private/PRIVATE_CANARY'}),
            lambda r: r.update(sourceHashAfter='PRIVATE_CANARY'),
            lambda r: r['checks'].update(images='NOT_RUN')]
        for mutate in mutations:
            report = PublicReceiptTests().report(); mutate(report)
            self.assert_invalid_output(fresh, report, 'FUSE-FRESH-DIAGNOSTIC-1')

    def test_security_projection_prints_only_fixed_checks_statuses_and_counts(self):
        report = self.security_report()
        result = json.loads(security.diagnostic_report(report))
        self.assertEqual({'schemaVersion', 'status', 'failure', 'checks', 'planned', 'passed', 'notRun'}, set(result))
        self.assertEqual(set(security.DIAGNOSTIC_CHECKS), set(result['checks']))
        self.assertEqual(len(security.DIAGNOSTIC_CHECKS), result['planned'])
        self.assertTrue(all(set(row) == {'status', 'collected', 'findings', 'skipped'} for row in result['checks'].values()))
        for marker in [report['commit'], report['candidateSha256'], 'observedAt', 'manifestSha256', 'tools', 'exitCode']:
            self.assertNotIn(marker, json.dumps(result))
        report['checks']['secrets'] = {**security.verdict(1, 2, 0, 0), 'candidateFindings': 5, 'reviewedFalsePositives': 3}
        report['status'] = 'BLOCKED'
        result = json.loads(security.diagnostic_report(report))
        self.assertEqual(('CHECKS_BLOCKED', 'FAIL', 2), (result['failure'], result['checks']['secrets']['status'], result['checks']['secrets']['findings']))

    def test_security_missing_extra_unknown_and_inconsistent_pass_reports_only_print_invalid(self):
        mutations = [lambda r: r.update(rawLog='PRIVATE_CANARY'), lambda r: r.pop('checks'),
            lambda r: r.update(status='PRIVATE_CANARY'), lambda r: r.update(reason='PRIVATE_CANARY'),
            lambda r: r['checks'].pop('sast'), lambda r: r['checks'].update(PRIVATE_CANARY=security.verdict(1, 0, 0, 0)),
            lambda r: r['checks']['sast'].update(status='PRIVATE_CANARY'),
            lambda r: r['checks']['sast'].update(raw='PRIVATE_CANARY'),
            lambda r: r['checks'].update(sast=['PRIVATE_CANARY']),
            lambda r: r['checks'].update(sast=security.verdict(1, 1, 0, 0)),
            lambda r: r['checks']['sast'].update(findings=1), lambda r: r['checks']['sast'].update(skipped=1),
            lambda r: r['tools']['npm'].update(raw='PRIVATE_CANARY'), lambda r: r.update(manifestSha256=['PRIVATE_CANARY']),
            lambda r: r['tools']['npm'].update(observed='private-version-canary', versionMatched=False)]
        for mutate in mutations:
            report = self.security_report(); mutate(report)
            self.assert_invalid_output(security, report, 'FUSE-SECURITY-DIAGNOSTIC-1')

    def test_security_counts_reject_booleans_negative_nonintegers_and_overflow(self):
        for value in (True, False, -1, 1.5, 'PRIVATE_CANARY', security.DIAGNOSTIC_COUNT_LIMIT + 1):
            for key in ('collected', 'findings', 'skipped'):
                report = self.security_report(); report['checks']['sast'][key] = value
                self.assert_invalid_output(security, report, 'FUSE-SECURITY-DIAGNOSTIC-1')
            report = self.security_report(); report['candidateFiles'] = value
            self.assert_invalid_output(security, report, 'FUSE-SECURITY-DIAGNOSTIC-1')
        for value in (True, 'PRIVATE_CANARY', -256, 256):
            report = self.security_report(); report['checks']['sast']['exitCode'] = value
            self.assert_invalid_output(security, report, 'FUSE-SECURITY-DIAGNOSTIC-1')

    def test_security_setup_errors_have_one_whitelisted_failure_code(self):
        report = dict(schemaVersion=1, status='BLOCKED', reason='SCAN_SETUP_ERROR', checks={})
        result = json.loads(security.diagnostic_report(report))
        self.assertEqual(('SCAN_SETUP_ERROR', 0, len(security.DIAGNOSTIC_CHECKS)),
                         (result['failure'], result['passed'], result['notRun']))
        for mutate in [lambda r: r.update(reason='PRIVATE_CANARY'), lambda r: r.update(raw='PRIVATE_CANARY'),
                       lambda r: r.pop('checks'), lambda r: r.update(checks=['PRIVATE_CANARY'])]:
            bad = copy.deepcopy(report); mutate(bad)
            self.assert_invalid_output(security, bad, 'FUSE-SECURITY-DIAGNOSTIC-1')

    def test_private_metadata_canary_cannot_enter_security_projection(self):
        report = self.security_report()
        report['tools']['npm'].update(observed='private-version-canary', versionMatched=False)
        report['checks']['npm-sca'] = security.verdict(available=False)
        report['checks']['npm-sbom'] = security.verdict(available=False)
        report['status'] = 'BLOCKED'
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertTrue(security.print_diagnostic(report))
        self.assertNotIn('private-version-canary', output.getvalue())
        self.assertEqual('', error.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
