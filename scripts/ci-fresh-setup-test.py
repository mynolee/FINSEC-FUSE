#!/usr/bin/env python3
"""Offline scope/report regression tests. These do not execute Docker, Java or PostgreSQL."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('fresh_setup', Path(__file__).with_name('ci-fresh-setup.py'))
fresh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fresh)


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
        self.assertIn("['stop']", source)
        self.assertIn("['start', '--wait', '--wait-timeout', '60', 'postgres']", source)
        self.assertIn("authority_snapshot(project) == authority", source)
        self.assertIn("log_out + log_err", source)
        self.assertIn("no_canaries(issued_diagnostics, list(tokens.values()))", source)

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
