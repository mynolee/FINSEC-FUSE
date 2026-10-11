#!/usr/bin/env python3
"""Synthetic scanner-gate regressions. No real credentials or malicious packages."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('scanner', Path(__file__).with_name('security-scan.py'))
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)


class SecurityGateTest(unittest.TestCase):
    def test_clean_nonzero_only_pass(self):
        self.assertEqual(scanner.verdict(3, 0, 0, 0)['status'], 'PASS')

    def test_findings_block_even_zero_exit(self):
        self.assertEqual(scanner.verdict(3, 1, 0, 0)['status'], 'FAIL')

    def test_skips_block(self):
        self.assertEqual(scanner.verdict(3, 0, 1, 0)['status'], 'ERROR')

    def test_invalid_counts_cannot_pass(self):
        for count in (True, '1', -1):
            self.assertEqual(scanner.verdict(count, 0, 0, 0)['status'], 'ERROR')

    def test_zero_collection_blocks(self):
        self.assertEqual(scanner.verdict(0, 0, 0, 0)['status'], 'ERROR')

    def test_tool_failure_blocks(self):
        for code in (2, 127, -9):
            self.assertEqual(scanner.verdict(3, 0, 0, code)['status'], 'ERROR')

    def test_unavailable_is_not_run(self):
        self.assertEqual(scanner.verdict(available=False)['status'], 'NOT_RUN')
        self.assertEqual(scanner.verdict()['status'], 'NOT_RUN')

    def test_candidate_excludes_private_and_environment(self):
        with tempfile.TemporaryDirectory() as d:
            root, out = Path(d) / 'repo', Path(d) / 'candidate'
            for scope in scanner.SCOPE:
                (root / scope).mkdir(parents=True, exist_ok=True)
            (root / 'agent/good.py').write_text('print(1)')
            (root / 'agent/.env').write_text('PRIVATE')
            (root / 'private-prompts').mkdir()
            (root / 'private-prompts/hidden.py').write_text('PRIVATE')
            (root / 'agent/__pycache__').mkdir()
            (root / 'agent/__pycache__/hidden.py').write_text('PRIVATE')
            count, digest = scanner.candidate(root, out)
            self.assertEqual(count, 1)
            self.assertEqual(len(digest), 64)
            self.assertEqual([p.name for p in out.rglob('*') if p.is_file()], ['good.py'])

    def test_candidate_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for scope in scanner.SCOPE:
                (root / scope).mkdir(parents=True, exist_ok=True)
            (root / 'agent/escape.py').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                scanner.candidate(root, root / 'output')

    def test_missing_tools_never_pass_or_leak(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'repo'
            for scope in scanner.SCOPE:
                (root / scope).mkdir(parents=True, exist_ok=True)
            (root / 'agent/file.py').write_text('print(1)')
            with patch.object(scanner.importlib.metadata, 'version', side_effect=scanner.importlib.metadata.PackageNotFoundError), patch.object(scanner, 'run', return_value=(127, b'PRIVATE-SYNTHETIC-MARKER')):
                report = scanner.execute(root, Path(d) / 'work')
            self.assertEqual(report['status'], 'BLOCKED')
            self.assertNotIn('PRIVATE-SYNTHETIC-MARKER', json.dumps(report))
            self.assertTrue(all(x['status'] != 'PASS' for name, x in report['checks'].items() if name != 'source-currentness'))

    def test_unapproved_or_mutated_dependency_record_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'scripts/security').mkdir(parents=True)
            record = root / 'scripts/security/dependency-review.json'
            record.write_text(json.dumps({'status': 'PENDING', 'decision': '', 'impactTests': [], 'sha256': {}}))
            self.assertNotEqual(scanner.dependency_review(root)['status'], 'PASS')
            record.write_text(json.dumps({'status': 'APPROVED', 'decision': 'synthetic', 'impactTests': ['synthetic'], 'sha256': {}}))
            self.assertNotEqual(scanner.dependency_review(root)['status'], 'PASS')

    def test_secret_review_is_exact_bound_and_expires(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'scripts/security').mkdir(parents=True)
            source = root / 'synthetic.py'
            source.write_text('synthetic fixture only')
            data = {'results': {'synthetic.py': [{'type': 'synthetic', 'hashed_secret': '0' * 40, 'line_number': 1}]}}
            row = {'path': 'synthetic.py', 'type': 'synthetic', 'fingerprintSha1': '0' * 40, 'lineNumber': 1,
                   'fileSha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'reason': 'test fixture',
                   'reviewedOn': '2026-01-01', 'expiresOn': '2099-01-01'}
            record = root / 'scripts/security/secret-review.json'
            def save():
                record.write_text(json.dumps({'status': 'APPROVED', 'findings': [row]}))
            save()
            self.assertEqual(scanner.secret_findings(data, root), 0)
            row['expiresOn'] = '2020-01-01'
            save()
            self.assertEqual(scanner.secret_findings(data, root), 1)
            row['expiresOn'] = '2099-01-01'
            save()
            source.write_text('changed fixture')
            self.assertEqual(scanner.secret_findings(data, root), 1)

    def test_metadata_exemption_is_field_type_and_occurrence_specific(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            path = 'scripts/security/secret-review.json'
            (root / path).parent.mkdir(parents=True)
            value = 'a' * 40
            record = {'path': 'synthetic.py', 'type': 'synthetic', 'fingerprintSha1': value,
                      'lineNumber': 1, 'fileSha256': 'b' * 64, 'reason': value,
                      'reviewedOn': '2026-01-01', 'expiresOn': '2099-01-01'}
            document = {'schemaVersion': 1, 'status': 'APPROVED', 'findings': [record]}
            (root / path).write_text(json.dumps(document, indent=2))
            lines = (root / path).read_text().splitlines()
            number = next(i + 1 for i, line in enumerate(lines) if 'fingerprintSha1' in line)
            row = {'type': 'Hex High Entropy String', 'line_number': number, 'hashed_secret': hashlib.sha1(value.encode()).hexdigest()}
            self.assertTrue(scanner.metadata_fingerprint(path, row, root))
            self.assertFalse(scanner.metadata_fingerprint(path, {**row, 'type': 'Secret Keyword'}, root))
            other = next(i + 1 for i, line in enumerate(lines) if 'reason' in line)
            self.assertFalse(scanner.metadata_fingerprint(path, {**row, 'line_number': other}, root))
            record['unexpectedCredential'] = value
            (root / path).write_text(json.dumps(document, indent=2))
            self.assertFalse(scanner.metadata_fingerprint(path, row, root))

    def test_dependency_metadata_requires_real_manifest_digest(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name in scanner.MANIFESTS:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('synthetic manifest')
            values = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in scanner.MANIFESTS}
            document = {'schemaVersion': 1, 'status': 'APPROVED', 'decision': 'synthetic', 'impactTests': ['synthetic'], 'sha256': values}
            path = 'scripts/security/dependency-review.json'
            (root / path).write_text(json.dumps(document, indent=2))
            number = next(i + 1 for i, line in enumerate((root / path).read_text().splitlines()) if 'build.gradle' in line)
            row = {'type': 'Hex High Entropy String', 'line_number': number, 'hashed_secret': hashlib.sha1(values['build.gradle'].encode()).hexdigest()}
            self.assertTrue(scanner.metadata_fingerprint(path, row, root))
            self.assertFalse(scanner.metadata_fingerprint(path, {**row, 'type': 'Secret Keyword'}, root))
            (root / 'build.gradle').write_text('tampered')
            self.assertFalse(scanner.metadata_fingerprint(path, row, root))
            document['unknownField'] = values['build.gradle']
            (root / path).write_text(json.dumps(document, indent=2))
            self.assertFalse(scanner.metadata_fingerprint(path, row, root))

    def test_ci_prepare_accepts_exact_browser_job_environment_only(self):
        import os
        import contextlib
        import io
        ci_spec = importlib.util.spec_from_file_location('ci_verify_scanner_test', scanner.ROOT / 'scripts/ci-verify.py')
        ci = importlib.util.module_from_spec(ci_spec)
        ci_spec.loader.exec_module(ci)
        with tempfile.TemporaryDirectory() as d:
            env = {'COMPOSE_PROJECT_NAME': 'fuse-ci-123-1', 'FUSE_UI_URL': 'http://127.0.0.1:5173',
                   'FUSE_E2E_INTEGRATION': '1', 'FUSE_E2E_ENV_FILE': d + '/.env',
                   'FUSE_E2E_SUMMARY_PATH': d + '/summary.json', 'FUSE_UI_SECURITY_HEADERS': '1'}
            with patch.object(ci, 'ROOT', Path(d)), patch.object(ci, 'credentials'), patch.object(ci.subprocess, 'run'), patch.dict(os.environ, env, clear=True):
                with contextlib.redirect_stdout(io.StringIO()):
                    ci.prepare()
                with patch.dict(os.environ, {'FUSE_UI_SECURITY_HEADERS': '0'}), self.assertRaises(ValueError):
                    ci.prepare()
                with patch.dict(os.environ, {'FUSE_SERVICE_TOKEN': 'unexpected'}), self.assertRaises(ValueError):
                    ci.prepare()

    def test_local_rules_cover_all_application_languages(self):
        rules = (scanner.ROOT / 'scripts/security/semgrep.yml').read_text()
        for language in ('python', 'java', 'typescript'):
            self.assertIn(language, rules)

    def test_ci_actions_pinned_and_no_broad_raw_upload(self):
        import re
        workflow = (scanner.ROOT / '.github/workflows/ci.yml').read_text()
        for reference in re.findall(r'uses: ([^\s]+)', workflow):
            self.assertRegex(reference, r'@[0-9a-f]{40}$')
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('contents: read', workflow)
        self.assertNotIn('path: build/', workflow)
        self.assertNotIn('security-events: write', workflow)


class ActualScannerSyntheticTest(unittest.TestCase):
    def test_actual_secret_scanner_detects_synthetic_marker(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # Deliberately synthetic, generated in an isolated temporary fixture.
            (root / 'synthetic.py').write_text('password = "' + 'fixture-only-' + 'A7b9C2d4E6f8G0h1' + '"\n')
            code, raw = scanner.run(['detect-secrets', 'scan', '--all-files', '--no-verify', '.'], root)
            self.assertEqual(code, 0, 'Required local secret scanner unavailable or failed')
            result = json.loads(raw)
            self.assertGreater(sum(len(v) for v in result['results'].values()), 0)

    def test_actual_sast_blocks_synthetic_eval(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'synthetic.py').write_text('def synthetic(value):\n    return ' + 'ev' + 'al(value)\n')
            code, raw = scanner.run(['semgrep', 'scan', '--config', str(scanner.ROOT / 'scripts/security/semgrep.yml'), '--json', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--jobs=1', '.'], root)
            self.assertEqual(code, 0, 'Required local SAST unavailable or failed')
            result = json.loads(raw)
            self.assertGreater(len(result['results']), 0)
            self.assertEqual(scanner.verdict(len(result['paths']['scanned']), len(result['results']), 0, code)['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
