#!/usr/bin/env python3
"""Synthetic, offline privacy gate regressions; no real credentials or user data."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('publication_privacy', Path(__file__).with_name('publication-privacy-check.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class PrivacyTests(unittest.TestCase):
    def test_generic_application_files_and_loader_allowed(self):
        for name, body in [('build.gradle', b'plugins { id "java" }'), ('compose.yaml', b'API_KEY: ${API_KEY:?Required}'), ('agent/prompt.py', b'def load_prompt(path): return read_registered_text(path)'), ('test.py', b'email = "synthetic@example.invalid"')]:
            self.assertIsNone(gate.inspect_bytes(name, body))

    def test_exact_reviewed_example_only(self):
        data = Path(__file__).resolve().parents[1].joinpath('.env.example').read_bytes()
        self.assertIsNone(gate.inspect_bytes('.env.example', data))
        self.assertEqual(gate.inspect_bytes('.env.example', data + b'\nSETTING=changed'), 'reviewed_file_changed')
        self.assertEqual(gate.inspect_bytes('nested/.env.example', data), 'environment_file')

    def test_environment_and_private_instruction_paths_blocked(self):
        for name in ['.env', '.env.production', 'local.env', 'nested/local.env.backup', 'nested/.env', 'AGENTS.md', 'nested/.codex/config.toml', '.github/prompts/task.md', 'private-prompts/body.txt', 'model.lock.json', '.secrets/signing.key']:
            self.assertIsNotNone(gate.inspect_bytes(name, b'generic'))

    def test_personal_paths_credentials_and_email_blocked(self):
        examples = [('/' + 'Users' + '/synthetic/file', 'personal_home_path'), ('C:' + '\\' + 'Users' + '\\' + 'synthetic', 'personal_home_path'), ('ghp_' + 'A' * 40, 'potential_credential'), ('sk-' + 'A' * 45, 'potential_credential'), ('person' + '@' + 'private-mail.tld', 'personal_email_requires_review')]
        for value, reason in examples:
            self.assertEqual(gate.inspect_bytes('ordinary.txt', value.encode()), reason)

    def manifest(self, root, records=None):
        path = root / 'inventory.json'
        if records is None:
            data = b'generic service configuration'
            (root / 'service.txt').write_bytes(data)
            records = [{'path': 'service.txt', 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}]
        path.write_text(json.dumps({'files': records}))
        return path

    def test_manifest_exact_bytes_duplicate_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = self.manifest(root)
            self.assertEqual(gate.check(gate.manifest_entries(root, manifest)), (1, {}))
            record = json.loads(manifest.read_text())['files'][0]
            self.manifest(root, [record, record])
            with self.assertRaises(gate.Blocked): gate.check(gate.manifest_entries(root, manifest))
            self.manifest(root, [record])
            (root / 'service.txt').write_bytes(b'changed')
            with self.assertRaises(gate.Blocked): gate.check(gate.manifest_entries(root, manifest))

    def test_paths_symlinks_modes_bounds_and_bad_json_fail_closed(self):
        for name in ['../escape', '/absolute', 'a/../b', 'a//b', './a', 'a\\b']:
            with self.assertRaises(gate.Blocked): gate.safe_path(name)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = self.manifest(root)
            (root / 'service.txt').unlink()
            (root / 'service.txt').symlink_to(root / 'other')
            with self.assertRaises(gate.Blocked): gate.check(gate.manifest_entries(root, manifest))
            manifest.write_text('{"files": [], "files": []}')
            with self.assertRaises(gate.Blocked): gate.check(gate.manifest_entries(root, manifest))
            with patch.object(gate, 'MAX_FILE', 1), self.assertRaises(gate.Blocked): gate.check([('safe.txt', b'long')])
            self.manifest(root, [{'path': 'safe.txt', 'size': 0, 'sha256': 'a'*64, 'mode': '120000'}])
            with self.assertRaises(gate.Blocked): gate.check(gate.manifest_entries(root, manifest))

    def test_index_reads_blobs_not_worktree_and_catches_tracked_ignored(self):
        oid = 'a' * 40
        calls = []
        def fake_git(root, *args):
            calls.append(args)
            if args[0] == 'rev-parse': return str(root.resolve()).encode()
            if args[0] == 'ls-files': return ('100644 ' + oid + ' 0\t.env\0').encode()
            if args[1] == '-s': return b'7'
            return b'private'
        with patch.object(gate, 'git', fake_git):
            count, errors = gate.check(gate.index_entries(Path('.')))
        self.assertEqual(count, 1)
        self.assertEqual(errors, {'environment_file': 1})
        self.assertIn(('cat-file', 'blob', oid), calls)

    def test_index_root_cannot_hide_parent_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            nested = root / 'nested'
            nested.mkdir()
            with patch.object(gate, 'git', return_value=str(root).encode()):
                with self.assertRaises(gate.Blocked):
                    list(gate.index_entries(nested))

    def test_output_never_echoes_sensitive_path_or_content(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            manifest = root / 'bad.json'
            manifest.write_text('unparseable private data')
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(gate.main(['--root', d, '--manifest', str(manifest)]), 1)
            self.assertNotIn(d, output.getvalue())
            self.assertNotIn('private data', output.getvalue())
            self.assertEqual(json.loads(output.getvalue())['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
