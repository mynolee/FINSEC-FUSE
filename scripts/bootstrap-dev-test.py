#!/usr/bin/env python3
"""Disposable synthetic-credential tests; never touches the working project's secrets."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
spec = importlib.util.spec_from_file_location("bootstrap_dev", Path(__file__).with_name("bootstrap_dev.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
class PrivateBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".env.example").write_text("FUSE_SERVICE_TOKEN=CHANGE_ME\n")
    def test_private_material_matches_nonroot_compose_identity_and_is_idempotent(self):
        bootstrap.provision(self.root)
        key, env = self.root / ".secrets/signing.key", self.root / ".env"
        for path in (key, env):
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(os.getuid(), path.stat().st_uid)
        self.assertEqual(0o700, stat.S_IMODE(key.parent.stat().st_mode))
        self.assertEqual(32, key.stat().st_size)
        self.assertIn(f"FUSE_RUNTIME_UID={os.getuid()}", env.read_text())
        self.assertIn(f"FUSE_RUNTIME_GID={os.getgid()}", env.read_text())
        snapshot = [(p.read_bytes(), p.stat().st_mtime_ns) for p in (key, env)]
        bootstrap.provision(self.root)
        self.assertEqual(snapshot, [(p.read_bytes(), p.stat().st_mtime_ns) for p in (key, env)])
    def test_root_and_invalid_identity_are_rejected_before_writes(self):
        for uid, gid in ((0, 1000), (1000, 0), (-1, 1000), (2**32 - 1, 1000), ("1000", 1000)):
            with self.subTest(uid=uid, gid=gid), patch.object(bootstrap.os, "getuid", return_value=uid), patch.object(bootstrap.os, "getgid", return_value=gid):
                with self.assertRaises(ValueError): bootstrap.provision(self.root)
                self.assertFalse((self.root / ".env").exists())
                self.assertFalse((self.root / ".secrets").exists())
    def test_legacy_world_readable_key_is_not_silently_repaired(self):
        bootstrap.provision(self.root)
        key = self.root / ".secrets/signing.key"
        key.chmod(0o444)
        before = key.read_bytes()
        with self.assertRaisesRegex(ValueError, "0600"): bootstrap.provision(self.root)
        self.assertEqual(0o444, stat.S_IMODE(key.stat().st_mode))
        self.assertEqual(before, key.read_bytes())
    def test_missing_or_wrong_runtime_identity_is_not_rewritten(self):
        bootstrap.provision(self.root)
        env = self.root / ".env"
        env.write_text(env.read_text().replace(f"FUSE_RUNTIME_UID={os.getuid()}", "FUSE_RUNTIME_UID=0"))
        before = env.read_bytes()
        with self.assertRaisesRegex(ValueError, "FUSE_RUNTIME_UID"): bootstrap.provision(self.root)
        self.assertEqual(before, env.read_bytes())
    def test_partial_write_failure_removes_only_new_files(self):
        original_open = bootstrap.os.open
        def fail_second(path, *args, **kwargs):
            if Path(path).name == ".env": raise OSError("synthetic exclusive create failure")
            return original_open(path, *args, **kwargs)
        with patch.object(bootstrap.os, "open", side_effect=fail_second):
            with self.assertRaises(OSError): bootstrap.provision(self.root)
        self.assertFalse((self.root / ".env").exists())
        self.assertFalse((self.root / ".secrets/signing.key").exists())
        self.assertTrue((self.root / ".env.example").exists())
    def test_symlink_and_partial_configuration_fail_without_overwrite(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.root / ".secrets").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): bootstrap.provision(self.root)
        self.assertEqual([], list(outside.iterdir()))
        (self.root / ".secrets").unlink()
        (self.root / ".env").write_text("synthetic existing configuration")
        with self.assertRaises(ValueError): bootstrap.provision(self.root)
        self.assertFalse((self.root / ".secrets").exists())
if __name__ == "__main__": unittest.main()
