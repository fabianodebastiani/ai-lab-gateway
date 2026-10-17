"""Disposable CI-only tests of root broker hotfix and rollback, no real service touch."""
from pathlib import Path
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / "scripts" / "deploy_console_approval_broker.py"
loader = importlib.machinery.SourceFileLoader("console_broker_deployer_test", str(SRC))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


@unittest.skipUnless(os.geteuid() == 0, "root only in isolated CI")
class ConsoleBrokerDeployment(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ai-lab-console-broker-ci-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.broker = self.root / "broker"
        self.source = self.root / "source.py"
        self.backup = self.root / "backup"
        self.old = b"#!/usr/bin/env python3\nprint('synthetic-old')\n"
        self.new = b"#!/usr/bin/env python3\nprint('synthetic-new')\n"
        self.broker.write_bytes(self.old)
        self.broker.chmod(0o755)
        self.source.write_bytes(self.new)
        p = patch.multiple(
            m, BROKER=self.broker, BACKUP=self.backup,
            OLD_SHA=hashlib.sha256(self.old).hexdigest(),
            NEW_SHA=hashlib.sha256(self.new).hexdigest())
        p.start()
        self.addCleanup(p.stop)

    def test_check_never_changes_files_or_calls_restart(self):
        with patch.object(m, "restart") as restart:
            self.assertEqual(m.check(self.source), self.new)
            restart.assert_not_called()
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.broker.read_bytes(), self.old)

    def test_only_broker_replaced_then_original_reinstated(self):
        with patch.object(m, "restart") as restart:
            new = m.check(self.source)
            m.apply(new)
            self.assertEqual(self.broker.read_bytes(), self.new)
            self.assertEqual(stat.S_IMODE(self.broker.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(self.backup.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((self.backup / "previous-broker").stat().st_mode), 0o600)
            with self.assertRaises(PermissionError):
                m.check(self.source)
            m.rollback()
            self.assertEqual(self.broker.read_bytes(), self.old)
            self.assertEqual(restart.call_count, 2)

    def test_reject_inconsistent_source_or_deployed_version(self):
        self.source.write_bytes(b"malicious changed bytes")
        with self.assertRaises(PermissionError):
            m.check(self.source)
        self.source.write_bytes(self.new)
        self.broker.write_bytes(b"unexpected deployed code")
        with self.assertRaises(PermissionError):
            m.check(self.source)
        self.assertFalse(self.backup.exists())

    def test_restart_failure_rolls_back_after_backup(self):
        calls = []
        def failure_first():
            calls.append("restart")
            if len(calls) == 1:
                raise RuntimeError("synthetic broker did not restart")
        with patch.object(m, "restart", side_effect=failure_first):
            with self.assertRaises(RuntimeError):
                m.apply(m.check(self.source))
        self.assertEqual(calls, ["restart", "restart"])
        self.assertEqual(self.broker.read_bytes(), self.old)
        self.assertEqual((self.backup / "previous-broker").read_bytes(), self.old)

    def test_symlinked_broker_is_denied(self):
        original = self.root / "original"
        self.broker.rename(original)
        self.broker.symlink_to(original)
        with self.assertRaises(PermissionError):
            m.check(self.source)
        self.assertFalse(self.backup.exists())


if __name__ == "__main__":
    unittest.main()
