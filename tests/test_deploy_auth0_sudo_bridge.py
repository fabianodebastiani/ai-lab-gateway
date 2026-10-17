"""Disposable-root dry-run, transaction and rollback tests for Gateway bridge.

All service starts are mocked; all files reside under temp on GitHub runner.
"""
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / "scripts/deploy_auth0_sudo_bridge.py"
loader = importlib.machinery.SourceFileLoader("gateway_sudo_deploy_tests", str(P))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


@unittest.skipUnless(os.geteuid() == 0, "isolated root fixture only")
class RootCodeDeployTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="auth0-sudo-deploy-test-")
        self.addCleanup(td.cleanup)
        parent = Path(td.name)
        dest = parent / "libexec"
        dest.mkdir(mode=0o755)
        self.broker = dest / "broker"
        plan_dir = parent / "src"
        plan_dir.mkdir(mode=0o755)
        self.plan = plan_dir / "linux_plan.py"
        self.old_broker = b'print("original broker")\n'
        self.old_plan = b'print("original plan")\n'
        self.new_broker = b'print("new broker")\n'
        self.new_plan = b'print("new plan")\n'
        self.broker.write_bytes(self.old_broker)
        self.plan.write_bytes(self.old_plan)
        self.broker.chmod(0o755)
        self.plan.chmod(0o644)
        back = parent / "backups"
        back.mkdir(mode=0o755)
        self.backup = back / "gateway-bak"
        original = (
            ("scripts/broker", "1" * 40, m.sha(self.new_broker), self.broker, m.sha(self.old_broker)),
            ("src/plan", "2" * 40, m.sha(self.new_plan), self.plan, m.sha(self.old_plan)),
        )
        pp = patch.multiple(m, SOURCES=original, BACKUP=self.backup)
        pp.start()
        self.addCleanup(pp.stop)
        source = lambda name, commit, check: (
            self.new_broker if name == "scripts/broker" else self.new_plan)
        ps = patch.object(m, "get_pinned", side_effect=source)
        ps.start()
        self.addCleanup(ps.stop)

    def test_check_unchanged_and_hash_strict(self):
        self.assertEqual(len(m.preflight()), 2)
        self.assertFalse(self.backup.exists())
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.plan.read_bytes(), self.old_plan)
        self.plan.write_text("altered external code")
        with self.assertRaises(PermissionError):
            m.preflight()

    def test_root_rollout_only_two_paths_and_backup(self):
        def fake_service(args, **kwargs):
            return subprocess.CompletedProcess(args, 0)
        with patch.object(m.subprocess, "run", side_effect=fake_service):
            m.apply()
        self.assertEqual(self.broker.read_bytes(), self.new_broker)
        self.assertEqual(self.plan.read_bytes(), self.new_plan)
        self.assertEqual((self.backup / "source-0.before").read_bytes(), self.old_broker)
        self.assertEqual((self.backup / "source-1.before").read_bytes(), self.old_plan)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)

    def test_failed_service_restart_restores_existing_services_code(self):
        calls = []
        def fake_service(args, **kwargs):
            calls.append(args)
            if len(calls) == 1:
                raise subprocess.CalledProcessError(1, args)
            return subprocess.CompletedProcess(args, 0)
        with patch.object(m.subprocess, "run", side_effect=fake_service):
            with self.assertRaises(subprocess.CalledProcessError):
                m.apply()
        self.assertEqual(self.broker.read_bytes(), self.old_broker)
        self.assertEqual(self.plan.read_bytes(), self.old_plan)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
