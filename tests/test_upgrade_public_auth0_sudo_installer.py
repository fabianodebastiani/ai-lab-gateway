"""Disposable root-controlled static one-line installer v2 upgrade tests.

No HTTPS or Caddy operations; fixture files only. No real host changes.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / "scripts/upgrade_verified_public_installer.py"
loader = importlib.machinery.SourceFileLoader("public_installer_v2_upgrade_test", str(P))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


@unittest.skipUnless(os.geteuid() == 0, "root tests on disposable GitHub runner only")
class StaticReleaseUpgradeTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="ai-lab-v2-publisher-tests-")
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        self.public = root / "install.sh"
        self.old = b"#!/bin/sh\nprintf OLD\n"
        self.new = b"#!/bin/sh\nprintf NEW\n"
        self.public.write_bytes(self.old)
        self.public.chmod(0o644)
        self.broker = root / "broker"
        self.broker.write_bytes(b"broker v2")
        self.broker.chmod(0o755)
        self.plan = root / "linux_plan.py"
        self.plan.write_bytes(b"new plan")
        self.plan.chmod(0o644)
        self.issuer = root / "targets.json"
        self.issuer.write_text(json.dumps({
            "version": 2, "devices": ["ai-lab-experiments-01-fd3dab34"],
            "allow_verified_restricted_onboarding": True,
        }))
        self.issuer.chmod(0o600)
        backdir = root / "backups"
        backdir.mkdir(mode=0o755)
        self.backup = backdir / "backup"
        p = patch.multiple(
            m, PUBLIC=self.public, BACKUP=self.backup,
            OLD=m.sha(self.old), NEW=m.sha(self.new),
            BROKER=self.broker, BROKER_SHA=m.sha(self.broker.read_bytes()),
            PLAN=self.plan, PLAN_SHA=m.sha(self.plan.read_bytes()),
            ISSUER_CONFIG=self.issuer)
        p.start()
        self.addCleanup(p.stop)
        d = patch.object(m, "pinned_download", return_value=self.new)
        d.start()
        self.addCleanup(d.stop)

    def test_check_does_not_update_public_url(self):
        self.assertEqual(m.preflight(), self.new)
        self.assertEqual(self.public.read_bytes(), self.old)
        self.assertFalse(self.backup.exists())

    def test_publish_succeeds_only_with_ready_gateway(self):
        with patch.object(m, "verify_online"):
            m.apply()
        self.assertEqual(self.public.read_bytes(), self.new)
        self.assertEqual((self.backup / "install-v1.sh").read_bytes(), self.old)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)

    def test_fail_closed_if_issuer_not_enabled(self):
        self.issuer.write_text(json.dumps({"version": 1, "devices": []}))
        with patch.object(m, "verify_online"):
            with self.assertRaises(PermissionError):
                m.apply()
        self.assertEqual(self.public.read_bytes(), self.old)

    def test_failure_verifying_public_response_restores_v1(self):
        with patch.object(m, "verify_online", side_effect=PermissionError("invalid remote hash")):
            with self.assertRaises(PermissionError):
                m.apply()
        self.assertEqual(self.public.read_bytes(), self.old)

    def test_modified_public_installer_refuses_upgrade(self):
        self.public.write_bytes(b"#!/bin/sh\nattacker\n")
        with self.assertRaises(PermissionError):
            m.preflight()


if __name__ == "__main__":
    unittest.main()
