"""Disposable-root test of one-time Auth0-scoped sudo eligibility opt-in.

Never accesses /etc on an actual Gateway; path constants point at an isolated
temporary directory on a disposable GitHub Actions runner.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/enable_auth0_sudo_onboarding.py"
loader = importlib.machinery.SourceFileLoader("one_time_auth0_sudo_optin", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)
DID = "simonelaptop-3099cd33"
PREV = "ai-lab-experiments-01-fd3dab34"


@unittest.skipUnless(os.geteuid() == 0, "isolated root fixture must use disposable runner")
class RootAdminOptInTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="ai-lab-root-sudo-migrate-")
        self.addCleanup(td.cleanup)
        d = Path(td.name)
        self.issuer = d / "issuer"
        self.issuer.mkdir(mode=0o700)
        self.tfile = self.issuer / "targets.json"
        self.registry = d / "devices.json"
        self.policy = d / "authorization.json"
        backups = d / "backups"
        backups.mkdir(mode=0o755)
        self.backup = backups / "sudo"
        self.set_json(self.tfile, {"version": 1, "devices": [PREV]}, 0o600)
        self.set_json(self.registry, {"devices": [{
            "id": DID, "enabled": True, "name": "SimoneLaptop",
            "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
            "tunnel_port": 11001,
            "identity_file": f"/etc/ai-lab-gateway/device-code-keys/{DID}/identity"
        }]}, 0o640)
        self.set_json(self.policy, {"users": [
            {"subject": "auth0|owner", "devices": {DID: [
                "status", "exec", "read_file", "write_file"]}},
            {"subject": "auth0|other", "devices": {"elsewhere": ["status"]}}
        ]}, 0o640)
        p = patch.multiple(m, ISSUER_DIR=self.issuer, TARGETS=self.tfile,
                           REGISTRY=self.registry, POLICY=self.policy,
                           BACKUP=self.backup)
        p.start()
        self.addCleanup(p.stop)

    def set_json(self, path, data, mode):
        path.write_text(json.dumps(data))
        path.chmod(mode)

    def test_check_does_not_write_either_file(self):
        before = (self.tfile.read_bytes(), self.policy.read_bytes())
        v2, acl, *rest = m.plan(DID)
        self.assertEqual(v2["version"], 2)
        self.assertEqual(v2["devices"], [PREV])
        self.assertEqual(acl["users"][0]["devices"][DID][-1], m.ACTION)
        self.assertEqual(before, (self.tfile.read_bytes(), self.policy.read_bytes()))
        self.assertFalse(self.backup.exists())

    def test_original_root_operator_approves_enable_and_one_device_backfill(self):
        m.apply(DID)
        config = json.loads(self.tfile.read_bytes())
        self.assertEqual(config["version"], 2)
        self.assertEqual(config["devices"], [PREV])
        self.assertTrue(config["allow_verified_restricted_onboarding"])
        grants = json.loads(self.policy.read_bytes())["users"]
        self.assertIn(m.ACTION, grants[0]["devices"][DID])
        self.assertEqual(grants[1]["devices"], {"elsewhere": ["status"]})
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.backup / "issuer-v1.json").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(PermissionError):
            m.apply(DID)

    def test_unknown_or_unverified_device_denied(self):
        for target in ("unknown-aaaaaaaa", "../root", ""):
            with self.subTest(target=target), self.assertRaises((ValueError, PermissionError)):
                m.plan(target)
        data = json.loads(self.registry.read_bytes())
        data["devices"][0]["ssh_user"] = "root"
        self.set_json(self.registry, data, 0o640)
        with self.assertRaises(PermissionError):
            m.plan(DID)

    def test_shared_device_owner_denied(self):
        policy = json.loads(self.policy.read_bytes())
        policy["users"][1]["devices"][DID] = ["status"]
        self.set_json(self.policy, policy, 0o640)
        with self.assertRaises(PermissionError):
            m.plan(DID)

    def test_world_writable_authorization_denied(self):
        self.policy.chmod(0o666)
        with self.assertRaises(PermissionError):
            m.plan(DID)

    def test_dry_run_without_backfill_does_not_change_auth0_grants(self):
        _, acl, _, before, _, after = m.plan(None)
        self.assertEqual(before, after)
        self.assertEqual(acl, json.loads(before))


if __name__ == "__main__":
    unittest.main()
