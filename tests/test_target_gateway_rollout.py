"""Disposable local-root tests for the reversible production Gateway rollout."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy_target_privilege_gateway.py"
loader = importlib.machinery.SourceFileLoader("gateway_root_rollout_test", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


@unittest.skipUnless(os.geteuid() == 0, "requires disposable GitHub Actions root runner")
class RolloutTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(prefix="ai-lab-gateway-tx-")
        self.addCleanup(t.cleanup)
        self.base = Path(t.name)
        self.src = self.base / "src"
        self.src.mkdir()
        self.issuer = self.base / "issuer"
        self.issuer.mkdir(mode=0o700)
        self.issuer.chmod(0o700)
        (self.issuer / "issuer_ed25519").write_text("SYNTHETIC PRIVATE KEY NOT VALID")
        (self.issuer / "issuer_ed25519").chmod(0o600)
        (self.issuer / "targets.json").write_text(json.dumps({
            "version": 1, "devices": [m.TARGET]}))
        (self.issuer / "targets.json").chmod(0o600)
        new_source = {}
        original_content = {}
        new_content = {}
        for i, (rel, (_real_path, _expected)) in enumerate(m.SOURCES.items()):
            path = self.src / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            blob = ("NEW_SAFE_TEST_PROGRAM_" + str(i)).encode()
            path.write_bytes(blob)
            dst = self.base / "installed" / str(i)
            dst.parent.mkdir(exist_ok=True)
            old = ("ORIGINAL_CONTENT_" + str(i)).encode()
            dst.write_bytes(old)
            dst.chmod(0o755 if i < 2 else 0o644)
            original_content[dst] = old
            new_content[dst] = blob
            new_source[rel] = (str(dst), hashlib.sha256(blob).hexdigest())
        self.original = original_content
        self.new = new_content
        self.policy = self.base / "authorization.json"
        self.policy.write_text(json.dumps({"users": [
            {"subject":"auth0|test-only-user", "devices":{
                m.TARGET: ["status", "exec"],
                "raspberry-lab": ["status"]}},
        ]}))
        self.policy.chmod(0o640)
        self.policy_old = self.policy.read_bytes()
        self.override = self.base / "systemd" / "40-target-privilege.conf"
        self.override.parent.mkdir()
        self.backup = self.base / "backup"
        p = patch.multiple(m, SOURCES=new_source, ISSUER=self.issuer,
                           POLICY=self.policy, OVERRIDE=self.override,
                           BACKUP=self.backup)
        p.start()
        self.addCleanup(p.stop)

    def test_check_never_changes_existing_runtime(self):
        with patch.object(m, "services") as svc:
            _, policy, subject = m.prepare(self.src)
        self.assertEqual(len(subject), 12)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.override.exists())
        self.assertNotEqual(policy, self.policy_old)
        self.assertEqual(self.policy.read_bytes(), self.policy_old)
        svc.assert_not_called()

    def test_apply_keeps_other_permissions_unchanged_and_rollback(self):
        with patch.object(m, "services") as svc:
            blobs, policy, _ = m.prepare(self.src)
            m.apply(blobs, policy)
            self.assertTrue(self.backup.is_dir())
            self.assertEqual(self.override.read_bytes(), m.OVERRIDE_BYTES)
            for p, content in self.new.items():
                self.assertEqual(p.read_bytes(), content)
            upgraded = json.loads(self.policy.read_text())
            actions = upgraded["users"][0]["devices"][m.TARGET]
            self.assertEqual(actions, ["status", "exec", "target_privilege_execute"])
            self.assertEqual(upgraded["users"][0]["devices"]["raspberry-lab"], ["status"])
            with self.assertRaises(FileExistsError):
                m.prepare(self.src)
            m.restore()
        for p, content in self.original.items():
            self.assertEqual(p.read_bytes(), content)
        self.assertEqual(self.policy.read_bytes(), self.policy_old)
        self.assertFalse(self.override.exists())
        self.assertTrue(svc.called)

    def test_no_action_grant_without_unique_existing_exec_right(self):
        policy = json.loads(self.policy.read_text())
        policy["users"][0]["devices"][m.TARGET] = ["status"]
        self.policy.write_text(json.dumps(policy))
        with self.assertRaises(PermissionError):
            m.prepare(self.src)
        policy["users"][0]["devices"][m.TARGET] = ["exec"]
        policy["users"].append({
            "subject": "auth0|someone-else", "devices":{m.TARGET:["exec"]}})
        self.policy.write_text(json.dumps(policy))
        with self.assertRaises(PermissionError):
            m.prepare(self.src)
        self.assertFalse(self.backup.exists())

    def test_bad_hash_or_symlink_fails_before_backup_or_service_restart(self):
        rel = next(iter(m.SOURCES))
        file = self.src / rel
        file.write_text("TAMPERED FILE")
        with self.assertRaises(PermissionError):
            m.prepare(self.src)
        self.assertFalse(self.backup.exists())
        self.assertFalse(self.override.exists())

    def test_service_failure_restores_original_and_disables_feature(self):
        counter = []
        def fake_services(*args):
            counter.append(args)
            if args == ("restart","ai-lab-approval-web") and sum(
                x == args for x in counter) == 1:
                raise RuntimeError("synthetic service restart failure")
        with patch.object(m, "services", side_effect=fake_services):
            blobs, policy, _ = m.prepare(self.src)
            with self.assertRaises(RuntimeError):
                m.apply(blobs, policy)
        for path, original in self.original.items():
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.policy.read_bytes(), self.policy_old)
        self.assertFalse(self.override.exists())


if __name__ == "__main__":
    unittest.main()
