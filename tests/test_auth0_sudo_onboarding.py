"""Read-only policy regression: Auth0-owned devices may request, never self-approve.

All root fixtures are created in an isolated GitHub-hosted runner, not Oracle.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parents[1] / "scripts" / "privilege_broker_daemon.py"
loader = importlib.machinery.SourceFileLoader("root_broker_auth0_sudo_test", str(P))
spec = importlib.util.spec_from_loader(loader.name, loader)
broker = importlib.util.module_from_spec(spec)
loader.exec_module(broker)

OWNER = "auth0|owner-test-subject"
OTHER = "auth0|other-test-subject"
NEW = "laptop-lab-a1b2c3d4"
OLD = "ai-lab-experiments-01-fd3dab34"


@unittest.skipUnless(os.geteuid() == 0, "root fixture requires disposable GitHub runner")
class BoundOwnerRootEligibility(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ai-lab-root-eligibility-")
        self.addCleanup(self.temp.cleanup)
        d = Path(self.temp.name)
        self.issuer = d / "issuer"
        self.issuer.mkdir(mode=0o700)
        self.config = self.issuer / "targets.json"
        self.registry = d / "devices.json"
        self.authz = d / "authorization.json"
        self.write_json(self.config, {"version": 1, "devices": [OLD]}, 0o600)
        self.write_json(self.registry, {"devices": [{
            "id": NEW, "name": "Disposable target", "enabled": True,
            "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
            "tunnel_port": 11001,
            "identity_file": f"/etc/ai-lab-gateway/device-code-keys/{NEW}/identity",
        }]}, 0o640)
        self.write_json(self.authz, {"users": [{
            "subject": OWNER, "devices": {NEW: [
                "status", "exec", "read_file", "write_file",
                "target_privilege_execute",
            ]}},
            {"subject": OTHER, "devices": {"unrelated-device": ["status"]}},
        ]}, 0o640)
        m = patch.multiple(broker, TARGET_ISSUER_DIR=self.issuer,
                           TARGET_DEVICES=self.config,
                           PROTECTED_REGISTRY=self.registry,
                           PROTECTED_AUTHZ=self.authz)
        m.start()
        self.addCleanup(m.stop)

    @staticmethod
    def write_json(path, document, mode):
        path.write_text(json.dumps(document))
        path.chmod(mode)

    def opt_in_v2(self):
        self.write_json(self.config, {
            "version": 2, "devices": [OLD],
            "allow_verified_restricted_onboarding": True}, 0o600)

    def test_v1_does_not_automatically_extend_to_new_device(self):
        self.assertTrue(broker.target_enabled(OLD, OWNER))
        self.assertFalse(broker.target_enabled(NEW, OWNER))

    def test_v2_only_verified_auth0_owner_can_request(self):
        self.opt_in_v2()
        self.assertTrue(broker.target_enabled(NEW, OWNER))
        self.assertFalse(broker.target_enabled(NEW, OTHER))
        self.assertFalse(broker.target_enabled(NEW))
        self.assertTrue(broker.target_enabled(OLD, OWNER))

    def test_new_device_without_request_grant_is_denied(self):
        self.opt_in_v2()
        data = json.loads(self.authz.read_text())
        data["users"][0]["devices"][NEW].remove("target_privilege_execute")
        self.write_json(self.authz, data, 0o640)
        self.assertFalse(broker.target_enabled(NEW, OWNER))

    def test_reject_unverified_ssh_or_untrusted_registry(self):
        self.opt_in_v2()
        original = json.loads(self.registry.read_text())
        for replacement in ({"enabled": False}, {"ssh_user": "root"},
                            {"tunnel_port": 22}, {"tunnel_host": "0.0.0.0"},
                            {"identity_file": "/tmp/attacker-key"}):
            bad = json.loads(json.dumps(original))
            bad["devices"][0].update(replacement)
            self.write_json(self.registry, bad, 0o640)
            with self.subTest(replacement=replacement):
                self.assertFalse(broker.target_enabled(NEW, OWNER))
        self.write_json(self.registry, original, 0o666)
        self.assertFalse(broker.target_enabled(NEW, OWNER))
        self.write_json(self.registry, original, 0o640)

    def test_reject_shared_target_or_duplicate_registration(self):
        self.opt_in_v2()
        doc = json.loads(self.authz.read_text())
        doc["users"][1]["devices"][NEW] = ["status"]
        self.write_json(self.authz, doc, 0o640)
        self.assertFalse(broker.target_enabled(NEW, OWNER))
        doc["users"][1]["devices"].pop(NEW)
        self.write_json(self.authz, doc, 0o640)
        registry = json.loads(self.registry.read_text())
        registry["devices"].append(dict(registry["devices"][0]))
        self.write_json(self.registry, registry, 0o640)
        self.assertFalse(broker.target_enabled(NEW, OWNER))

    def test_reject_dangerous_v2_policy_and_symlink(self):
        for bad in ({"version": 2, "devices": [OLD],
                     "allow_verified_restricted_onboarding": False},
                    {"version": 2, "devices": [OLD, OLD],
                     "allow_verified_restricted_onboarding": True},
                    {"version": 2, "devices": [OLD],
                     "allow_verified_restricted_onboarding": "yes"}):
            self.write_json(self.config, bad, 0o600)
            with self.subTest(bad=bad):
                self.assertFalse(broker.target_enabled(NEW, OWNER))
        self.opt_in_v2()
        copy = self.issuer / "registry-real.json"
        copy.write_bytes(self.registry.read_bytes())
        self.registry.unlink()
        self.registry.symlink_to(copy)
        self.assertFalse(broker.target_enabled(NEW, OWNER))


if __name__ == "__main__":
    unittest.main()
