"""Fail-closed regression tests for inert WSL SSH candidate provisioner."""
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_candidate import (
    build_candidate_plan, stage_lab_candidate, PILOT_PORT,
)


class CandidateLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sandbox = self.root / "only-candidates"
        self.sandbox.mkdir(mode=0o700)
        self.store = DeviceCodeStore(self.root / "private-state" / "pairing.sqlite",
                                     hmac_key=b"C" * 32)
        self.keys = {}
        for role in ("device_tunnel", "device_host", "gateway_host",
                     "management", "attacker"):
            path = self.root / role
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(path)], check=True, capture_output=True)
            self.keys[role] = (
                path, " ".join(Path(str(path) + ".pub").read_text("ascii").split()[:2]))
        self.started = self.store.start(
            device_id="windows-wsl", display_name="Original WSL v2 pilot",
            source_id="198.51.100.8", persistent=False,
            tunnel_public_key=self.keys["device_tunnel"][1],
            host_public_key=self.keys["device_host"][1], now=100)
        self.request_id = self.started["request_id"]

    def approve(self):
        key = serialization.load_ssh_private_key(
            self.keys["device_tunnel"][0].read_bytes(), password=None)
        signature = base64.b64encode(
            key.sign(base64.b64decode(self.started["challenge_b64"]))).decode("ascii")
        self.store.prove(request_id=self.request_id,
                         device_secret=self.started["device_secret"],
                         signature_b64=signature, now=101)
        self.store.lookup(user_code=self.started["user_code"],
                          operator_subject="auth0|real-owner", now=102)
        self.store.confirm(request_id=self.request_id,
                           operator_subject="auth0|real-owner",
                           confirmation=self.started["confirmation"], now=103)

    def plan(self, **updates):
        kwargs = {
            "gateway_host_public_key": self.keys["gateway_host"][1],
            "gateway_management_public_key": self.keys["management"][1],
            "now": 105,
        }
        kwargs.update(updates)
        return build_candidate_plan(self.store, self.request_id, **kwargs)

    def test_no_identity_approval_no_plan_and_no_files(self):
        with self.assertRaises(PermissionError):
            self.plan()
        with self.assertRaises(PermissionError):
            stage_lab_candidate(
                self.store, self.request_id, sandbox_root=self.sandbox,
                trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=105)
        self.assertEqual(list(self.sandbox.iterdir()), [])
        with self.assertRaises(PermissionError):
            self.store.approved_candidate_snapshot(request_id=self.request_id, now=701)
        self.approve()
        with self.assertRaises(PermissionError):
            self.store.approved_candidate_snapshot(request_id=self.request_id, now=701)

    def test_exact_plan_restricts_identity_port_and_permissions(self):
        self.approve()
        plan = self.plan()
        offer = plan["offer"]
        self.assertEqual(offer["device_id"], "windows-wsl")
        self.assertEqual(offer["access_mode"], "restricted")
        self.assertIs(offer["persistent"], False)
        self.assertEqual(offer["reverse_listen_host"], "127.0.0.1")
        self.assertEqual(offer["reverse_listen_port"], 10003)
        self.assertEqual(offer["gateway_management_public_key"],
                         self.keys["management"][1])
        self.assertIn('permitlisten="127.0.0.1:10003"',
                      plan["tunnel_authorized_keys_append"])
        self.assertEqual(plan["target_management_authorized_keys_append"],
                         self.keys["management"][1] + "\n")
        self.assertNotIn("10002", json.dumps(plan))
        self.assertNotIn("sudo", json.dumps(plan))
        self.assertNotIn("ssh-rsa", json.dumps(plan))
        self.assertFalse(any(p.name.startswith("candidate-")
                             for p in self.sandbox.iterdir()))

    def test_reject_substituted_keys_even_after_approval(self):
        self.approve()
        with self.assertRaises(PermissionError):
            self.plan(gateway_management_public_key=self.keys["gateway_host"][1])
        with self.assertRaises(PermissionError):
            self.plan(gateway_host_public_key=self.keys["device_host"][1],
                      gateway_management_public_key=self.keys["device_tunnel"][1])
        with self.assertRaises(ValueError):
            self.plan(gateway_management_public_key="ssh-rsa AAAA")

    def test_stage_is_only_in_sandbox_and_offer_is_not_privileged(self):
        self.approve()
        old = self.root / "live-system-marker"
        old.write_text("legacy port 10002 remains unchanged")
        result = stage_lab_candidate(
            self.store, self.request_id, sandbox_root=self.sandbox,
            trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=105)
        self.assertEqual(result["status"], "candidate_staged")
        self.assertFalse(result["production_ssh_changed"])
        directory = Path(result["candidate_directory"])
        self.assertEqual(directory.parent, self.sandbox)
        self.assertTrue((directory / "STAGING_ONLY").is_file())
        for item in directory.iterdir():
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o600)
        private = directory / "gateway-management-ed25519"
        self.assertIn("OPENSSH PRIVATE KEY", private.read_text())
        manifest = json.loads((directory / "offer.json").read_text())
        self.assertEqual(manifest["reverse_listen_port"], PILOT_PORT)
        self.assertNotIn("private", json.dumps(manifest))
        self.assertNotIn("device_secret", json.dumps(manifest))
        self.assertEqual(old.read_text(), "legacy port 10002 remains unchanged")
        public_polled = self.store.poll(request_id=self.request_id,
                                        device_secret=self.started["device_secret"],
                                        now=110)
        self.assertEqual(public_polled["connection_offer"], manifest)
        self.assertEqual(public_polled["status"], "approved")
        with self.assertRaises(PermissionError):
            self.plan()
        with self.assertRaises(FileExistsError):
            stage_lab_candidate(
                self.store, self.request_id, sandbox_root=self.sandbox,
                trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=112)

    def test_failed_db_stage_removes_only_new_candidate(self):
        self.approve()
        marker = self.sandbox / "existing"
        marker.write_text("keep-me")
        with patch.object(self.store, "stage_connection_offer",
                          side_effect=PermissionError("simulated state race")):
            with self.assertRaises(PermissionError):
                stage_lab_candidate(
                    self.store, self.request_id, sandbox_root=self.sandbox,
                    trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=105)
        self.assertEqual(marker.read_text(), "keep-me")
        self.assertEqual([p.name for p in self.sandbox.iterdir()], ["existing"])
        self.assertNotIn("connection_offer", self.store.poll(
            request_id=self.request_id,
            device_secret=self.started["device_secret"], now=110))

    def test_reject_unsafe_sandbox_root(self):
        self.approve()
        self.sandbox.chmod(0o777)
        with self.assertRaises(PermissionError):
            stage_lab_candidate(
                self.store, self.request_id, sandbox_root=self.sandbox,
                trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=105)
        self.sandbox.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.sandbox, target_is_directory=True)
        with self.assertRaises(PermissionError):
            stage_lab_candidate(
                self.store, self.request_id, sandbox_root=alias,
                trusted_gateway_host_public_key=self.keys["gateway_host"][1], now=105)


if __name__ == "__main__":
    unittest.main()
