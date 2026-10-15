"""Rehearse candidate append/rollback against sandbox files, never real sshd."""
import base64
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_candidate import stage_lab_candidate
from ai_lab_gateway.device_code_candidate_files import rehearse_mock_gateway_install


class SandboxSSHFileTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sandbox = self.root / "sandbox"
        self.sandbox.mkdir(mode=0o700)
        self.mock = self.sandbox / "mock-gateway"
        self.mock.mkdir(mode=0o700)
        self.auth = self.mock / "authorized_keys"
        self.known = self.mock / "known_hosts"
        self.old_auth = b'permitlisten="127.0.0.1:10002" ssh-ed25519 LEGACY123\n'
        self.old_known = b'[127.0.0.1]:10002 ssh-ed25519 LEGACY456\n'
        self.auth.write_bytes(self.old_auth)
        self.known.write_bytes(self.old_known)
        self.auth.chmod(0o600)
        self.known.chmod(0o600)
        self.external_marker = self.root / "production-not-touched"
        self.external_marker.write_text("preserve-me")
        self.store = DeviceCodeStore(self.root / "db" / "sessions.sqlite",
                                     hmac_key=b"R" * 32)
        self.keys = {}
        for label in ("tunnel", "host", "gateway"):
            name = self.root / label
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                            "-N", "", "-f", str(name)], capture_output=True,
                           check=True)
            self.keys[label] = (name, " ".join(
                Path(str(name) + ".pub").read_text().split()[:2]))
        self.started = self.store.start(
            device_id="windows-wsl", display_name="WSL candidate test",
            persistent=False, source_id="203.0.113.11",
            tunnel_public_key=self.keys["tunnel"][1],
            host_public_key=self.keys["host"][1])
        self.request = self.started["request_id"]

    def stage(self):
        tunnel_private = serialization.load_ssh_private_key(
            self.keys["tunnel"][0].read_bytes(), password=None)
        signature = base64.b64encode(
            tunnel_private.sign(base64.b64decode(self.started["challenge_b64"]))).decode()
        self.store.prove(request_id=self.request,
                         device_secret=self.started["device_secret"],
                         signature_b64=signature)
        self.store.lookup(user_code=self.started["user_code"],
                          operator_subject="auth0|approved")
        self.store.confirm(request_id=self.request,
                           operator_subject="auth0|approved",
                           confirmation=self.started["confirmation"])
        return stage_lab_candidate(
            self.store, self.request, sandbox_root=self.sandbox,
            trusted_gateway_host_public_key=self.keys["gateway"][1])

    def rehearse(self, **kw):
        return rehearse_mock_gateway_install(
            self.store, self.request, sandbox_root=self.sandbox,
            independent_gateway_host_key=self.keys["gateway"][1], **kw)

    def unchanged(self):
        self.assertEqual(self.auth.read_bytes(), self.old_auth)
        self.assertEqual(self.known.read_bytes(), self.old_known)
        self.assertEqual(self.external_marker.read_text(), "preserve-me")

    def test_approved_candidate_appends_only_fixed_sandbox_fragments(self):
        self.stage()
        answer = self.rehearse()
        self.assertEqual(answer, {
            "status": "mock_gateway_fragments_applied",
            "port": 10003, "live_ssh_changed": False,
            "registry_changed": False})
        self.assertTrue(self.auth.read_bytes().startswith(self.old_auth))
        self.assertTrue(self.known.read_bytes().startswith(self.old_known))
        self.assertIn(b'permitlisten="127.0.0.1:10003"', self.auth.read_bytes())
        self.assertIn(b'[127.0.0.1]:10003 ', self.known.read_bytes())
        self.assertEqual(stat.S_IMODE(self.auth.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.known.stat().st_mode), 0o600)
        self.assertEqual(self.external_marker.read_text(), "preserve-me")

    def test_replay_rejected_without_mutation(self):
        self.stage()
        self.rehearse()
        before = self.auth.read_bytes(), self.known.read_bytes()
        with self.assertRaises(FileExistsError):
            self.rehearse()
        self.assertEqual(before, (self.auth.read_bytes(), self.known.read_bytes()))

    def test_failure_after_first_atomic_write_restores_existing_files(self):
        self.stage()
        with self.assertRaises(RuntimeError):
            self.rehearse(inject_failure_after_first=True)
        self.unchanged()

    def test_wrong_independent_gateway_host_pin_rejected(self):
        self.stage()
        with self.assertRaises(PermissionError):
            rehearse_mock_gateway_install(
                self.store, self.request, sandbox_root=self.sandbox,
                independent_gateway_host_key=self.keys["host"][1])
        self.unchanged()

    def test_modified_offer_and_public_fragments_rejected(self):
        self.stage()
        candidate = self.sandbox / ("candidate-" + self.request)
        manifest = candidate / "offer.json"
        original = manifest.read_bytes()
        data = json.loads(original)
        data["reverse_listen_port"] = 10002
        manifest.write_text(json.dumps(data))
        manifest.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.rehearse()
        manifest.write_bytes(original)
        manifest.chmod(0o600)
        frag = candidate / "tunnel-authorized_keys.append"
        frag.write_text(frag.read_text().replace("10003", "11003"))
        frag.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.rehearse()
        self.unchanged()

    def test_unapproved_or_expired_state_does_not_touch_files(self):
        with self.assertRaises(PermissionError):
            self.rehearse()
        self.stage()
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE sessions SET expires_at=1 WHERE request_id=?",
                       (self.request,))
        with self.assertRaises(PermissionError):
            self.rehearse()
        self.unchanged()

    def test_mock_file_symlink_or_unsafe_permissions_rejected(self):
        self.stage()
        self.auth.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.rehearse()
        self.auth.chmod(0o600)
        self.auth.unlink()
        self.auth.symlink_to(self.external_marker)
        with self.assertRaises(PermissionError):
            self.rehearse()
        self.assertEqual(self.external_marker.read_text(), "preserve-me")
        self.assertEqual(self.known.read_bytes(), self.old_known)

    def test_rejects_path_traversal_request_before_any_file_operation(self):
        self.stage()
        with self.assertRaises(PermissionError):
            rehearse_mock_gateway_install(
                self.store, "../" + self.request, sandbox_root=self.sandbox,
                independent_gateway_host_key=self.keys["gateway"][1])
        self.unchanged()


if __name__ == "__main__":
    unittest.main()
