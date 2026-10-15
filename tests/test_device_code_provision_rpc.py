"""End-to-end non-root Unix boundary tests (no real SSH/systemd writes)."""
import base64
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_provision_rpc import (
    CandidateProvisionProtocol, call_lab_provision_socket,
    create_lab_provision_socket,
)


class CandidateProvisionRPCTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.sandbox = self.root / "sandbox"
        self.sandbox.mkdir(mode=0o700)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.sock = self.runtime / "candidate.sock"
        self.store = DeviceCodeStore(self.root/"db"/"device.sqlite",
                                     hmac_key=b"Q" * 32)
        self.keys = {}
        for role in ("tunnel", "target_host", "gateway_host"):
            key = self.root / role
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(key)], check=True, capture_output=True)
            self.keys[role] = (key, " ".join(Path(str(key) + ".pub")
                                           .read_text("ascii").split()[:2]))
        self.protocol = CandidateProvisionProtocol(
            self.store, sandbox_root=self.sandbox,
            trusted_gateway_host_public_key=self.keys["gateway_host"][1])
        self.started = self.store.start(
            device_id="windows-wsl", display_name="Test WSL",
            tunnel_public_key=self.keys["tunnel"][1],
            host_public_key=self.keys["target_host"][1],
            persistent=False, source_id="127.0.0.1")
        self.request_id = self.started["request_id"]

    def approve(self):
        key = serialization.load_ssh_private_key(
            self.keys["tunnel"][0].read_bytes(), password=None)
        proof = base64.b64encode(
            key.sign(base64.b64decode(self.started["challenge_b64"]))).decode("ascii")
        self.store.prove(request_id=self.request_id,
                         device_secret=self.started["device_secret"],
                         signature_b64=proof)
        self.store.lookup(user_code=self.started["user_code"],
                          operator_subject="auth0|operator")
        self.store.confirm(request_id=self.request_id,
                           operator_subject="auth0|operator",
                           confirmation=self.started["confirmation"])

    def launch(self, *, allowed_uid=None):
        server = create_lab_provision_socket(
            self.sock, self.protocol,
            allowed_peer_uid=os.geteuid() if allowed_uid is None else allowed_uid)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def stop():
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()
            self.sock.unlink(missing_ok=True)
        self.addCleanup(stop)

    def raw_call(self, payload):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.connect(str(self.sock))
            conn.sendall(json.dumps(payload).encode() + b"\n")
            result = conn.recv(1024)
        return json.loads(result)

    def test_real_kernel_peer_uid_and_approved_only_action(self):
        self.approve()
        self.launch()
        self.assertEqual(stat.S_IMODE(self.sock.stat().st_mode), 0o600)
        result = call_lab_provision_socket(self.sock, request_id=self.request_id)
        self.assertEqual(result, {
            "ok": True, "status": "candidate_staged",
            "access_mode": "restricted", "live_ssh_changed": False,
        })
        target = self.sandbox / ("candidate-" + self.request_id)
        self.assertTrue(target.exists())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(
            (target/"gateway-management-ed25519").stat().st_mode), 0o600)
        offer = json.loads((target/"offer.json").read_text("utf-8"))
        self.assertEqual(offer["reverse_listen_port"], 10003)
        self.assertEqual(offer["access_mode"], "restricted")
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("key", json.dumps(result))

    def test_pending_session_cannot_stage_and_leaks_nothing(self):
        self.launch()
        result = call_lab_provision_socket(self.sock, request_id=self.request_id)
        self.assertEqual(result, {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_unapproved_expired_request_fails_closed(self):
        self.approve()
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE sessions SET expires_at=1 WHERE request_id=?",
                       (self.request_id,))
        self.launch()
        self.assertEqual(call_lab_provision_socket(
            self.sock, request_id=self.request_id),
            {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_wrong_peer_uid_rejected_by_kernel_and_no_keys_created(self):
        self.approve()
        self.launch(allowed_uid=os.geteuid() + 1)
        self.assertEqual(call_lab_provision_socket(
            self.sock, request_id=self.request_id),
            {"ok": False, "error": "unauthorized_peer"})
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_rejects_any_client_selected_port_device_mode_key_or_command(self):
        self.approve()
        self.launch()
        for change in ({"port": 22}, {"device_id": "oracle-gateway"},
                       {"access_mode": "unrestricted"}, {"sudo": True},
                       {"key": "ssh-ed25519 AAAA"}, {"path": "/etc/sudoers"},
                       {"command": "id"}, {"approved": True}):
            request = {"action": "stage_wsl_candidate",
                       "request_id": self.request_id, **change}
            with self.subTest(change=change):
                self.assertEqual(self.raw_call(request),
                                 {"ok": False, "error": "invalid_request"})
        self.assertEqual(self.raw_call(
            {"action": "activate", "request_id": self.request_id}),
            {"ok": False, "error": "unsupported"})
        self.assertEqual(self.raw_call(
            {"action": "stage_wsl_candidate", "request_id": True}),
            {"ok": False, "error": "invalid_request"})
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_once_only_and_existing_lab_files_preserved(self):
        self.approve()
        marker = self.sandbox / "existing-lab-data"
        marker.write_text("preserved")
        self.launch()
        ok = call_lab_provision_socket(self.sock, request_id=self.request_id)
        bad = call_lab_provision_socket(self.sock, request_id=self.request_id)
        self.assertTrue(ok["ok"])
        self.assertEqual(bad, {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(marker.read_text(), "preserved")
        self.assertEqual(len(list(self.sandbox.glob("candidate-*"))), 1)

    def test_db_failure_rolls_back_new_artifacts_without_exposing_keys(self):
        self.approve()
        self.launch()
        with patch.object(self.store, "stage_connection_offer",
                          side_effect=PermissionError("simulated collision")):
            result = call_lab_provision_socket(self.sock, request_id=self.request_id)
        self.assertEqual(result, {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(list(self.sandbox.iterdir()), [])

    def test_socket_requires_private_directory_and_refuses_symlinks(self):
        self.runtime.chmod(0o777)
        with self.assertRaises(PermissionError):
            create_lab_provision_socket(
                self.sock, self.protocol, allowed_peer_uid=os.geteuid())
        self.runtime.chmod(0o700)
        link = self.root / "socket-link"
        link.symlink_to(self.sock)
        with self.assertRaises(PermissionError):
            create_lab_provision_socket(
                link, self.protocol, allowed_peer_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
