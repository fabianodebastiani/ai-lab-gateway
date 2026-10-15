"""Read-only protected Unix handoff to future privileged SSH installer."""
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

from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_candidate import stage_lab_candidate
from ai_lab_gateway.device_code_approval_handoff import (
    ApprovalHandoff, create_lab_approval_handoff, inspect_candidate_over_unix,
)


class HandoffSecurityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.sandbox = self.root / "sandbox"
        self.sandbox.mkdir(mode=0o700)
        self.socket = self.runtime / "approval.sock"
        self.store = DeviceCodeStore(self.root / "pairing" / "store.sqlite",
                                     hmac_key=b"A" * 32)
        self.keys = {}
        for name in ("tunnel", "device_host", "gateway_host"):
            private = self.root / name
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(private)], capture_output=True, check=True)
            public = " ".join(Path(str(private) + ".pub").read_text().split()[:2])
            self.keys[name] = (private, public)
        self.started = self.store.start(
            device_id="windows-wsl", display_name="WSL approved candidate",
            source_id="127.0.0.1", persistent=False,
            tunnel_public_key=self.keys["tunnel"][1],
            host_public_key=self.keys["device_host"][1])
        self.request_id = self.started["request_id"]
        self.protocol = ApprovalHandoff(self.store)

    def approve_and_stage(self):
        private = serialization.load_ssh_private_key(
            self.keys["tunnel"][0].read_bytes(), password=None)
        signed = base64.b64encode(
            private.sign(base64.b64decode(self.started["challenge_b64"]))).decode()
        self.store.prove(
            request_id=self.request_id,
            device_secret=self.started["device_secret"], signature_b64=signed)
        self.store.lookup(user_code=self.started["user_code"],
                          operator_subject="auth0|operator")
        self.store.confirm(
            request_id=self.request_id, operator_subject="auth0|operator",
            confirmation=self.started["confirmation"])
        return stage_lab_candidate(
            self.store, self.request_id, sandbox_root=self.sandbox,
            trusted_gateway_host_public_key=self.keys["gateway_host"][1])

    def serve(self, uid=None):
        server = create_lab_approval_handoff(
            self.socket, self.protocol,
            allowed_uid=os.geteuid() if uid is None else uid)
        thr = threading.Thread(target=server.serve_forever, daemon=True)
        thr.start()
        def close():
            server.shutdown()
            thr.join(timeout=3)
            server.server_close()
            self.socket.unlink(missing_ok=True)
        self.addCleanup(close)

    def raw(self, data):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as con:
            con.connect(str(self.socket))
            con.sendall(json.dumps(data).encode() + b"\n")
            return json.loads(con.recv(4096))

    def test_only_staged_valid_approval_can_be_inspected(self):
        self.serve()
        self.assertEqual(stat.S_IMODE(self.socket.stat().st_mode), 0o600)
        self.assertEqual(inspect_candidate_over_unix(
            self.socket, request_id=self.request_id),
            {"ok": False, "error": "candidate_unavailable"})
        self.approve_and_stage()
        result = inspect_candidate_over_unix(
            self.socket, request_id=self.request_id)
        self.assertTrue(result["ok"])
        candidate = result["candidate"]
        self.assertEqual(candidate["access_mode"], "restricted")
        self.assertEqual(candidate["device_id"], "windows-wsl")
        self.assertEqual(candidate["persistent"], False)
        self.assertEqual(candidate["offer"]["reverse_listen_port"], 10003)
        self.assertEqual(candidate["host_public_key"], self.keys["device_host"][1])
        self.assertEqual(candidate["tunnel_public_key"], self.keys["tunnel"][1])
        self.assertNotIn("operator_subject", json.dumps(result))
        self.assertNotIn("device_secret", json.dumps(result))
        self.assertNotIn("confirmation", json.dumps(result))
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn(self.started["device_secret"], json.dumps(result))

    def test_root_peer_identity_cannot_be_forged_in_payload(self):
        self.approve_and_stage()
        self.serve(uid=os.geteuid() + 1)
        self.assertEqual(self.raw({
            "action": "inspect_staged_wsl", "request_id": self.request_id,
            "uid": os.geteuid() + 1}),
            {"ok": False, "error": "unauthorized_peer"})
        # A kernel-peer rejection may return the explicit denial OR close
        # with a reset before the client can send its complete request.
        # Both are fail-closed outcomes; only approved material would be a bug.
        try:
            denied = inspect_candidate_over_unix(
                self.socket, request_id=self.request_id)
        except (BrokenPipeError, ConnectionResetError):
            denied = {"ok": False, "error": "unauthorized_peer"}
        self.assertEqual(denied, {"ok": False, "error": "unauthorized_peer"})

    def test_rejects_all_other_actions_and_mutation_parameters(self):
        self.approve_and_stage()
        self.serve()
        for mutation in (
            {"port": 22}, {"access_mode": "unrestricted"}, {"key": "AAA"},
            {"device_id": "oracle-gateway"}, {"path": "/etc/sudoers"},
            {"command": "sudo -i"}, {"provisioner_verified": True},
        ):
            self.assertEqual(self.raw({
                "action": "inspect_staged_wsl", "request_id": self.request_id,
                **mutation}), {"ok": False, "error": "invalid_request"})
        for action in ("activate", "approve", "stage", "install", "exec"):
            self.assertEqual(self.raw({
                "action": action, "request_id": self.request_id
            }), {"ok": False, "error": "unsupported"})
        self.assertFalse(any(p.name == "mock-gateway" for p in self.sandbox.iterdir()))

    def test_expired_staged_approval_is_inaccessible(self):
        self.approve_and_stage()
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE sessions SET expires_at=1 WHERE request_id=?",
                       (self.request_id,))
        self.serve()
        self.assertEqual(inspect_candidate_over_unix(
            self.socket, request_id=self.request_id),
            {"ok": False, "error": "candidate_unavailable"})

    def test_socket_permissions_and_symlink_denial(self):
        self.runtime.chmod(0o777)
        with self.assertRaises(PermissionError):
            create_lab_approval_handoff(
                self.socket, self.protocol, allowed_uid=os.geteuid())
        self.runtime.chmod(0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(PermissionError):
            create_lab_approval_handoff(
                alias / "approval.sock", self.protocol, allowed_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
