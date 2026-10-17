"""Root handoff tests: one UID boundary, approved-state and schema denial."""
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest

from ai_lab_gateway.device_code_root_handoff import (
    ProvisionHandoff, create_root_handoff,
)


class FakeStore:
    def __init__(self):
        self.published = []
        self.activated = []

    def list_approved_request_ids(self):
        return ["ABCDEFGHIJKLMNOPQRSTUVWX"]

    def approved_root_snapshot(self, *, request_id):
        if request_id != "ABCDEFGHIJKLMNOPQRSTUVWX":
            raise PermissionError("expired or absent")
        return {"request_id": request_id, "device_id": "isolated-linux",
                "persistent": False, "operator_subject": "auth0|owner",
                "device_name": "isolated linux",
                "tunnel_public_key": "public-only", "host_public_key": "public-only"}

    def stage_connection_offer(self, *, request_id, offer,
                               trusted_gateway_host_public_key,
                               provisioner_verified):
        if not provisioner_verified:
            raise PermissionError("not privileged")
        self.published.append((request_id, offer, trusted_gateway_host_public_key))
        return {"status": "candidate_staged", "access_mode": "restricted"}

    def staged_candidate_snapshot(self, *, request_id):
        if not self.published or self.published[-1][0] != request_id:
            raise PermissionError("not staged")
        return {"device_id": "isolated-linux"}

    def activate(self, *, request_id, provisioner_verified):
        if not provisioner_verified:
            raise PermissionError("not privileged")
        self.activated.append(request_id)
        return {"status": "active", "access_mode": "restricted"}


class HandoffTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.folder.chmod(0o711)
        self.path = self.folder / "provision.sock"
        self.fake = FakeStore()

    def serve(self, allowed_uid):
        server = create_root_handoff(self.path, self.fake, root_uid=allowed_uid)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        self.addCleanup(server.server_close)
        self.addCleanup(t.join, 3)
        self.addCleanup(server.shutdown)
        return server

    def rpc(self, data):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(str(self.path))
            sock.sendall(json.dumps(data).encode() + b"\n")
            return json.loads(sock.recv(8192))

    def test_kernel_peer_uid_denied_before_request(self):
        self.serve(allowed_uid=os.geteuid() + 10000)
        self.assertEqual(self.rpc({"action": "list_approved"}),
                         {"ok": False, "error": "unauthorized_peer"})
        self.assertEqual(self.fake.published, [])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_root_allowed_path_only_and_one_time_session_state(self):
        self.serve(allowed_uid=os.geteuid())  # UID 0 in production
        self.assertEqual(self.rpc({"action": "list_approved"}),
                         {"ok": True, "requests": ["ABCDEFGHIJKLMNOPQRSTUVWX"]})
        approved = self.rpc({"action": "inspect_approved",
                             "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        self.assertEqual(approved["candidate"]["operator_subject"], "auth0|owner")
        rid = "ABCDEFGHIJKLMNOPQRSTUVWX"
        self.assertEqual(self.rpc({"action": "mark_active", "request_id": rid}),
                         {"ok": False, "error": "candidate_unavailable"})
        offer = {"version": "lab-only"}
        published = self.rpc({"action": "publish_offer",
                              "request_id": rid, "offer": offer,
                              "gateway_ssh_host_key": "test-public-host"})
        self.assertTrue(published["ok"])
        self.assertEqual(self.fake.published, [(rid, offer, "test-public-host")])
        self.assertEqual(self.rpc({"action": "mark_active",
                                   "request_id": rid})["result"]["status"], "active")

    def test_no_arbitrary_root_commands_or_client_supplied_identity(self):
        self.serve(allowed_uid=os.geteuid())
        bad = [
            {"action": "shell", "command": "id"},
            {"action": "list_approved", "command": "id"},
            {"action": "inspect_approved", "request_id": "short"},
            {"action": "inspect_approved",
             "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX", "sudo": True},
            {"action": "publish_offer", "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
             "offer": {}, "gateway_ssh_host_key": "pub", "path": "/etc/shadow"},
            {"action": "mark_active", "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
             "provisioner_verified": True},
        ]
        for item in bad:
            with self.subTest(item=item):
                self.assertFalse(self.rpc(item)["ok"])
        self.assertEqual(self.fake.published, [])

    def test_bad_socket_directory_or_existing_socket_refused(self):
        self.folder.chmod(0o700)
        with self.assertRaises(PermissionError):
            create_root_handoff(self.path, self.fake, root_uid=os.geteuid())
        self.folder.chmod(0o711)
        self.path.write_text("foreign file")
        with self.assertRaises(PermissionError):
            create_root_handoff(self.path, self.fake, root_uid=os.geteuid())


if __name__ == "__main__":
    unittest.main()
