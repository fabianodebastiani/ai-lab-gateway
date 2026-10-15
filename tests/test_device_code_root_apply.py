"""Root apply RPC: exact action, no arbitrary SSH, sudo, or activation."""
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest

from ai_lab_gateway.device_code_root_apply import (
    RootApplyProtocol, _open_socket, reserved_wsl_candidate_port,
)


class RootApplyProtocolTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="ai-lab-candidate-rpc-")
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.runtime = self.root / "private"
        self.runtime.mkdir(mode=0o700)
        self.path = self.runtime / "apply.sock"
        self.request_id = "A" * 26
        self.seen = []

        def accepted(request_id):
            self.seen.append(request_id)
            if request_id != self.request_id:
                raise PermissionError("unapproved")
            return {"status": "candidate_ssh_staged", "port": 10003,
                    "registry_changed": False, "sudo_granted": False}
        self.protocol = RootApplyProtocol(accepted)

    def start(self, *, allowed_uid: int | None = None):
        sock = _open_socket(
            self.path, self.protocol, caller_uid=os.geteuid()
            if allowed_uid is None else allowed_uid,
            owner_uid=os.geteuid(), owner_gid=os.getegid(),
            directory_mode=0o700, socket_mode=0o600)
        worker = threading.Thread(target=sock.serve_forever, daemon=True)
        worker.start()
        def cleanup():
            sock.shutdown()
            worker.join(timeout=2)
            sock.server_close()
            self.path.unlink(missing_ok=True)
        self.addCleanup(cleanup)

    def raw(self, message):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.path))
            sock.sendall(json.dumps(message).encode() + b"\n")
            return json.loads(sock.recv(1024))

    def test_valid_request_gets_only_a_nonactivating_status(self):
        self.start()
        self.assertEqual(self.raw({
            "action": "apply_wsl_candidate", "request_id": self.request_id}), {
                "ok": True, "status": "ssh_candidate_staged", "port": 10003,
                "registry_changed": False, "sudo_granted": False,
                "activated": False,
            })
        self.assertEqual(self.seen, [self.request_id])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_peer_uid_mismatch_is_rejected_before_any_action(self):
        self.start(allowed_uid=os.geteuid() + 1)
        self.assertEqual(self.raw({
            "action": "apply_wsl_candidate", "request_id": self.request_id}),
            {"ok": False, "error": "unauthorized_peer"})
        self.assertEqual(self.seen, [])

    def test_caller_cannot_pass_port_keys_path_sudo_or_commands(self):
        self.start()
        for forbidden in (
            {"port": 10002}, {"device_id": "oracle-gateway"},
            {"path": "/etc/sudoers"}, {"key": "ssh-ed25519 AAAA"},
            {"sudo": True}, {"access_mode": "unrestricted"},
            {"confirmed": True}, {"test_interrupt_after": 1},
            {"command": "sh"}, {"registry": {}},
        ):
            with self.subTest(forbidden=forbidden):
                self.assertEqual(self.raw({
                    "action": "apply_wsl_candidate", "request_id": self.request_id,
                    **forbidden}), {"ok": False, "error": "invalid_request"})
        for action in ("exec", "activate", "revoke", "root", "recover",
                       "enable", "cutover", "grant_sudo"):
            self.assertEqual(self.raw({
                "action": action, "request_id": self.request_id}),
                {"ok": False, "error": "unsupported"})
        self.assertEqual(self.seen, [])

    def test_unknown_request_and_unsafe_result_fail_closed(self):
        self.start()
        self.assertEqual(self.raw({
            "action": "apply_wsl_candidate", "request_id": "B" * 26}),
            {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(self.seen, ["B" * 26])
        unsafe = RootApplyProtocol(lambda _: {
            "status": "candidate_ssh_staged", "port": 10003,
            "registry_changed": False, "sudo_granted": True})
        self.assertEqual(unsafe.dispatch({
            "action": "apply_wsl_candidate", "request_id": self.request_id}),
            {"ok": False, "error": "candidate_unavailable"})

    def test_request_must_be_opaque_identifier(self):
        self.start()
        for rid in (True, "X", "../" + "A" * 26, None, {}, " " * 26):
            self.assertEqual(self.raw({
                "action": "apply_wsl_candidate", "request_id": rid}),
                {"ok": False, "error": "invalid_request"})
        self.assertEqual(self.seen, [])

    def test_socket_refuses_unsafe_directory_and_symlink(self):
        self.runtime.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.start()
        self.runtime.chmod(0o700)
        link = self.root / "alternate"
        link.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(PermissionError):
            _open_socket(link / "apply.sock", self.protocol,
                         caller_uid=os.geteuid(), owner_uid=os.geteuid(),
                         owner_gid=os.getegid(), directory_mode=0o700,
                         socket_mode=0o600)


if __name__ == "__main__":
    unittest.main()
