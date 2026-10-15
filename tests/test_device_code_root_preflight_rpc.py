"""Kernel UID and exact-action checks on the disabled root preflight service."""
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from ai_lab_gateway.device_code_root_preflight_rpc import (
    RootPreflightProtocol, create_lab_root_preflight_server,
    create_root_preflight_server, call_root_preflight,
)


class RootPreflightRPCTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.runtime = self.root / "private-run"
        self.runtime.mkdir(mode=0o700)
        self.socket = self.runtime / "preflight.sock"
        self.request = "ABCDEFGHIJKLMNOPQRSTUVWXyz"
        self.approval_calls = []
        self.probe_calls = []
        self.candidate = {"request_id": self.request, "approved": True}

        def approved(rid):
            self.approval_calls.append(rid)
            if rid != self.request:
                raise PermissionError("unknown request")
            return self.candidate

        def probe(candidate):
            self.probe_calls.append(candidate)
            return {
                "status": "candidate_preflight_ok", "port": 10003,
                "ssh_changed": False, "registry_changed": False,
            }
        self.protocol = RootPreflightProtocol(
            trusted_approval_reader=approved,
            trusted_environment_probe=probe)

    def serve(self, uid=None):
        server = create_lab_root_preflight_server(
            self.socket, self.protocol,
            allowed_uid=os.geteuid() if uid is None else uid)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        def stop():
            server.shutdown()
            worker.join(timeout=3)
            server.server_close()
            self.socket.unlink(missing_ok=True)
        self.addCleanup(stop)

    def call_raw(self, payload):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(self.socket))
            sock.sendall(json.dumps(payload).encode() + b"\n")
            return json.loads(sock.recv(512))

    def test_legitimate_kernel_uid_can_only_request_readonly_preflight(self):
        self.serve()
        self.assertEqual(stat.S_IMODE(self.socket.stat().st_mode), 0o600)
        self.assertEqual(call_root_preflight(self.socket, request_id=self.request), {
            "ok": True, "status": "preflight_only", "port": 10003,
            "access_mode": "restricted",
            "ssh_changed": False, "registry_changed": False,
        })
        self.assertEqual(self.approval_calls, [self.request])
        self.assertEqual(self.probe_calls, [self.candidate])

    def test_unknown_or_expired_approval_fails_without_preflight(self):
        self.serve()
        self.assertEqual(call_root_preflight(self.socket, request_id="Z" * 26),
                         {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(self.probe_calls, [])

    def test_wrong_uid_is_rejected_before_any_request_is_parsed(self):
        self.serve(uid=os.geteuid() + 1)
        self.assertEqual(call_root_preflight(self.socket, request_id=self.request),
                         {"ok": False, "error": "unauthorized_peer"})
        self.assertEqual(self.approval_calls, [])
        self.assertEqual(self.probe_calls, [])

    def test_caller_cannot_select_port_sudo_keys_approval_or_commands(self):
        self.serve()
        for forbidden in (
            {"port": 22}, {"path": "/etc/ssh/sshd_config"},
            {"sudo": True}, {"approved": True},
            {"command": "sudo -i"}, {"access_mode": "unrestricted"},
            {"management_public_key": "ssh-ed25519 attacker"},
        ):
            with self.subTest(forbidden=forbidden):
                self.assertEqual(self.call_raw({
                    "action": "preflight_wsl_candidate",
                    "request_id": self.request, **forbidden}),
                    {"ok": False, "error": "invalid_request"})
        for action in ("apply", "activate", "write_file", "prepare_keys", "root"):
            self.assertEqual(self.call_raw({
                "action": action, "request_id": self.request}),
                {"ok": False, "error": "unsupported"})
        self.assertEqual(self.approval_calls, [])

    def test_root_factory_does_not_operate_without_real_root(self):
        with patch("ai_lab_gateway.device_code_root_preflight_rpc.os.geteuid",
                   return_value=1000):
            with self.assertRaises(PermissionError):
                create_root_preflight_server()

    def test_symlinked_runtime_and_untrusted_dir_fail(self):
        self.runtime.chmod(0o777)
        with self.assertRaises(PermissionError):
            create_lab_root_preflight_server(
                self.socket, self.protocol, allowed_uid=os.geteuid())
        self.runtime.chmod(0o700)
        link = self.root / "alias"
        link.symlink_to(self.runtime, target_is_directory=True)
        with self.assertRaises(PermissionError):
            create_lab_root_preflight_server(
                link / "preflight.sock", self.protocol,
                allowed_uid=os.geteuid())

    def test_probe_must_report_readonly_success(self):
        unsafe = RootPreflightProtocol(
            trusted_approval_reader=lambda _: self.candidate,
            trusted_environment_probe=lambda _: {
                "status": "candidate_preflight_ok", "port": 10003,
                "ssh_changed": True, "registry_changed": False})
        self.assertEqual(unsafe.dispatch({
            "action": "preflight_wsl_candidate", "request_id": self.request}),
            {"ok": False, "error": "candidate_unavailable"})
        self.assertEqual(self.approval_calls, [])


if __name__ == "__main__":
    unittest.main()
