"""Real-root *disposable* registry/ACL commit with rollback and no production IO."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_lab_gateway import device_code_root_generic_finalize as finish
from ai_lab_gateway.device_code_linux_plan import plan_generic_linux_enrollment


@unittest.skipUnless(os.geteuid() == 0, "requires root-only ephemeral CI runner")
class RootGenericActivationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="lab-root-enrollment-test-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.state = self.root / "journal"
        self.state.mkdir(mode=0o700)
        self.registry_file = self.root / "devices.json"
        self.policy_file = self.root / "authorization.json"
        self.registry = {"devices": [
            {"id": "windows-wsl", "name": "WSL",
             "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
             "tunnel_port": 10002, "identity_file": "/keys/old"}
        ]}
        self.policy = {"users": [
            {"subject": "auth0|trusted-owner",
             "devices": {"windows-wsl": ["status", "exec"]}},
            {"subject": "auth0|guest", "devices": {}},
        ]}
        self._write_initial(self.registry_file, self.registry)
        self._write_initial(self.policy_file, self.policy)
        publics = []
        for i in range(4):
            key = self.root / ("test-key-" + str(i))
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                            "-N", "", "-f", str(key)],
                           check=True, capture_output=True, timeout=8)
            publics.append(" ".join(key.with_suffix(".pub").read_text().split()[:2]))
        candidate = {
            "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
            "device_id": "ai-lab-experiments-01-aabbccdd",
            "device_name": "ai-lab-experiments-01",
            "operator_subject": "auth0|trusted-owner",
            "tunnel_public_key": publics[0],
            "host_public_key": publics[1],
            "persistent": False,
            "expires_at": 9999999999,
        }
        offer, _, _ = plan_generic_linux_enrollment(
            approved_candidate=candidate, registry=self.registry,
            policy=self.policy, reserved_ports=(),
            gateway_ssh_host_key=publics[2],
            gateway_management_public_key=publics[3])
        self.candidate = {**candidate, "offer": offer}

    def _write_initial(self, path, value):
        path.write_text(json.dumps(value, sort_keys=True) + "\n")
        path.chmod(0o640)

    def _call(self, socket_path, data):
        if data["action"] == "inspect_staged":
            return {"candidate": self.candidate}
        if data["action"] == "mark_active":
            return {"result": {"status": "active"}}
        raise AssertionError(data["action"])

    def _environment(self, *, rpc=None):
        from contextlib import ExitStack
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(finish, "ROOT_STATE", self.state))
        stack.enter_context(patch.object(finish, "LOCK", self.state / "finalize.lock"))
        stack.enter_context(patch.object(finish, "JOURNAL", self.state / "finalize.json"))
        stack.enter_context(patch.object(finish, "PROD_REGISTRY", self.registry_file))
        stack.enter_context(patch.object(finish, "POLICY_PATH", self.policy_file))
        stack.enter_context(patch.object(finish, "root_handoff_call",
                                         side_effect=rpc or self._call))
        return stack

    def test_root_commit_is_restricted_and_preserves_old_device(self):
        self._environment()
        reply = finish._commit_active(self.candidate, gateway_gid=0)
        self.assertEqual(reply["status"], "active")
        self.assertFalse((self.state / "finalize.json").exists())
        reg = json.loads(self.registry_file.read_text())
        pol = json.loads(self.policy_file.read_text())
        self.assertEqual(reg["devices"][0], self.registry["devices"][0])
        self.assertEqual(reg["devices"][1]["tunnel_port"], 11000)
        self.assertEqual(reg["devices"][1]["ssh_user"], "ai-gateway")
        self.assertEqual(
            pol["users"][0]["devices"][self.candidate["device_id"]],
            ["status", "exec", "read_file", "write_file"])
        self.assertEqual(pol["users"][1], self.policy["users"][1])

    def test_failed_active_mark_rolls_back_both_files(self):
        def fail_mark(socket_path, msg):
            if msg["action"] == "mark_active":
                raise PermissionError("device approval expired")
            return self._call(socket_path, msg)
        self._environment(rpc=fail_mark)
        self.assertRaises(
            PermissionError, finish._commit_active,
            self.candidate, gateway_gid=0)
        self.assertEqual(json.loads(self.registry_file.read_text()), self.registry)
        self.assertEqual(json.loads(self.policy_file.read_text()), self.policy)
        self.assertFalse((self.state / "finalize.json").exists())

    def test_unrecovered_journal_blocks_activation(self):
        self._environment()
        (self.state / "finalize.json").write_text("pending")
        self.assertRaises(
            PermissionError, finish._commit_active,
            self.candidate, gateway_gid=0)
        self.assertEqual(json.loads(self.registry_file.read_text()), self.registry)
        self.assertEqual(json.loads(self.policy_file.read_text()), self.policy)


if __name__ == "__main__":
    unittest.main()
