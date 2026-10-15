"""Recovery remains a separate root-console command, not a Gateway RPC."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/recover_device_code_root_candidate.py"
spec = importlib.util.spec_from_file_location("root_ssh_recovery_runner", SCRIPT)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class RecoveryEntryTests(unittest.TestCase):
    def test_recovery_cannot_execute_without_actual_root(self):
        with patch.object(runner.os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                runner.recover_supervised_candidate()

    def test_root_recovery_uses_only_fixed_gateway_identities_and_paths(self):
        seen = []
        accounts = {
            "tunnel": SimpleNamespace(pw_uid=21101, pw_gid=21102),
            "ai-lab-gateway": SimpleNamespace(pw_uid=21201, pw_gid=21202),
        }
        fixed_paths = object()

        def fixed(**kwargs):
            seen.append(("paths", kwargs))
            return fixed_paths

        def recover(paths):
            seen.append(("recover", paths))
            return True

        with patch.object(runner.os, "geteuid", return_value=0), \
             patch.object(runner.pwd, "getpwnam",
                          side_effect=lambda account: accounts[account]), \
             patch.object(runner, "production_paths", side_effect=fixed), \
             patch.object(runner, "recover_candidate_root_transaction",
                          side_effect=recover):
            self.assertIs(runner.recover_supervised_candidate(), True)
        self.assertEqual(seen, [
            ("paths", {"tunnel_uid": 21101, "tunnel_gid": 21102,
                       "gateway_uid": 21201, "gateway_gid": 21202}),
            ("recover", fixed_paths),
        ])

    def test_apply_socket_cannot_call_recovery_by_payload(self):
        from ai_lab_gateway.device_code_root_apply import RootApplyProtocol
        protocol = RootApplyProtocol(lambda _: {
            "status": "candidate_ssh_staged", "port": 10003,
            "registry_changed": False, "sudo_granted": False})
        for action in ("recover_wsl_10003", "rollback", "recover", "restore"):
            self.assertEqual(protocol.dispatch({
                "action": action, "request_id": "R" * 26}),
                {"ok": False, "error": "unsupported"})


if __name__ == "__main__":
    unittest.main()
