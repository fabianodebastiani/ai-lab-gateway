"""No network. SSH acceptance uses a fixed key, port, target and commands."""
import subprocess
import unittest
from unittest.mock import patch

from ai_lab_gateway.device_code_ssh_acceptance import (
    verify_wsl_ssh_acceptance, TUNNEL_PORT
)


class AcceptanceTests(unittest.TestCase):
    def test_exact_nonroot_ssh_identity_success(self):
        with patch(
            "ai_lab_gateway.device_code_ssh_acceptance.subprocess.run"
        ) as runner:
            runner.side_effect = [
                subprocess.CompletedProcess([], 0, "ai-gateway\n", ""),
                subprocess.CompletedProcess([], 0, "LAPTOP-5RJJ0KBM\n", ""),
            ]
            result = verify_wsl_ssh_acceptance()
        self.assertEqual(result, {
            "verified": True, "user": "ai-gateway",
            "hostname": "laptop-5rjj0kbm", "port": TUNNEL_PORT,
        })
        self.assertEqual(runner.call_count, 2)
        for call in runner.call_args_list:
            argv = call.args[0]
            self.assertEqual(argv[0], "/usr/bin/ssh")
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("ClearAllForwardings=yes", argv)
            self.assertIn("PasswordAuthentication=no", argv)
            self.assertIn("10003", argv)
            self.assertIn("ai-gateway@127.0.0.1", argv)
            self.assertNotIn("root@127.0.0.1", argv)
            self.assertIn("UserKnownHostsFile=/var/lib/ai-lab-gateway/.ssh/known_hosts", argv)
        self.assertEqual(runner.call_args_list[0].args[0][-1], "id -un")
        self.assertEqual(runner.call_args_list[1].args[0][-1], "hostname")

    def test_wrong_user_or_hostname_or_ssh_failure_is_denied(self):
        for a, b in [
            ((0, "root\n"), (0, "LAPTOP-5RJJ0KBM\n")),
            ((0, "ai-gateway\n"), (0, "other-host\n")),
            ((255, ""), (0, "LAPTOP-5RJJ0KBM\n")),
            ((0, "ai-gateway\n"), (255, "")),
        ]:
            with self.subTest(a=a, b=b):
                with patch(
                    "ai_lab_gateway.device_code_ssh_acceptance.subprocess.run"
                ) as runner:
                    runner.side_effect = [
                        subprocess.CompletedProcess([], a[0], a[1], ""),
                        subprocess.CompletedProcess([], b[0], b[1], ""),
                    ]
                    with self.assertRaises(PermissionError):
                        verify_wsl_ssh_acceptance()

    def test_missing_private_key_or_connection_error_is_denied(self):
        with patch(
            "ai_lab_gateway.device_code_ssh_acceptance.subprocess.run",
            side_effect=OSError("no key or network")
        ):
            with self.assertRaises(PermissionError):
                verify_wsl_ssh_acceptance()


if __name__ == "__main__":
    unittest.main()
