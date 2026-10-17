"""Rootless regression tests for hidden SSH stdin privilege voucher transport."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ai_lab_gateway.registry import Device
from ai_lab_gateway.ssh_exec import execute_privileged_one_use


DEVICE_ID = "ai-lab-experiments-01-fd3dab34"


def device(**updates):
    raw = dict(id=DEVICE_ID, name="Oracle E2E pilot", ssh_user="ai-gateway",
               tunnel_host="127.0.0.1", tunnel_port=11000,
               identity_file="/private/synthetic-device-ssh-key", enabled=True)
    raw.update(updates)
    return Device(**raw)


def voucher(**updates):
    permit = dict(version="ai-lab-privexec-one-v1",
                  device_id=DEVICE_ID,
                  subject="auth0|synthetic-subject",
                  operation="root-identity-check",
                  argv=["/usr/bin/id", "-u"],
                  nonce="a" * 64,
                  issued_at=100,
                  expires_at=160)
    permit.update(updates)
    return {"permit": permit, "signature": "SYNTHETIC_SIGNATURE_NOT_VALID"}


class VoucherPrivateTransport(unittest.TestCase):
    def test_fixed_ssh_argv_and_voucher_only_on_stdin(self):
        receipt = subprocess.CompletedProcess(args=[], returncode=0,
                                              stdout="0\n", stderr="")
        with patch("ai_lab_gateway.ssh_exec.subprocess.run", return_value=receipt) as run:
            result = execute_privileged_one_use(device(), voucher())
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "0\n")
        args, kwargs = run.call_args
        argv = args[0]
        self.assertEqual(argv[-1], "/usr/bin/sudo -n -- /usr/local/libexec/ai-lab-target-privexec")
        self.assertEqual(argv[-2], "--")
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("ai-gateway@127.0.0.1", argv)
        self.assertEqual(kwargs["input"].count("SYNTHETIC_SIGNATURE_NOT_VALID"), 1)
        self.assertEqual(json.loads(kwargs["input"]), voucher())
        self.assertNotIn("SYNTHETIC_SIGNATURE_NOT_VALID", " ".join(argv))
        self.assertEqual(kwargs["text"], True)
        self.assertLessEqual(kwargs["timeout"], 45)

    def test_reject_wrong_account_target_argv_and_operation_before_subprocess(self):
        bad = [
            (device(ssh_user="root"), voucher()),
            (device(tunnel_host="attacker.example"), voucher()),
            (device(tunnel_port=22), voucher()),
            (device(), voucher(device_id="raspberry-lab")),
            (device(), voucher(argv=["/bin/bash"])),
            (device(), voucher(operation="sudo-bash")),
            (device(), voucher(version="untrusted")),
        ]
        with patch("ai_lab_gateway.ssh_exec.subprocess.run") as cmd:
            for dev, permit in bad:
                with self.subTest(dev=dev,permit=permit):
                    with self.assertRaises(PermissionError):
                        execute_privileged_one_use(dev, permit)
            cmd.assert_not_called()

    def test_no_signed_voucher_explicitly_denied(self):
        with patch("ai_lab_gateway.ssh_exec.subprocess.run") as cmd:
            for value in (None, {}, {"permit": {}},
                          {"permit": {}, "signature": None}):
                with self.assertRaises(PermissionError):
                    execute_privileged_one_use(device(), value)
            cmd.assert_not_called()


if __name__ == "__main__":
    unittest.main()
