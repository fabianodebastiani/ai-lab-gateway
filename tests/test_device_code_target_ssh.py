"""Non-root, mocked target SSH activation; no real tunnel or keys installed."""
import importlib.util
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "device_code_pair_linux.py"
spec = importlib.util.spec_from_file_location("client_target_activation", SCRIPT)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class TargetActivationTests(unittest.TestCase):
    def setUp(self):
        ctx = tempfile.TemporaryDirectory()
        self.addCleanup(ctx.cleanup)
        self.home = Path(ctx.name)
        self.ssh = self.home / ".ssh"
        self.ssh.mkdir(mode=0o700)
        self.state = self.ssh / "pairing"
        self.state.mkdir(mode=0o700)
        self.private = self.state / "tunnel-ed25519"
        self.private.write_bytes(b"not-a-real-test-key")
        self.private.chmod(0o600)
        # These are public constants, not credentials. Unit tests mock
        # ssh-keyscan and systemd-run so no network / device is changed.
        self.pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIArkQEjGi6HfiJlMeKv8yv3xf6XripB4npdSSnYWFGjA"
        self.other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPeSG8jn82luT8boqsgsvTbEJo9juin47Zd96kCmgx37"
        self.offer = {
            "device_id": "test-linux-001",
            "persistent": False,
            "access_mode": "restricted",
            "management_user": pwd.getpwuid(os.getuid()).pw_name,
            "gateway_host": "gateway.debasti.com",
            "gateway_tunnel_user": "tunnel",
            "gateway_ssh_host_key": self.pub,
            "gateway_management_public_key": self.other,
            "reverse_listen_port": 10003,
        }

    def activate(self, *, local_key=None, offer=None):
        with mock.patch.object(client.Path, "home", return_value=self.home), \
             mock.patch.object(client, "_active_target_sshd_key",
                               return_value=local_key or self.other), \
             mock.patch.object(client.subprocess, "run") as spawn:
            spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
            unit = client.activate_verified_on_demand_tunnel(
                offer=offer or self.offer, state_dir=self.state,
                tunnel_key_path=self.private,
                signed_host_public_key=self.other,
                gateway_host_pin=self.pub)
        return unit, spawn.call_args

    def test_existing_sshd_user_activates_loopback_only_without_root(self):
        old = self.ssh / "authorized_keys"
        old.write_text("ssh-ed25519 AAAAold old-comment\n")
        old.chmod(0o644)
        unit, invocation = self.activate()
        self.assertEqual(unit, "ai-lab-device-test-linux-001")
        self.assertEqual(stat.S_IMODE(old.stat().st_mode), 0o600)
        data = old.read_text()
        self.assertIn("AAAAold old-comment", data)
        self.assertIn(self.other, data)
        pin = self.state / "trusted-gateway-known_hosts"
        self.assertEqual(stat.S_IMODE(pin.stat().st_mode), 0o600)
        self.assertEqual(pin.read_text(), "gateway.debasti.com " + self.pub + "\n")
        argv = invocation.args[0]
        self.assertEqual(argv[0:2], ["systemd-run", "--user"])
        self.assertIn("127.0.0.1:10003:127.0.0.1:22", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)

    def test_wrong_active_sshd_key_rejects_before_any_write(self):
        with self.assertRaises(PermissionError):
            self.activate(local_key=self.pub)
        self.assertFalse((self.ssh / "authorized_keys").exists())

    def test_wrong_management_user_rejects(self):
        altered = dict(self.offer, management_user="not-current-user")
        with self.assertRaises(PermissionError):
            self.activate(offer=altered)
        self.assertFalse((self.ssh / "authorized_keys").exists())

    def test_no_persistent_or_elevated_mode_can_be_silently_started(self):
        for changes in ({"persistent": True}, {"access_mode": "unrestricted"}):
            with self.subTest(changes=changes):
                with self.assertRaises(PermissionError):
                    self.activate(offer=dict(self.offer, **changes))
        self.assertFalse((self.ssh / "authorized_keys").exists())

    def test_symlinked_authorized_keys_rejected(self):
        outside = self.home / "outside"
        outside.write_text("ssh-ed25519 AAAAold")
        (self.ssh / "authorized_keys").symlink_to(outside)
        with self.assertRaises(PermissionError):
            self.activate()
        self.assertEqual(outside.read_text(), "ssh-ed25519 AAAAold")

    def test_reused_offer_does_not_duplicate_management_public_key(self):
        self.activate()
        first = (self.ssh / "authorized_keys").read_text()
        self.activate()
        self.assertEqual(first, (self.ssh / "authorized_keys").read_text())


if __name__ == "__main__":
    unittest.main()
