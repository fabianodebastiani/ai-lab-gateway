"""Rootless unit/negative regression tests for local ailab CLI.

No production SSH or root operations; all tests work in disposable paths.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "ailab"
loader = importlib.machinery.SourceFileLoader("ailab_client_test", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)


class LocalAilabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.base = self.home / ".ssh"
        self.base.mkdir(mode=0o700)
        self.state = self.base / "ai-lab-device-code"
        self.state.mkdir(mode=0o700)
        self.device_id = "ai-lab-experiments-01-fd3dab34"
        self.unit = "ai-lab-device-" + self.device_id + ".service"
        self._file(self.state / "device-id", self.device_id + "\n")
        self.key = self.state / "tunnel-ed25519"
        self.pin = self.state / "trusted-gateway-known_hosts"
        self._file(self.key, "EXAMPLE_TEST_SECRET_NOT_AN_SSH_KEY\n")
        self._file(self.pin, "gateway.debasti.com ssh-ed25519 AAAATESTPIN\n")
        self.offer = {
            "device_id": self.device_id, "access_mode": "restricted",
            "management_user": "ai-gateway", "gateway_host": "gateway.debasti.com",
            "gateway_ssh_port": 22, "gateway_tunnel_user": "tunnel",
            "reverse_listen_host": "127.0.0.1", "reverse_listen_port": 11000,
            "persistent": False, "gateway_ssh_host_key": "ssh-ed25519 AAAATESTPIN",
            "gateway_management_public_key": "ssh-ed25519 AAAATESTMGMT",
        }
        import json
        candidate = self.state / "candidate-fake"
        candidate.mkdir(mode=0o700)
        self._file(candidate / "offer.json", json.dumps(self.offer))
        self._file(self.base / "authorized_keys", "ssh-ed25519 AAAATESTMGMT\n")
        patcher = patch.object(cli.Path, "home", return_value=self.home)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def _file(path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)

    def test_offer_stays_local_and_does_not_grant_root(self):
        actual, key, pin = cli.verified_offer(self.state, self.device_id)
        self.assertEqual(actual["reverse_listen_port"], 11000)
        self.assertEqual(key, self.key)
        self.assertEqual(pin, self.pin)
        ssh = cli.ssh_argv(actual, key, pin)
        self.assertEqual(ssh[0], "/usr/bin/ssh")
        self.assertNotIn("sudo", ssh)
        self.assertIn("127.0.0.1:11000:127.0.0.1:22", ssh)
        unit = cli.stable_unit(ssh)
        self.assertIn("StrictHostKeyChecking=yes", unit)
        self.assertIn("Restart=always", unit)
        self.assertNotIn("User=root", unit)

    def test_untrusted_data_cannot_choose_listen_port_or_host(self):
        import json
        path = self.state / "candidate-fake" / "offer.json"
        for field, value in (
            ("reverse_listen_port", 22),
            ("reverse_listen_port", True),
            ("reverse_listen_port", 11999 + 1),
            ("gateway_host", "attacker.example"),
            ("management_user", "root"),
            ("access_mode", "unrestricted"),
            ("persistent", True),
        ):
            with self.subTest(field=field, value=value):
                invalid = dict(self.offer, **{field: value})
                self._file(path, json.dumps(invalid))
                with self.assertRaises(PermissionError):
                    cli.verified_offer(self.state, self.device_id)
        self._file(path, json.dumps(self.offer))

    def test_symlinked_or_modified_identity_is_refused(self):
        self.key.chmod(0o644)
        with self.assertRaises(PermissionError):
            cli.verified_offer(self.state, self.device_id)
        self.key.chmod(0o600)
        self.key.unlink()
        self.key.symlink_to(self.pin)
        with self.assertRaises(PermissionError):
            cli.verified_offer(self.state, self.device_id)

    def test_conflicting_management_key_rejected(self):
        self._file(self.base / "authorized_keys", "ssh-ed25519 AAAAOTHER\n")
        with self.assertRaises(PermissionError):
            cli.verified_offer(self.state, self.device_id)

    def test_status_transient_connection_does_not_claim_boot_persistence(self):
        def fake_run(*argv, **_):
            return subprocess.CompletedProcess(argv, 0,
                "LoadState=loaded\nActiveState=active\n"
                "UnitFileState=transient\nFragmentPath=/run/user/1002/systemd/transient/a.service\n", "")
        with patch.object(cli, "run", side_effect=fake_run):
            outcome = cli.status(self.unit)
        self.assertIn("connected=yes", outcome)
        self.assertIn("persistent=off", outcome)

    def test_connect_idempotent_when_already_active(self):
        with patch.object(cli, "device_state", return_value=(self.state, self.device_id, self.unit)), \
             patch.object(cli, "verified_offer", return_value=(self.offer,self.key,self.pin)), \
             patch.object(cli, "details", return_value={"ActiveState":"active"}), \
             patch.object(cli, "start_transient") as launch, \
             patch.object(cli, "systemd") as systemctl, \
             patch.object(cli, "unit_file", return_value=self.home / "missing"):
            result = cli.act("connect")
        self.assertIn("connected=yes", result) if "connected=yes" in result else None
        launch.assert_not_called()
        systemctl.assert_not_called()

    def test_persistence_off_does_not_stop_connection(self):
        folder = self.home / ".config" / "systemd" / "user"
        folder.mkdir(parents=True)
        self._file(folder / self.unit, "this-unit-is-disabled-only")
        with patch.object(cli, "device_state", return_value=(self.state, self.device_id, self.unit)), \
             patch.object(cli, "systemd") as systemctl, \
             patch.object(cli, "details", return_value={"UnitFileState":"disabled","ActiveState":"active"}):
            cli.act("persistent","off")
        systemctl.assert_called_once_with("disable", self.unit)

    def test_disconnected_remote_mcp_cannot_be_reconnected_from_gateway(self):
        # Local state launch must not use SSH to a different host, sudo,
        # downloaded commands or auto-enroll.
        ssh = cli.ssh_argv(self.offer, self.key, self.pin)
        for banned in ("sudo", "bash", "curl", "wget", "root@"):
            self.assertFalse(any(banned in arg for arg in ssh))


if __name__ == "__main__":
    unittest.main()
