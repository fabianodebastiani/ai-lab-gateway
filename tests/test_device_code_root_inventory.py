"""Auditor validates actual trusted runtime paths; never prints secrets."""
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from ai_lab_gateway.device_code_root_inventory import (
    extract_registry_path, parse_tunnel_authorized_keys_location,
    path_metadata, inspect_root_environment, report_to_json,
)


class RootInventoryTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)

    def test_defaults_are_only_used_without_real_runtime_override(self):
        self.assertEqual(str(extract_registry_path(b"SECRET_API_TOKEN=not-for-logs\x00")),
                         "/etc/ai-lab-gateway/devices.json")
        p = extract_registry_path(
            b"SECRET_API_TOKEN=HIDE_ME\x00"
            b"AI_LAB_DEVICE_REGISTRY=/etc/ai-lab-gateway/live-devices.json\x00")
        self.assertEqual(str(p), "/etc/ai-lab-gateway/live-devices.json")
        self.assertNotIn("HIDE_ME", str(p))

    def test_untrusted_registry_override_is_rejected(self):
        for env in (
            b"AI_LAB_DEVICE_REGISTRY=../../etc/passwd\x00",
            b"AI_LAB_DEVICE_REGISTRY=/etc/ai-lab-gateway/../sudoers\x00",
            b"AI_LAB_DEVICE_REGISTRY=/tmp/evil.json\x00",
            b"AI_LAB_DEVICE_REGISTRY=\x00",
            b"AI_LAB_DEVICE_REGISTRY=/etc/ai-lab-gateway/one\x00"
            b"AI_LAB_DEVICE_REGISTRY=/etc/ai-lab-gateway/two\x00",
            b"AI_LAB_DEVICE_REGISTRY=\xff\x00",
        ):
            with self.subTest(env=env), self.assertRaises(PermissionError):
                extract_registry_path(env)

    def test_sshd_file_list_resolves_tunnel_home_not_maintenance_home(self):
        sshd = (
            "allowtcpforwarding remote\n"
            "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2\n"
            "maxsessions 0\n")
        paths = parse_tunnel_authorized_keys_location(
            sshd, tunnel_home=Path("/var/lib/ai-lab-tunnel"))
        self.assertEqual(paths, (
            Path("/var/lib/ai-lab-tunnel/.ssh/authorized_keys"),
            Path("/var/lib/ai-lab-tunnel/.ssh/authorized_keys2")))
        self.assertEqual(parse_tunnel_authorized_keys_location(
            "authorizedkeysfile /etc/ssh/tunnel_keys\n",
            tunnel_home=Path("/var/lib/ai-lab-tunnel")),
            (Path("/etc/ssh/tunnel_keys"),))

    def test_unsupported_sshd_expansions_are_not_guessed(self):
        for line in (
            "authorizedkeysfile %h/.ssh/authorized_keys",
            "authorizedkeysfile none",
            "authorizedkeysfile ../outside",
            "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys",
            "authorizedkeysfile",
        ):
            with self.subTest(line=line), self.assertRaises(PermissionError):
                parse_tunnel_authorized_keys_location(
                    line + "\n", tunnel_home=Path("/var/lib/ai-lab-tunnel"))

    def test_missing_inaccessible_and_symlink_are_distinct(self):
        missing = path_metadata(self.root / "missing")
        self.assertEqual(missing["status"], "not_found_for_root")
        existing = self.root / "file"
        existing.write_text("SECRET_DO_NOT_PRINT")
        data = path_metadata(existing)
        self.assertEqual(data["status"], "exists")
        self.assertEqual(data["type"], "regular")
        self.assertNotIn("SECRET", json.dumps(data))
        symlink = self.root / "alias"
        symlink.symlink_to(existing)
        self.assertEqual(path_metadata(symlink)["type"], "symlink")

    def test_unprivileged_auditor_refuses_runtime_probes(self):
        with patch("ai_lab_gateway.device_code_root_inventory.os.geteuid",
                   return_value=1000):
            with self.assertRaises(PermissionError):
                inspect_root_environment()

    def test_mock_root_inventory_uses_live_config_and_outputs_only_metadata(self):
        registry = self.root / "registry.json"
        registry.write_text(json.dumps({
            "devices": [
                {"id": "raspberry-lab", "ssh_user": "ai-gateway",
                 "tunnel_port": 10001, "identity_file": "/root/keys/pi"},
                {"id": "windows-wsl", "ssh_user": "ai-gateway",
                 "tunnel_port": 10002, "identity_file": "/root/keys/wsl"},
            ],
            "secret": "TOP_SECRET_NOT_FOR_CHAT",
        }))
        registry.chmod(0o600)
        sshd = ("authorizedkeysfile .ssh/authorized_keys\n"
                "authenticationmethods publickey\n"
                "allowtcpforwarding remote\n"
                "gatewayports no\nmaxsessions 0\n"
                "passwordauthentication no\n")
        gateway_home = self.root / "gwhome"
        tunnel_home = self.root / "tunhome"
        gateway_home.mkdir()
        tunnel_home.mkdir()
        fake = {
            "ai-lab-gateway": SimpleNamespace(
                pw_uid=900, pw_gid=900, pw_dir=str(gateway_home)),
            "tunnel": SimpleNamespace(
                pw_uid=901, pw_gid=901, pw_dir=str(tunnel_home)),
        }

        with patch("ai_lab_gateway.device_code_root_inventory.os.geteuid",
                   return_value=0), \
             patch("ai_lab_gateway.device_code_root_inventory.pwd.getpwnam",
                   side_effect=lambda name: fake[name]), \
             patch("ai_lab_gateway.device_code_root_inventory._service_registry",
                   return_value=registry), \
             patch("ai_lab_gateway.device_code_root_inventory._run",
                   return_value=sshd):
            report = inspect_root_environment()
        safe = report_to_json(report)
        self.assertEqual(report["status"], "root_read_only_inventory")
        self.assertIn(str(registry), safe)
        self.assertIn(str(tunnel_home / ".ssh" / "authorized_keys"), safe)
        self.assertEqual(report["registry_devices"][1]["port"], 10002)
        self.assertNotIn("TOP_SECRET_NOT_FOR_CHAT", safe)

    def test_refuses_untrusted_report_format(self):
        with self.assertRaises(ValueError):
            report_to_json({"status": "SSH_CANDIDATE_DEPLOYED"})


if __name__ == "__main__":
    unittest.main()
