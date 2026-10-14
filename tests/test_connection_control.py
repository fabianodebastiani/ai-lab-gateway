"""Tests for per-device boolean persistence, online state and safe sudo routing."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ai_lab_gateway.connection_control import (
    persistent_flag, read_connection, unit_for, update_persistent_flag,
)
from ai_lab_gateway.registry import Device, DeviceRegistry
from ai_lab_gateway.ssh_exec import CommandResult


def device(unit="ai-lab-wsl-tunnel.service"):
    return Device(
        id="windows-wsl", name="WSL", ssh_user="ai-gateway",
        tunnel_host="127.0.0.1", tunnel_port=10002,
        identity_file="/keys/windows-wsl", connection_unit=unit,
    )


class ConnectionFlagTests(unittest.TestCase):
    def test_boolean_flag_not_a_device_type(self):
        self.assertTrue(persistent_flag(True))
        self.assertFalse(persistent_flag(False))
        for invalid in (0, 1, "true", "false", None):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    persistent_flag(invalid)

    def test_legacy_device_lacks_unit_until_explicitly_configured(self):
        with self.assertRaises(ValueError):
            unit_for(device(None))

    def test_reject_invalid_unit_from_registry(self):
        for bad in ("ssh.service", "ai-lab-wsl-tunnel.service; sudo id",
                    "../ai-lab-wsl-tunnel.service", True, ""):
            with self.subTest(bad=bad):
                with tempfile.TemporaryDirectory() as tmp:
                    data = {
                        "devices": [{
                            "id": "windows-wsl", "name": "WSL",
                            "ssh_user": "ai-gateway",
                            "tunnel_host": "127.0.0.1",
                            "tunnel_port": 10002,
                            "identity_file": "/keys/wsl",
                            "connection_unit": bad,
                        }]
                    }
                    path = Path(tmp) / "registry.json"
                    path.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        DeviceRegistry.load(path)

    def test_registered_unit_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            path.write_text(json.dumps({"devices": [{
                "id": "windows-wsl", "name": "WSL", "ssh_user": "ai-gateway",
                "tunnel_host": "127.0.0.1", "tunnel_port": 10002,
                "identity_file": "/keys/wsl",
                "connection_unit": "ai-lab-wsl-tunnel.service"
            }]}))
            self.assertEqual(
                DeviceRegistry.load(path).get("windows-wsl").connection_unit,
                "ai-lab-wsl-tunnel.service",
            )

    def test_on_demand_can_be_online(self):
        with patch("ai_lab_gateway.connection_control.execute",
                   return_value=CommandResult(
                       "ActiveState=active\nUnitFileState=disabled\n", "", 0
                   )) as mock:
            state = read_connection(device())
            self.assertTrue(state.connected)
            self.assertFalse(state.persistent)
            self.assertEqual(state.detail, "ok")
            self.assertIn("systemctl show", mock.call_args.args[1])

    def test_persistent_can_be_offline(self):
        with patch("ai_lab_gateway.connection_control.execute",
                   return_value=CommandResult(
                       "ActiveState=inactive\nUnitFileState=enabled\n", "", 0
                   )):
            state = read_connection(device())
            self.assertFalse(state.connected)
            self.assertTrue(state.persistent)

    def test_unreachable_is_not_confused_with_persistent_false(self):
        with patch("ai_lab_gateway.connection_control.execute",
                   return_value=CommandResult("", "Connection refused", 255)):
            state = read_connection(device())
            self.assertFalse(state.connected)
            self.assertIsNone(state.persistent)

    def test_unknown_enabled_state_fails_closed(self):
        with patch("ai_lab_gateway.connection_control.execute",
                   return_value=CommandResult(
                       "ActiveState=active\nUnitFileState=bogus\n", "", 0
                   )):
            with self.assertRaises(RuntimeError):
                read_connection(device())

    def test_narrow_command_sets_boolean_only(self):
        for flag, expected in ((True, "1"), (False, "0")):
            calls = []
            def fake_execute(dev, command, timeout):
                calls.append(command)
                if command.startswith("sudo -n"):
                    return CommandResult("", "", 0)
                return CommandResult(
                    "ActiveState=active\nUnitFileState=" +
                    ("enabled\n" if flag else "disabled\n"), "", 0
                )
            with patch("ai_lab_gateway.connection_control.execute",
                       side_effect=fake_execute):
                state = update_persistent_flag(device(), flag)
            self.assertIs(state.persistent, flag)
            self.assertEqual(calls[0],
                "sudo -n /usr/local/libexec/ai-lab-device-connectionctl "
                "set-persistent ai-lab-wsl-tunnel.service " + expected)
            self.assertNotIn("systemctl stop", " ".join(calls))

    def test_failed_sudo_does_not_claim_success(self):
        with patch("ai_lab_gateway.connection_control.execute",
                   return_value=CommandResult("", "password required", 1)):
            with self.assertRaises(RuntimeError):
                update_persistent_flag(device(), True)

    def test_wrong_readback_fails(self):
        values = [
            CommandResult("", "", 0),
            CommandResult("ActiveState=active\nUnitFileState=disabled\n", "", 0),
        ]
        with patch("ai_lab_gateway.connection_control.execute",
                   side_effect=values):
            with self.assertRaises(RuntimeError):
                update_persistent_flag(device(), True)


if __name__ == "__main__":
    unittest.main()
