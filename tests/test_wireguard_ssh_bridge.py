"""Isolated tests for the optional WireGuard-to-loopback SSH bridge."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "render_wireguard_ssh_bridge.py"
SPEC = importlib.util.spec_from_file_location("wireguard_bridge_renderer", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WireGuardBridgeTests(unittest.TestCase):
    def test_renders_loopback_only_non_root_systemd_proxy(self):
        units = MODULE.render_units("lab-node-03", 11002, "10.77.0.4")
        socket = units["ai-lab-wg-lab-node-03.socket"]
        service = units["ai-lab-wg-lab-node-03.service"]
        self.assertIn("ListenStream=127.0.0.1:11002", socket)
        self.assertNotIn("ListenStream=0.0.0.0", socket)
        self.assertIn("Service=ai-lab-wg-lab-node-03.service", socket)
        self.assertIn("ExecStart=/usr/lib/systemd/systemd-socket-proxyd 10.77.0.4:22", service)
        self.assertIn("User=ai-lab-gateway", service)
        self.assertIn("NoNewPrivileges=yes", service)
        self.assertIn("Requires=wg-quick@wg0.service", service)
        self.assertNotIn("sudo", service)
        self.assertNotIn("systemctl enable", service)
        self.assertNotIn("WGPrivateKey", service)

    def test_rejects_shell_injection_and_invalid_ports(self):
        for device_id in ("../../evil", "test;echo", "UPPER", "trailing-", ""):
            with self.subTest(device_id=device_id):
                with self.assertRaises(ValueError):
                    MODULE.render_units(device_id, 11002, "10.77.0.4")
        for port in (0, 22, 1023, 65536, True):
            with self.subTest(port=port):
                with self.assertRaises(ValueError):
                    MODULE.render_units("lab-node", port, "10.77.0.4")

    def test_rejects_non_vpn_targets(self):
        for address in ("8.8.8.8", "127.0.0.1", "10.77.1.5",
                        "10.77.0.1", "10.77.0.0", "10.77.0.255",
                        "::1", "10.77.0.4;id"):
            with self.subTest(address=address):
                with self.assertRaises(ValueError):
                    MODULE.render_units("lab-node", 11002, address)
        with self.assertRaises(ValueError):
            MODULE.render_units("lab-node", 11002, "10.77.0.4", "0.0.0.0/0")

    def test_writes_drafts_only_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            units = MODULE.render_units("lab-node", 11002, "10.77.0.4")
            files = MODULE.write_units(units, root)
            self.assertEqual(len(files), 2)
            self.assertTrue(all(file.is_file() for file in files))
            self.assertIn("127.0.0.1:11002", (root / "ai-lab-wg-lab-node.socket").read_text())
            with self.assertRaises(FileExistsError):
                MODULE.write_units(units, root)
            self.assertEqual(len(list(root.iterdir())), 2)

    def test_distinct_devices_have_distinct_unit_names(self):
        a = MODULE.render_units("node-a", 11002, "10.77.0.4")
        b = MODULE.render_units("node-b", 11003, "10.77.0.5")
        self.assertTrue(set(a).isdisjoint(b))
        self.assertNotEqual(list(a.values())[0], list(b.values())[0])


if __name__ == "__main__":
    unittest.main()
