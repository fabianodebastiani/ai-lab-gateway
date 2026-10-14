"""Fail-closed tests for narrow root-only persistence helper (no real sudo)."""
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load_helper():
    source = Path(__file__).resolve().parents[1] / "scripts" / "ai-lab-device-connectionctl"
    loader = SourceFileLoader("device_connectionctl_under_test", str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class HelperSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()

    def test_refuses_non_root(self):
        with patch.object(self.helper.os, "geteuid", return_value=1001):
            with self.assertRaises(PermissionError):
                self.helper.set_persistent("ai-lab-wsl-tunnel.service", "1")

    def test_refuses_non_tunnel_service_or_other_arguments(self):
        with patch.object(self.helper.os, "geteuid", return_value=0):
            for unit in ("ssh.service", "../ai-lab-foo-tunnel.service",
                         "ai-lab-a-tunnel.service;id"):
                with self.subTest(unit=unit):
                    with self.assertRaises(ValueError):
                        self.helper.set_persistent(unit, "1")
            for flag in ("True", "false", "yes", "2", ""):
                with self.subTest(flag=flag):
                    with self.assertRaises(ValueError):
                        self.helper.set_persistent("ai-lab-wsl-tunnel.service", flag)

    def test_refuses_non_root_owned_or_writable_systemd_unit(self):
        with patch.object(self.helper.os, "geteuid", return_value=0):
            for owner,mode in [(1001, stat.S_IFREG | 0o644),
                               (0, stat.S_IFREG | 0o664),
                               (0, stat.S_IFREG | 0o646)]:
                with patch.object(self.helper.Path, "stat",
                                  return_value=SimpleNamespace(st_uid=owner, st_mode=mode)):
                    with self.assertRaises(PermissionError):
                        self.helper.set_persistent("ai-lab-wsl-tunnel.service", "1")

    def test_only_enables_or_disables_exact_unit(self):
        with patch.object(self.helper.os, "geteuid", return_value=0):
            with patch.object(self.helper.Path, "stat", return_value=SimpleNamespace(
                st_uid=0, st_mode=stat.S_IFREG | 0o644
            )):
                with patch.object(self.helper.subprocess, "run",
                                  return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
                    self.assertEqual(self.helper.set_persistent("ai-lab-wsl-tunnel.service", "1"), 0)
                    self.assertEqual(run.call_args.args[0],
                                     ["/usr/bin/systemctl", "enable", "ai-lab-wsl-tunnel.service"])
                    self.assertFalse(run.call_args.kwargs["check"])
                    self.assertEqual(self.helper.set_persistent("ai-lab-wsl-tunnel.service", "0"), 0)
                    self.assertEqual(run.call_args.args[0],
                                     ["/usr/bin/systemctl", "disable", "ai-lab-wsl-tunnel.service"])

    def test_cli_fails_closed(self):
        self.assertEqual(self.helper.main(["prog", "shell"]), 2)


if __name__ == "__main__":
    unittest.main()
