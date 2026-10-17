"""Local target setup: only local admin and no-sudo user; no real changes."""
import importlib.util
from pathlib import Path
import pwd
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ai_lab_prepare_linux_target.py"
spec = importlib.util.spec_from_file_location("ai_lab_target_setup_test", SCRIPT)
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class TargetLocalSetupTests(unittest.TestCase):
    def test_no_root_no_changes(self):
        with patch.object(setup.os, "geteuid", return_value=1000), \
             patch.object(setup, "command") as run:
            with self.assertRaises(PermissionError):
                setup.prepare()
        run.assert_not_called()

    def test_existing_target_user_cannot_be_privileged(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d)
            fake = types.SimpleNamespace(
                pw_uid=home.stat().st_uid or 1000,
                pw_gid=1000, pw_shell="/bin/bash", pw_dir=str(home))
            with patch.object(setup.pwd, "getpwnam", return_value=fake), \
                 patch.object(setup.subprocess, "run",
                              return_value=subprocess.CompletedProcess(
                                  [], 0, "ai-gateway sudo\n", "")), \
                 patch.object(setup.Path, "is_file", return_value=False):
                with self.assertRaises(PermissionError):
                    setup.inspect_existing_user()

    def test_setup_command_never_receives_remote_requested_values(self):
        with patch.object(setup.os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                setup.prepare()
        self.assertEqual(setup.USER, "ai-gateway")
        self.assertNotIn("sudo", setup.USER)
        self.assertNotIn("docker", (setup.USER,))
        self.assertEqual(setup.REQUIRED_HOST,
                         Path("/etc/ssh/ssh_host_ed25519_key.pub"))


if __name__ == "__main__":
    unittest.main()
