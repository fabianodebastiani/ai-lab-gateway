"""Regression: Ubuntu sudo -l -U USER may return 0 for denied user.

The installer accepts ONLY a canonical, non-sudo denial. It must not
misclassify a no-sudo management user as privileged, and must continue to
reject real wildcard privileges or ambiguous sudo policy output.
"""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "scripts" / "ai_lab_prepare_linux_target.py"
spec = importlib.util.spec_from_file_location("ai_lab_nosudo_helper", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LocalSudoAccountTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        uid = self.home.stat().st_uid
        # Tests may run as runner UID0 in isolated root CI: use a synthetic
        # non-root uid and mock lstat only for the test home as needed.
        self.uid = uid or 17771
        self.account = types.SimpleNamespace(
            pw_uid=self.uid, pw_gid=self.uid,
            pw_shell="/bin/bash", pw_dir=str(self.home))

    def check(self, *, output, exit_code, stderr=""):
        info = self.home.stat()
        with patch.object(module.pwd, "getpwnam", return_value=self.account), \
             patch.object(module.Path, "lstat",
                          autospec=True, side_effect=lambda p: (
                              types.SimpleNamespace(st_mode=info.st_mode,
                                                    st_uid=self.uid)
                              if str(p) == str(self.home)
                              else p.stat())), \
             patch.object(module.subprocess, "run") as run:
            run.side_effect = [
                subprocess.CompletedProcess([], 0, "ai-gateway\n", ""),
                subprocess.CompletedProcess([], exit_code, output, stderr),
            ]
            result = module.inspect_existing_user()
        return result

    def test_no_sudo_denial_with_exit_zero_is_allowed(self):
        actual = self.check(
            output="User ai-gateway is not allowed to run sudo on ai-lab-experiments-01.\n",
            exit_code=0)
        self.assertEqual(actual.pw_shell, "/bin/bash")

    def test_denial_with_exit_one_is_allowed(self):
        self.check(output="User ai-gateway is not allowed to run sudo on hostname.\n",
                   exit_code=1)

    def test_real_sudo_grant_is_rejected(self):
        for output in [
            "Matching Defaults entries for ai-gateway on host:\n"
            "User ai-gateway may run the following commands on host:\n"
            "    (ALL : ALL) NOPASSWD: ALL\n",
            "User ai-gateway may run the following commands on host:\n"
            "    (root) /usr/bin/id\n",
            "User ai-gateway is not allowed to run sudo on host.\n"
            "User ai-gateway may run the following commands on host:\n"
            "    (ALL) ALL\n",
        ]:
            with self.subTest(output=output):
                with self.assertRaises(PermissionError):
                    self.check(output=output, exit_code=0)

    def test_ambiguous_policy_and_error_are_rejected(self):
        for output, rc, stderr in [
            ("", 0, ""),
            ("User ai-gateway is not allowed to run sudo on host.", 2, ""),
            ("User ai-gateway is not allowed to run sudo on host.", 0,
             "sudo: audit plugin failed"),
            ("User another-user is not allowed to run sudo on host.", 0, ""),
            ("User ai-gateway is not allowed to run sudo on host", 0, ""),
        ]:
            with self.subTest(output=output, rc=rc):
                with self.assertRaises(PermissionError):
                    self.check(output=output, exit_code=rc, stderr=stderr)


if __name__ == "__main__":
    unittest.main()
