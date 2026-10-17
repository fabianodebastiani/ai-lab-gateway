"""Test the exact sudo policy accepted during idempotent Linux setup.

No actual sudoers, OS user, sshd, WSL or Oracle changes are made.
"""
import importlib.machinery
import importlib.util
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "ai_lab_prepare_linux_target.py"
loader = importlib.machinery.SourceFileLoader("restricted_local_prepare_test", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
target = importlib.util.module_from_spec(spec)
loader.exec_module(target)

ALLOW = """Matching Defaults entries for ai-gateway on labhost:
    env_reset, secure_path=/usr/bin, use_pty

User ai-gateway may run the following commands on labhost:
    (root) NOPASSWD: /usr/local/libexec/ai-lab-target-privexec ""
"""
DENY = "User ai-gateway is not allowed to run sudo on labhost.\n"


class ExactScopedSudoPolicyTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.home = Path(td.name)
        self.user = SimpleNamespace(
            pw_uid=1001, pw_gid=1001, pw_shell="/bin/bash", pw_dir=str(self.home))
        self.old_lstat = Path.lstat
        self.sudo_reply = subprocess.CompletedProcess([], 0, ALLOW, "")

    def with_policy(self, response, mode=0o755):
        self.sudo_reply = response
        def subprocess_run(argv, **kwargs):
            if argv[:2] == ["/usr/bin/id", "-nG"]:
                return subprocess.CompletedProcess(argv, 0, "ai-gateway\n", "")
            if argv[:3] == ["/usr/bin/sudo", "-n", "-l"]:
                return self.sudo_reply
            raise AssertionError(f"unexpected command {argv!r}")
        def fake_stat(path):
            name = str(path)
            if name.endswith("/etc/sudoers.d/90-ai-lab-target-privexec"):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0,
                                       st_gid=0, st_nlink=1)
            if name.endswith("/usr/local/libexec/ai-lab-target-privexec"):
                return SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0,
                                       st_gid=0, st_nlink=1)
            return self.old_lstat(path)
        return patch.object(target.pwd, "getpwnam", return_value=self.user), \
               patch.object(target.subprocess, "run", side_effect=subprocess_run), \
               patch.object(Path, "lstat", fake_stat)

    def test_paired_user_with_only_fixed_privexec_rule_is_accepted(self):
        p, q, r = self.with_policy(subprocess.CompletedProcess([], 0, ALLOW, ""))
        with p, q, r:
            self.assertIs(target.inspect_existing_user(), self.user)

    def test_clean_first_run_without_sudo_rule_is_accepted(self):
        p, q, r = self.with_policy(subprocess.CompletedProcess([], 0, DENY, ""))
        with p, q, r:
            self.assertIs(target.inspect_existing_user(), self.user)

    def test_wildcard_or_second_command_is_rejected(self):
        for unwanted in ('    (root) NOPASSWD: ALL\n',
                         '    (ALL) ALL\n',
                         '    (root) NOPASSWD: /usr/bin/id -u\n'):
            response = subprocess.CompletedProcess([], 0, ALLOW + unwanted, "")
            p, q, r = self.with_policy(response)
            with p, q, r, self.subTest(extra=unwanted):
                with self.assertRaises(PermissionError):
                    target.inspect_existing_user()

    def test_fails_closed_if_fixed_executor_file_has_writable_mode(self):
        p, q, r = self.with_policy(subprocess.CompletedProcess([], 0, ALLOW, ""), mode=0o777)
        with p, q, r:
            with self.assertRaises(PermissionError):
                target.inspect_existing_user()

    def test_malformed_local_sudo_output_fails_closed(self):
        p, q, r = self.with_policy(subprocess.CompletedProcess([], 0, "sudo works\n", ""))
        with p, q, r:
            with self.assertRaises(PermissionError):
                target.inspect_existing_user()


if __name__ == "__main__":
    unittest.main()
