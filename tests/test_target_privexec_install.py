"""Disposable-root tests only; never install target sudoers on CI host."""
import base64
import hashlib
import importlib.machinery
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
import secrets
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "install_target_privexec.py"
EXECUTOR = SOURCE.parent / "ai-lab-target-privexec"
loader = importlib.machinery.SourceFileLoader("test_target_bootstrap", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)


@unittest.skipUnless(os.geteuid() == 0, "root tests run only on ephemeral CI runner")
class LocalRootBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="isolated-target-bootstrap-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.device = "ai-lab-experiments-01-fd3dab34"
        local_id = self.base / "local-id"
        local_id.write_text(self.device + "\n")
        issuer = self.base / "synthetic-issuer"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(issuer)], check=True)
        self.pub = issuer.with_suffix(".pub")
        payload = self.pub.read_text().split()[1]
        raw = base64.b64decode(payload)
        self.fingerprint = "SHA256:" + base64.b64encode(
            hashlib.sha256(raw).digest()).decode().rstrip("=")
        self.config = self.base / "target-config"
        self.state = self.base / "target-state"
        self.installed = self.base / "libexec" / "ai-lab-target-privexec"
        self.installed.parent.mkdir()
        self.sudoers = self.base / "sudoers" / "90-ai-lab-target-privexec"
        self.sudoers.parent.mkdir()
        p = patch.multiple(mod, LOCAL_ID=local_id, CONFIG=self.config,
                           STATE=self.state, EXECUTOR_PATH=self.installed,
                           SUDOERS=self.sudoers)
        p.start()
        self.addCleanup(p.stop)
        q = patch.object(mod.pwd, "getpwnam",
                         return_value=SimpleNamespace(pw_uid=1002,
                                                      pw_dir="/home/ai-gateway"))
        q.start()
        self.addCleanup(q.stop)

    def install(self, *, apply=True):
        return mod.apply(self.device, self.pub, self.fingerprint, EXECUTOR,
                         check_only=not apply)

    def test_plan_is_non_mutating(self):
        self.assertIn("DRY_RUN_OK", self.install(apply=False))
        for path in (self.config, self.state, self.installed, self.sudoers):
            self.assertFalse(path.exists())

    def test_installs_only_fixed_validated_root_policy(self):
        self.assertEqual(hashlib.sha256(EXECUTOR.read_bytes()).hexdigest(),
                         mod.EXECUTOR_SHA256)
        message = self.install()
        self.assertIn("INSTALLED", message)
        self.assertEqual(self.installed.read_bytes(), EXECUTOR.read_bytes())
        self.assertEqual(stat.S_IMODE(self.installed.stat().st_mode), 0o755)
        self.assertEqual(self.config.joinpath("device-id").read_text().strip(),
                         self.device)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.sudoers.stat().st_mode), 0o440)
        self.assertNotIn(b"ALL) NOPASSWD: ALL", self.sudoers.read_bytes())
        self.assertIn(b'privexec ""', self.sudoers.read_bytes())
        self.assertIn("REVOKED", mod.revoke())
        self.assertFalse(self.sudoers.exists())
        self.assertTrue(self.installed.exists())  # remains inert

    def test_mismatch_and_tampering_fail_without_touching_sudoers(self):
        with self.assertRaises(PermissionError):
            mod.apply("raspberry-lab", self.pub, self.fingerprint, EXECUTOR,
                      check_only=False)
        with self.assertRaises(PermissionError):
            mod.apply(self.device, self.pub, "SHA256:wrong", EXECUTOR,
                      check_only=False)
        modified = self.base / "modified"
        modified.write_bytes(EXECUTOR.read_bytes() + b"# modified\n")
        with self.assertRaises(PermissionError):
            mod.apply(self.device, self.pub, self.fingerprint, modified,
                      check_only=False)
        self.assertFalse(self.sudoers.exists())

    def test_missing_libexec_created_and_rollback_removes_directory(self):
        # Real Ubuntu 24.04 minimal second Oracle has no /usr/local/libexec.
        self.installed.parent.rmdir()
        self.assertIn("DRY_RUN_OK", self.install(apply=False))
        self.assertFalse(self.installed.parent.exists())
        self.assertIn("INSTALLED", self.install())
        self.assertTrue(self.installed.parent.is_dir())
        self.assertEqual(stat.S_IMODE(self.installed.parent.stat().st_mode), 0o755)
        self.assertTrue(self.installed.is_file())

    def test_missing_libexec_failed_visudo_does_not_leave_root_directory(self):
        self.installed.parent.rmdir()
        with patch.object(mod.subprocess, "run",
                          return_value=subprocess.CompletedProcess(["visudo"], 1)):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.installed.parent.exists())
        self.assertFalse(self.sudoers.exists())
        self.assertFalse(self.state.exists())

    def test_existing_file_cannot_be_overwritten(self):
        self.install()
        installed_copy = self.installed.read_bytes()
        with self.assertRaises(FileExistsError):
            self.install()
        self.assertEqual(self.installed.read_bytes(), installed_copy)
        self.assertTrue(self.sudoers.exists())

    def test_failed_visudo_rolls_back_all_created_files(self):
        with patch.object(mod.subprocess, "run",
                          return_value=subprocess.CompletedProcess(["visudo"], 1)):
            with self.assertRaises(PermissionError):
                self.install()
        self.assertFalse(self.sudoers.exists())
        self.assertFalse(self.installed.exists())
        self.assertFalse(self.config.exists())
        self.assertFalse(self.state.exists())

    def test_symlinked_source_not_accepted(self):
        alternative = self.base / "link-to-source"
        alternative.symlink_to(EXECUTOR)
        with self.assertRaises(PermissionError):
            mod.apply(self.device, self.pub, self.fingerprint, alternative,
                      check_only=True)


if __name__ == "__main__":
    unittest.main()
