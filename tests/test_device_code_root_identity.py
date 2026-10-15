"""Real root-only SSH identity setup in a disposable CI-owned directory."""
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ai_lab_gateway.device_code_root_identity import (
    prepare_wsl_management_identity, verify_wsl_management_identity,
    PILOT, PRIVATE, PUBLIC,
)


@unittest.skipUnless(os.geteuid() == 0, "requires disposable UID-0 CI runner")
class RootCandidateIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ai-lab-identity-CI-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.group_gid = 21321
        self.base = self.root / "only-identity"
        self.base.mkdir(mode=0o750)
        os.chown(self.base, 0, self.group_gid)
        self.legacy = self.root / "legacy-10002"
        self.legacy.write_text("old identity preserved")

    def prepare(self):
        return prepare_wsl_management_identity(
            group_gid=self.group_gid, base=self.base)

    def test_root_creates_independent_atomic_keypair_only_once(self):
        result = self.prepare()
        self.assertEqual(result["status"], "root_candidate_identity_prepared")
        self.assertEqual(result["port"], 10003)
        self.assertFalse(result["ssh_activated"])
        self.assertFalse(result["registry_changed"])
        dest = self.base / PILOT
        info = dest.lstat()
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_gid, self.group_gid)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o750)
        for name in (PRIVATE, PUBLIC):
            path = dest / name
            info = path.lstat()
            self.assertEqual(info.st_uid, 0)
            self.assertEqual(info.st_gid, self.group_gid)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o640)
        self.assertIn("BEGIN OPENSSH PRIVATE KEY", (dest / PRIVATE).read_text())
        self.assertEqual(verify_wsl_management_identity(
            group_gid=self.group_gid, base=self.base), result["public_key"])
        self.assertEqual(self.legacy.read_text(), "old identity preserved")
        with self.assertRaises(FileExistsError):
            self.prepare()

    def test_wrong_root_folder_owner_or_mode_is_rejected(self):
        self.base.chmod(0o770)
        with self.assertRaises(PermissionError):
            self.prepare()
        self.base.chmod(0o750)
        os.chown(self.base, 0, 21444)
        with self.assertRaises(PermissionError):
            self.prepare()
        self.assertFalse((self.base / PILOT).exists())

    def test_root_uid_is_mandatory(self):
        with patch("ai_lab_gateway.device_code_root_identity.os.geteuid",
                   return_value=22020):
            with self.assertRaises(PermissionError):
                self.prepare()
        self.assertFalse((self.base / PILOT).exists())

    def test_corrupted_or_swapped_public_key_fails_verification(self):
        self.prepare()
        pub = self.base / PILOT / PUBLIC
        before = pub.read_bytes()
        pub.write_text("ssh-ed25519 not-a-key")
        with self.assertRaises((PermissionError, ValueError)):
            verify_wsl_management_identity(
                group_gid=self.group_gid, base=self.base)
        pub.write_bytes(before)
        pub.chmod(0o666)
        with self.assertRaises(PermissionError):
            verify_wsl_management_identity(
                group_gid=self.group_gid, base=self.base)

    def test_symlinked_final_dir_cannot_be_adopted_as_candidate(self):
        alias = self.base / PILOT
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            self.prepare()
        with self.assertRaises(PermissionError):
            verify_wsl_management_identity(group_gid=self.group_gid, base=self.base)
        self.assertEqual(self.legacy.read_text(), "old identity preserved")


if __name__ == "__main__":
    unittest.main()
