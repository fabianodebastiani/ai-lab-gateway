"""Root-only CI tests in disposable directories; NEVER production SSH paths."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

from ai_lab_gateway.device_code_root_transaction import (
    RootSSHPaths, InterruptedRootTransaction, apply_candidate_root_transaction,
    recover_candidate_root_transaction, JOURNAL, AUDIT,
)


@unittest.skipUnless(os.geteuid() == 0, "requires real root in ephemeral CI runner")
class RealRootCandidateTransactionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ai-lab-root-ssh-CI-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.journal = self.root / "journal"
        self.journal.mkdir(mode=0o700)
        # Separate synthetic identities exercise actual fchown/fchmod.
        self.tunnel_uid = 21011
        self.gateway_uid = 21012
        self.tunnel = self.root / "tunnel"
        self.gateway = self.root / "gateway"
        self.tunnel.mkdir(mode=0o700)
        self.gateway.mkdir(mode=0o700)
        os.chown(self.tunnel, self.tunnel_uid, self.tunnel_uid)
        os.chown(self.gateway, self.gateway_uid, self.gateway_uid)
        self.auth = self.tunnel / "authorized_keys"
        self.known = self.gateway / "known_hosts"
        self.legacy_auth = b'permitlisten="127.0.0.1:10002" ssh-ed25519 LEGACY\n'
        self.legacy_known = b'[127.0.0.1]:10002 ssh-ed25519 LEGACY\n'
        for p, data, uid in ((self.auth, self.legacy_auth, self.tunnel_uid),
                             (self.known, self.legacy_known, self.gateway_uid)):
            p.write_bytes(data)
            p.chmod(0o600)
            os.chown(p, uid, uid)
        self.registry = self.root / "devices.json"
        self.registry.write_text('{"devices":[{"id":"windows-wsl","tunnel_port":10002}]}')
        self.registry_backup = self.registry.read_bytes()
        self.paths = RootSSHPaths(
            authorized_keys=self.auth, known_hosts=self.known,
            journal_dir=self.journal, tunnel_uid=self.tunnel_uid,
            tunnel_gid=self.tunnel_uid, gateway_uid=self.gateway_uid,
            gateway_gid=self.gateway_uid)
        self.keys = {}
        for name in ("tunnel_key", "target_host", "other"):
            p = self.root / name
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                            "-N", "", "-f", str(p)],
                           check=True, capture_output=True)
            self.keys[name] = " ".join(
                Path(str(p) + ".pub").read_text().split()[:2])
        self.rid = "A" * 26
        self.approved_calls = 0

    def approved(self):
        self.approved_calls += 1
        return True

    def apply(self, **kwargs):
        return apply_candidate_root_transaction(
            self.paths, request_id=self.rid,
            tunnel_key=self.keys["tunnel_key"],
            host_key=self.keys["target_host"],
            approval_check=self.approved, **kwargs)

    def unchanged(self):
        self.assertEqual(self.auth.read_bytes(), self.legacy_auth)
        self.assertEqual(self.known.read_bytes(), self.legacy_known)
        self.assertEqual(self.registry.read_bytes(), self.registry_backup)

    def test_actual_root_file_writes_keep_two_different_owners(self):
        result = self.apply()
        self.assertEqual(result["status"], "candidate_ssh_staged")
        self.assertFalse(result["registry_changed"])
        self.assertFalse(result["sudo_granted"])
        self.assertEqual(self.approved_calls, 1)
        self.assertIn(b'permitlisten="127.0.0.1:10003"', self.auth.read_bytes())
        self.assertIn(b'[127.0.0.1]:10003', self.known.read_bytes())
        self.assertTrue(self.auth.read_bytes().startswith(self.legacy_auth))
        self.assertTrue(self.known.read_bytes().startswith(self.legacy_known))
        for path, uid in ((self.auth, self.tunnel_uid),
                          (self.known, self.gateway_uid)):
            info = path.lstat()
            self.assertEqual(info.st_uid, uid)
            self.assertEqual(info.st_gid, uid)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertFalse((self.journal / JOURNAL).exists())
        events = [json.loads(v)["status"] for v in
                  (self.journal / AUDIT).read_text().splitlines()]
        self.assertEqual(events, ["prepared", "applied"])
        self.assertEqual(self.registry.read_bytes(), self.registry_backup)

    def test_approval_required_before_any_file_or_journal_change(self):
        with self.assertRaises(PermissionError):
            apply_candidate_root_transaction(
                self.paths, request_id=self.rid,
                tunnel_key=self.keys["tunnel_key"],
                host_key=self.keys["target_host"],
                approval_check=lambda: False)
        self.unchanged()
        self.assertFalse((self.journal / JOURNAL).exists())
        self.assertFalse((self.journal / AUDIT).exists())

    def test_wrong_or_replayed_candidate_cannot_replace_old_credentials(self):
        with self.assertRaises(PermissionError):
            apply_candidate_root_transaction(
                self.paths, request_id="../" + self.rid,
                tunnel_key=self.keys["tunnel_key"],
                host_key=self.keys["target_host"], approval_check=self.approved)
        self.unchanged()
        self.apply()
        before = (self.auth.read_bytes(), self.known.read_bytes())
        with self.assertRaises(PermissionError):
            self.apply()
        self.assertEqual(before, (self.auth.read_bytes(), self.known.read_bytes()))

    def test_real_root_journal_survives_crash_after_first_write(self):
        with self.assertRaises(InterruptedRootTransaction):
            self.apply(test_interrupt_after=1)
        self.assertIn(b'10003', self.auth.read_bytes())
        self.assertEqual(self.known.read_bytes(), self.legacy_known)
        self.assertTrue((self.journal / JOURNAL).is_file())
        with self.assertRaises(PermissionError):
            self.apply()
        self.assertTrue(recover_candidate_root_transaction(self.paths))
        self.unchanged()
        self.assertFalse((self.journal / JOURNAL).exists())
        self.assertFalse(recover_candidate_root_transaction(self.paths))
        self.apply()

    def test_abrupt_process_exit_after_first_root_write_is_recoverable(self):
        """A real os._exit skips Python exception/finally rollback entirely."""
        pid = os.fork()
        if pid == 0:
            try:
                from ai_lab_gateway import device_code_root_transaction as tx
                original = tx._replace
                def exit_after_first(*args, **kwargs):
                    original(*args, **kwargs)
                    os._exit(137)
                tx._replace = exit_after_first
                self.apply()
            except BaseException:
                os._exit(90)
            os._exit(91)
        waited, status = os.waitpid(pid, 0)
        self.assertEqual(waited, pid)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 137)
        self.assertIn(b"10003", self.auth.read_bytes())
        self.assertEqual(self.known.read_bytes(), self.legacy_known)
        self.assertTrue((self.journal / JOURNAL).exists())
        self.assertTrue(recover_candidate_root_transaction(self.paths))
        self.unchanged()

    def test_real_root_journal_survives_crash_after_second_write(self):
        with self.assertRaises(InterruptedRootTransaction):
            self.apply(test_interrupt_after=2)
        self.assertIn(b'10003', self.auth.read_bytes())
        self.assertIn(b'10003', self.known.read_bytes())
        self.assertTrue(recover_candidate_root_transaction(self.paths))
        self.unchanged()

    def test_non_crash_second_write_failure_restores_both_files(self):
        # Force a failure in the second write, with safe recovery.
        from ai_lab_gateway import device_code_root_transaction as transaction
        original = transaction._replace
        calls = []
        def fail_second(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise OSError("simulated second write failure")
            return original(*args, **kwargs)
        from unittest.mock import patch
        with patch.object(transaction, "_replace", side_effect=fail_second):
            self.assertRaises(OSError, self.apply)
        self.unchanged()
        self.assertFalse((self.journal / JOURNAL).exists())

    def test_recovery_never_overwrites_unrelated_admin_change(self):
        with self.assertRaises(InterruptedRootTransaction):
            self.apply(test_interrupt_after=1)
        self.known.write_bytes(self.legacy_known + b"# independent admin edit\n")
        with self.assertRaises(PermissionError):
            recover_candidate_root_transaction(self.paths)
        self.assertTrue((self.journal / JOURNAL).exists())
        self.assertIn(b'10003', self.auth.read_bytes())
        self.assertIn(b"# independent admin edit", self.known.read_bytes())

    def test_symlinks_and_weak_permissions_are_rejected(self):
        self.auth.chmod(0o666)
        with self.assertRaises(PermissionError):
            self.apply()
        self.auth.chmod(0o600)
        self.auth.unlink()
        self.auth.symlink_to(self.registry)
        with self.assertRaises(OSError):
            self.apply()
        self.assertEqual(self.registry.read_bytes(), self.registry_backup)

    def test_untrusted_root_journal_is_not_used(self):
        journal = self.journal / JOURNAL
        journal.write_text('{"invalid":"journal"}')
        journal.chmod(0o600)
        with self.assertRaises(PermissionError):
            recover_candidate_root_transaction(self.paths)
        with self.assertRaises(PermissionError):
            self.apply()
        self.unchanged()

    def test_wrong_root_journal_permissions_are_rejected(self):
        self.journal.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.apply()
        self.unchanged()


    def test_root_apply_adapter_rechecks_handoff_inside_journal_lock(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from ai_lab_gateway import device_code_root_apply as adapter

        candidate = {
            "request_id": self.rid,
            "tunnel_public_key": self.keys["tunnel_key"],
            "host_public_key": self.keys["target_host"],
            "device_id": "windows-wsl", "access_mode": "restricted",
            "persistent": False,
        }
        report = {
            "status": "candidate_preflight_ok", "device_id": "windows-wsl",
            "port": 10003, "access_mode": "restricted", "persistent": False,
            "registry_changed": False, "ssh_changed": False,
        }
        identities = {
            "tunnel": SimpleNamespace(pw_uid=self.tunnel_uid,
                                      pw_gid=self.tunnel_uid),
            "ai-lab-gateway": SimpleNamespace(pw_uid=self.gateway_uid,
                                               pw_gid=self.gateway_uid),
        }
        handoff_reads = []
        def trusted_approval(rid):
            self.assertEqual(rid, self.rid)
            handoff_reads.append(rid)
            return dict(candidate)
        with patch.object(adapter, "production_paths", return_value=self.paths), \
             patch.object(adapter, "_trusted_approved_candidate", side_effect=trusted_approval), \
             patch.object(adapter, "_verify_root_environment", return_value=report), \
             patch.object(adapter.pwd, "getpwnam", side_effect=lambda name: identities[name]):
            applied = adapter.apply_staged_wsl_candidate(self.rid)
        self.assertEqual(applied["status"], "candidate_ssh_staged")
        self.assertEqual(handoff_reads, [self.rid, self.rid])
        self.assertIn(b"10003", self.auth.read_bytes())
        self.assertEqual(self.registry.read_bytes(), self.registry_backup)

    def test_root_apply_adapter_detects_revoked_approval_at_commit(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        from ai_lab_gateway import device_code_root_apply as adapter

        original = {"request_id": self.rid,
                    "tunnel_public_key": self.keys["tunnel_key"],
                    "host_public_key": self.keys["target_host"],
                    "device_id": "windows-wsl"}
        tampered = {**original, "host_public_key": self.keys["other"]}
        verified = {
            "status": "candidate_preflight_ok", "device_id": "windows-wsl",
            "port": 10003, "access_mode": "restricted", "persistent": False,
            "registry_changed": False, "ssh_changed": False,
        }
        identities = {
            "tunnel": SimpleNamespace(pw_uid=self.tunnel_uid,
                                      pw_gid=self.tunnel_uid),
            "ai-lab-gateway": SimpleNamespace(pw_uid=self.gateway_uid,
                                               pw_gid=self.gateway_uid),
        }
        with patch.object(adapter, "production_paths", return_value=self.paths), \
             patch.object(adapter, "_trusted_approved_candidate",
                          side_effect=[original, tampered]), \
             patch.object(adapter, "_verify_root_environment", return_value=verified), \
             patch.object(adapter.pwd, "getpwnam", side_effect=lambda name: identities[name]):
            with self.assertRaises(PermissionError):
                adapter.apply_staged_wsl_candidate(self.rid)
        self.unchanged()
        self.assertFalse((self.journal / JOURNAL).exists())


if __name__ == "__main__":
    unittest.main()
