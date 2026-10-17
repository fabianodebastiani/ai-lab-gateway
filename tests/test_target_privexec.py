"""Disposable root-only laboratory for one-use signed device vouchers.

Run with sudo on a disposable CI runner, never on a production device.
All credential material is synthetic and lives only under TemporaryDirectory.
"""
import importlib.machinery
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "ai-lab-target-privexec"
loader = importlib.machinery.SourceFileLoader("test_target_privexec_module", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)


def canonical(permit):
    return (json.dumps(permit, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def run_claim(raw, q):
    try:
        q.put(mod.execute_packet(raw))
    except Exception as exc:
        q.put(type(exc).__name__)


@unittest.skipUnless(os.geteuid() == 0, "requires isolated root CI, never target root")
class RootSignedVoucherTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        base = Path(self.t.name)
        self.config = base / "config"
        self.state = base / "state"
        self.config.mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        for folder in ("used", "revoked"):
            (self.state / folder).mkdir(mode=0o700)
        self._write(self.state / "lock", b"")
        self.device = "ai-lab-experiments-01-fd3dab34"
        self._write(self.config / "device-id", (self.device + "\n").encode())
        key = base / "synthetic_issuer"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                        "-N", "", "-f", str(key)], check=True)
        self.issuer = key
        pub = (base / "synthetic_issuer.pub").read_text().split()
        self._write(self.config / "allowed_signers",
                    (mod.SIGNER + " " + " ".join(pub[:2]) + "\n").encode())
        p = patch.multiple(mod, CONFIG=self.config, STATE=self.state)
        p.start()
        self.addCleanup(p.stop)

    @staticmethod
    def _write(path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def voucher(self, *, permit_updates=None, sign=True):
        now = int(time.time())
        permit = {
            "version": mod.VERSION,
            "device_id": self.device,
            "subject": "auth0|synthetic-test-human",
            "operation": "root-identity-check",
            "argv": ["/usr/bin/id", "-u"],
            "nonce": secrets.token_hex(32),
            "issued_at": now,
            "expires_at": now + 150,
        }
        permit.update(permit_updates or {})
        if sign:
            proc = subprocess.run(
                ["/usr/bin/ssh-keygen", "-Y", "sign", "-n", mod.NAMESPACE,
                 "-f", str(self.issuer)],
                input=canonical(permit), capture_output=True, check=True)
            sig = proc.stdout.decode("ascii")
        else:
            sig = "-----BEGIN SSH SIGNATURE-----\nINVALID\n-----END SSH SIGNATURE-----\n"
        raw = json.dumps({"permit": permit, "signature": sig},
                         separators=(",", ":")).encode()
        return raw, permit

    def test_valid_signed_root_identity_executes_once_only(self):
        raw, permit = self.voucher()
        code, output = mod.execute_packet(raw)
        self.assertEqual(code, 0)
        self.assertEqual(output.strip(), "0")
        used = self.state / "used" / permit["nonce"]
        self.assertEqual(stat.S_IMODE(used.stat().st_mode), 0o600)
        self.assertIn(self.device, used.read_text())
        with self.assertRaises(FileExistsError):
            mod.execute_packet(raw)
        # A second independent call/engine lifetime still finds the durable marker.
        with self.assertRaises(FileExistsError):
            mod.execute_packet(raw)

    def test_unsigned_or_modified_grants_denied(self):
        raw, permit = self.voucher()
        packet = json.loads(raw)
        packet["permit"]["subject"] = "auth0|attacker"
        with self.assertRaises(PermissionError):
            mod.execute_packet(json.dumps(packet).encode())
        raw2, _ = self.voucher(sign=False)
        with self.assertRaises(PermissionError):
            mod.execute_packet(raw2)
        self.assertFalse(list((self.state / "used").iterdir()))

    def test_wrong_device_or_args_rejected_even_with_valid_signer(self):
        for change in (
            {"device_id": "raspberry-lab"},
            {"operation": "sudo-bash"},
            {"argv": ["/bin/bash", "-c", "id"]},
            {"argv": ["/usr/bin/id", "-u", "--help"]},
            {"version": "old"},
        ):
            with self.subTest(change=change):
                raw, _ = self.voucher(permit_updates=change)
                with self.assertRaises(PermissionError):
                    mod.execute_packet(raw)
        self.assertFalse(list((self.state / "used").iterdir()))

    def test_expiry_future_and_oversized_ttl_denied(self):
        now = int(time.time())
        for change in (
            {"issued_at": now - 320, "expires_at": now - 1},
            {"issued_at": now + 80, "expires_at": now + 180},
            {"issued_at": now, "expires_at": now + 301},
            {"issued_at": True},
            {"expires_at": True},
        ):
            with self.subTest(change=change):
                raw, _ = self.voucher(permit_updates=change)
                with self.assertRaises(PermissionError):
                    mod.execute_packet(raw)

    def test_pre_revoked_nonce_denied(self):
        raw, permit = self.voucher()
        self._write(self.state / "revoked" / permit["nonce"], b"revoked\n")
        with self.assertRaises(PermissionError):
            mod.execute_packet(raw)
        self.assertFalse(list((self.state / "used").iterdir()))

    def test_symlink_or_wrong_ownership_fails_closed(self):
        raw, _ = self.voucher()
        signer = self.config / "allowed_signers"
        signer.chmod(0o644)
        with self.assertRaises(PermissionError):
            mod.execute_packet(raw)
        signer.chmod(0o600)
        real = self.config / "signer-real"
        signer.rename(real)
        signer.symlink_to(real)
        with self.assertRaises(PermissionError):
            mod.execute_packet(raw)

    def test_single_success_under_eight_processes(self):
        raw, _ = self.voucher()
        ctx = multiprocessing.get_context("fork")
        q = ctx.Queue()
        workers = [ctx.Process(target=run_claim, args=(raw, q)) for _ in range(8)]
        for worker in workers:
            worker.start()
        results = [q.get(timeout=15) for _ in workers]
        for worker in workers:
            worker.join(timeout=15)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sum(isinstance(x, tuple) and x == (0, "0\n")
                             for x in results), 1, results)
        self.assertEqual(sum(x == "FileExistsError" for x in results), 7, results)

    def test_json_duplicate_key_and_untrusted_blob(self):
        raw, _ = self.voucher()
        packet = json.loads(raw)
        invalid = json.dumps(packet)[:-1] + ', "permit": {}}\n'
        with self.assertRaises(ValueError):
            mod.execute_packet(invalid.encode())
        with self.assertRaises(ValueError):
            mod.execute_packet(raw + b"x" * mod.MAX_INPUT)
        self.assertFalse(list((self.state / "used").iterdir()))

    def test_no_root_permission_denied_first(self):
        raw, _ = self.voucher()
        with patch.object(mod.os, "geteuid", return_value=1000):
            with self.assertRaises(PermissionError):
                mod.execute_packet(raw)


if __name__ == "__main__":
    unittest.main()
