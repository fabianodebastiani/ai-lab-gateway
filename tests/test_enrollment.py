"""Unit tests for secure, restricted-first, one-time enrollment invitation store."""
import base64
import hashlib
import sqlite3
import struct
import tempfile
from pathlib import Path
import unittest

from ai_lab_gateway.enrollment import EnrollmentStore


def public_key(seed: int):
    blob = (
        struct.pack(">I", 11) + b"ssh-ed25519" +
        struct.pack(">I", 32) + bytes([seed]) * 32
    )
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "pairing.sqlite3"
        self.store = EnrollmentStore(self.path)

    def claim(self, token, *, device_id="windows-wsl-v2", persistent=False, now=101):
        return self.store.claim(
            token, device_id=device_id, device_name="WSL Pilot",
            tunnel_public_key=public_key(1),
            ssh_host_public_key=public_key(2),
            persistent=persistent, now=now,
        )

    def test_invitation_is_not_saved_in_plaintext(self):
        token = self.store.invite("oauth-subject-123", now=100)
        self.assertGreaterEqual(len(token), 40)
        self.assertNotIn(token, self.path.read_bytes().decode("latin-1"))
        with sqlite3.connect(self.path) as db:
            count = db.execute("SELECT count(*) FROM invites").fetchone()[0]
            digest = db.execute("SELECT token_hash FROM invites").fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(digest, hashlib.sha256(token.encode()).hexdigest())

    def test_restricted_enrollment_with_either_flag(self):
        token = self.store.invite("owner", now=100)
        response = self.claim(token, persistent=True)
        self.assertEqual(response["status"], "pending")
        self.assertEqual(response["access_mode"], "restricted")
        self.assertTrue(response["persistent"])
        self.assertTrue(response["host_key_fingerprint"].startswith("SHA256:"))
        token2 = self.store.invite("owner", now=100)
        response2 = self.claim(token2, device_id="linux-test-002", persistent=False)
        self.assertFalse(response2["persistent"])
        self.assertEqual(response2["access_mode"], "restricted")

    def test_token_is_single_use(self):
        token = self.store.invite("owner", now=100)
        self.claim(token)
        with self.assertRaises(PermissionError):
            self.claim(token, device_id="different-linux")

    def test_expired_token_rejected(self):
        token = self.store.invite("owner", now=100)
        with self.assertRaises(PermissionError):
            self.claim(token, now=700)

    def test_invalid_operator_rejected(self):
        with self.assertRaises(ValueError):
            self.store.invite("", now=100)

    def test_invalid_flag_rejected(self):
        token = self.store.invite("owner", now=100)
        for flag in ("true", 1, None):
            with self.subTest(flag=flag):
                with self.assertRaises(ValueError):
                    self.store.claim(
                        token, device_id="new-linux-001", device_name="Linux",
                        tunnel_public_key=public_key(1),
                        ssh_host_public_key=public_key(2),
                        persistent=flag, now=101,
                    )

    def test_reject_same_tunnel_and_host_key(self):
        token = self.store.invite("owner", now=100)
        with self.assertRaises(ValueError):
            self.store.claim(
                token, device_id="new-linux-001", device_name="Linux",
                tunnel_public_key=public_key(1),
                ssh_host_public_key=public_key(1),
                persistent=False, now=101,
            )

    def test_reject_wrong_key_type(self):
        token = self.store.invite("owner", now=100)
        with self.assertRaises(ValueError):
            self.store.claim(
                token, device_id="new-linux-001", device_name="Linux",
                tunnel_public_key="ssh-rsa AAAA", ssh_host_public_key=public_key(2),
                persistent=False, now=101,
            )

    def test_duplicate_pending_device_id_rejected(self):
        self.claim(self.store.invite("owner", now=100))
        token2 = self.store.invite("owner", now=100)
        with self.assertRaises(ValueError):
            self.claim(token2)

    def test_no_unrestricted_parameter_in_claim(self):
        token = self.store.invite("owner", now=100)
        with self.assertRaises(TypeError):
            self.store.claim(
                token, device_id="new-linux-001", device_name="Linux",
                tunnel_public_key=public_key(1),
                ssh_host_public_key=public_key(2),
                persistent=False, access_mode="unrestricted", now=101,
            )

    def test_db_file_private(self):
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
