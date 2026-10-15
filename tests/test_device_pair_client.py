"""No-network tests for the independent target-side v2 pairing client."""
from pathlib import Path
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ai-lab-device-pair-v2.py"


def client_module():
    spec = importlib.util.spec_from_file_location("device_pair_under_test", SCRIPT)
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


class FakeResponse:
    status = 202
    def __init__(self, result):
        self.body = json.dumps(result).encode("utf8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n):
        return self.body[:n]


class TargetPairingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.m = client_module()
        self.host_private = self.root / "ssh_host_ed25519_key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-f", str(self.host_private)], check=True, capture_output=True
        )

    def test_preparation_creates_fresh_private_key_once(self):
        directory = self.root / "v2-state"
        first = self.m.prepare(directory, "linux-fresh-01",
                               host_key_path=Path(str(self.host_private) + ".pub"))
        self.assertEqual(first["device_id"], "linux-fresh-01")
        self.assertTrue(first["tunnel_key_fingerprint"].startswith("SHA256:"))
        self.assertNotEqual(first["tunnel_key_fingerprint"], first["host_key_fingerprint"])
        self.assertEqual((directory.stat().st_mode & 0o777), 0o700)
        private, public = self.m.key_paths(directory, "linux-fresh-01")
        self.assertEqual(private.stat().st_mode & 0o777, 0o600)
        self.assertEqual(public.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.m.prepare(directory, "linux-fresh-01",
                                        host_key_path=Path(str(self.host_private) + ".pub")),
                         first)

    def test_claim_is_restricted_and_verifies_both_fingerprints(self):
        local = self.m.prepare(self.root / "state", "linux-new-01",
                               host_key_path=Path(str(self.host_private) + ".pub"))
        token = "A" * 43
        def opener(req, timeout):
            self.assertEqual(timeout, 10)
            self.assertEqual(req.full_url, self.m.DEFAULT_ENDPOINT)
            payload = json.loads(req.data)
            self.assertEqual(payload["token"], token)
            self.assertFalse(payload["persistent"])
            self.assertNotEqual(payload["tunnel_public_key"],
                                payload["ssh_host_public_key"])
            return FakeResponse({
                "status": "pending", "access_mode": "restricted",
                "device_id": "linux-new-01", "request_id": "candidate",
                "tunnel_key_fingerprint": local["tunnel_key_fingerprint"],
                "host_key_fingerprint": local["host_key_fingerprint"],
            })
        result = self.m.claim(self.m.DEFAULT_ENDPOINT, token, device_id="linux-new-01",
                              device_name="Fresh Linux", persistent=False,
                              tunnel_public_key=local["tunnel_public_key"],
                              ssh_host_public_key=local["ssh_host_public_key"],
                              opener=opener)
        self.assertEqual(result["status"], "pending")

    def test_wrong_fingerprint_or_admin_status_fails_closed(self):
        local = self.m.prepare(self.root / "state", "linux-new-01",
                               host_key_path=Path(str(self.host_private) + ".pub"))
        for override in (
            {"tunnel_key_fingerprint": "SHA256:wrong"},
            {"access_mode": "unrestricted"},
            {"status": "active"},
        ):
            payload = {
                "status": "pending", "access_mode": "restricted",
                "device_id": "linux-new-01", "request_id": "candidate",
                "tunnel_key_fingerprint": local["tunnel_key_fingerprint"],
                "host_key_fingerprint": local["host_key_fingerprint"],
                **override,
            }
            with self.subTest(override=override), self.assertRaises(RuntimeError):
                self.m.claim(self.m.DEFAULT_ENDPOINT, "A"*43,
                    device_id="linux-new-01", device_name="Fresh Linux",
                    persistent=False,
                    tunnel_public_key=local["tunnel_public_key"],
                    ssh_host_public_key=local["ssh_host_public_key"],
                    opener=lambda req,timeout: FakeResponse(payload))

    def test_invalid_endpoint_and_bad_identity_rejected(self):
        local = self.m.prepare(self.root / "state", "linux-new-01",
                               host_key_path=Path(str(self.host_private) + ".pub"))
        with self.assertRaises(ValueError):
            self.m.claim("http://example.com/claim", "A" * 43,
                device_id="linux-new-01", device_name="Fresh Linux",
                persistent=False,
                tunnel_public_key=local["tunnel_public_key"],
                ssh_host_public_key=local["ssh_host_public_key"])
        with self.assertRaises(ValueError):
            self.m.prepare(self.root / "second", "Bad ID",
                           host_key_path=Path(str(self.host_private) + ".pub"))

    def test_existing_keys_are_not_overwritten(self):
        directory = self.root / "state"
        directory.mkdir(mode=0o700)
        private,_ = self.m.key_paths(directory,"linux-new-01")
        private.write_text("do not overwrite")
        with self.assertRaises(PermissionError):
            self.m.prepare(directory,"linux-new-01",
                        host_key_path=Path(str(self.host_private) + ".pub"))
        self.assertEqual(private.read_text(),"do not overwrite")


if __name__ == "__main__":
    unittest.main()
