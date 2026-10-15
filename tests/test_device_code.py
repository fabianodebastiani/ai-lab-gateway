"""Nonproduction ADR-029 device-code pairing, proof, replay, consent tests."""
import base64
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from ai_lab_gateway.device_code import (
    CODE_ALPHABET, CODE_ENTROPY_BITS, DeviceCodeStore,
    MAX_PENDING_PER_SOURCE, MAX_CODE_LOOKUPS_PER_PRINCIPAL,
)


class DeviceCodeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.store=DeviceCodeStore(self.root/"codes.sqlite",
                                   hmac_key=b"K"*32)
        self.keys=[]
        for role in ("tunnel","host","wrong"):
            private=self.root/role
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","",
                            "-f",str(private)],check=True,capture_output=True)
            self.keys.append((
                private,
                Path(str(private)+".pub").read_text().strip()
            ))

    def new(self, *, device_id="linux-new-01",source_id="192.0.2.1",
            persistent=False, now=100):
        return self.store.start(device_id=device_id,display_name="Linux de teste",
                    source_id=source_id,
                    tunnel_public_key=self.keys[0][1],
                    host_public_key=self.keys[1][1],
                    persistent=persistent,now=now)

    def proof(self, pending, private=None):
        if private is None: private=self.keys[0][0]
        key=serialization.load_ssh_private_key(private.read_bytes(),password=None)
        message=base64.b64decode(pending["challenge_b64"])
        return base64.b64encode(key.sign(message)).decode("ascii")

    def prove(self, pending, *, now=105, private=None):
        return self.store.prove(request_id=pending["request_id"],
               device_secret=pending["device_secret"],
               signature_b64=self.proof(pending,private),now=now)

    def test_code_is_random_human_typeable_40_bits(self):
        p=self.new()
        self.assertEqual(CODE_ENTROPY_BITS,40)
        self.assertEqual(len(CODE_ALPHABET),32)
        self.assertRegex(p["user_code"],r"^[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertTrue(set(p["user_code"].replace("-","")).issubset(set(CODE_ALPHABET)))
        self.assertEqual(p["status"],"pending")
        self.assertEqual(p["access_mode"],"restricted")
        self.assertFalse(p["persistent"])
        self.assertNotEqual(p["user_code"],p["device_secret"])
        self.assertGreaterEqual(len(p["device_secret"]),40)
        data=(self.root/"codes.sqlite").read_bytes()
        self.assertNotIn(p["user_code"].encode(),data)
        self.assertNotIn(p["user_code"].replace("-","").encode(),data)
        self.assertNotIn(p["device_secret"].encode(),data)

    def test_valid_proof_and_operator_confirmed_only_with_attestation(self):
        p=self.new(persistent=True)
        self.assertTrue(p["persistent"])
        self.assertEqual(self.prove(p)["status"],"proven")
        lookup=self.store.lookup(user_code=p["user_code"].lower(),
                      operator_subject="auth0|alice",now=106)
        self.assertEqual(lookup["request_id"],p["request_id"])
        self.assertEqual(lookup["confirmation"],p["confirmation"])
        self.assertEqual(lookup["access_mode"],"restricted")
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=p["request_id"],
                   operator_subject="auth0|alice",
                   confirmation=p["confirmation"],now=107)
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=p["request_id"],
                   operator_subject="auth0|mallory",
                   confirmation=p["confirmation"],consent_verified=True,now=107)
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=p["request_id"],
                   operator_subject="auth0|alice",
                   confirmation="WRONG",
                   consent_verified=True,now=107)
        approved=self.store.confirm(request_id=p["request_id"],
                   operator_subject="auth0|alice",
                   confirmation=p["confirmation"],
                   consent_verified=True,now=107)
        self.assertEqual(approved["status"],"approved")
        with self.assertRaises(PermissionError):
            self.store.activate(request_id=p["request_id"],now=108)
        self.assertEqual(self.store.activate(request_id=p["request_id"],
                         provisioner_verified=True,now=108)["status"],"active")
        with self.assertRaises(PermissionError):
            self.store.activate(request_id=p["request_id"],
                         provisioner_verified=True,now=109)

    def test_wrong_key_forgery_does_not_advance(self):
        p=self.new()
        with self.assertRaises(PermissionError):
            self.prove(p,private=self.keys[2][0])
        with self.assertRaises(PermissionError):
            self.store.lookup(user_code=p["user_code"],
                        operator_subject="auth0|alice",now=106)
        self.assertEqual(self.prove(p)["status"],"proven")

    def test_modify_challenge_or_signature_fails(self):
        p=self.new()
        key=serialization.load_ssh_private_key(self.keys[0][0].read_bytes(),
                                                 password=None)
        bad=base64.b64encode(key.sign(
            base64.b64decode(p["challenge_b64"])+b"tamper")).decode()
        with self.assertRaises(PermissionError):
            self.store.prove(request_id=p["request_id"],
                   device_secret=p["device_secret"],
                   signature_b64=bad,now=106)
        self.assertEqual(self.prove(p,now=107)["status"],"proven")

    def test_replayed_or_expired_proof_fails(self):
        p=self.new()
        self.prove(p)
        with self.assertRaises(PermissionError):
            self.prove(p,now=106)
        q=self.new(device_id="linux-other-01",now=200)
        with self.assertRaises(PermissionError):
            self.prove(q,now=801)

    def test_stolen_code_cannot_take_over_bound_principal(self):
        p=self.new()
        self.prove(p)
        self.store.lookup(user_code=p["user_code"],
                           operator_subject="auth0|alice",now=107)
        with self.assertRaises(PermissionError):
            self.store.lookup(user_code=p["user_code"],
                           operator_subject="auth0|mallory",now=108)
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=p["request_id"],
                           operator_subject="auth0|mallory",
                           confirmation=p["confirmation"],
                           consent_verified=True,now=109)

    def test_secret_needed_to_poll_and_poll_rate_limit(self):
        p=self.new()
        with self.assertRaises(PermissionError):
            self.store.poll(request_id=p["request_id"],
                 device_secret="B"*43,now=101)
        self.assertEqual(self.store.poll(request_id=p["request_id"],
                 device_secret=p["device_secret"],now=101)["status"],"pending")
        with self.assertRaises(PermissionError):
            self.store.poll(request_id=p["request_id"],
                 device_secret=p["device_secret"],now=103)
        self.assertEqual(self.store.poll(request_id=p["request_id"],
                 device_secret=p["device_secret"],now=106)["status"],"pending")

    def test_source_quota_and_duplicate_device_cannot_be_bypassed(self):
        self.new()
        with self.assertRaises(PermissionError):
            self.new(device_id="linux-new-01",source_id="192.0.2.2")
        for i in range(1,MAX_PENDING_PER_SOURCE):
            self.new(device_id=f"linux-unit-{i:02}",now=100)
        with self.assertRaises(PermissionError):
            self.new(device_id="linux-another-02",now=100)

    def test_expired_code_invalid(self):
        p=self.new()
        self.prove(p)
        with self.assertRaises(PermissionError):
            self.store.lookup(user_code=p["user_code"],
                           operator_subject="auth0|alice",now=701)
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=p["request_id"],
                           operator_subject="auth0|alice",
                           confirmation=p["confirmation"],
                           consent_verified=True,now=701)

    def test_invalid_identity_rejected(self):
        with self.assertRaises(ValueError):
            self.new(device_id="contains uppercase")
        with self.assertRaises(ValueError):
            self.store.start(device_id="linux-fresh-01",
                display_name="Test",source_id="test",
                tunnel_public_key=self.keys[0][1],
                host_public_key=self.keys[0][1],persistent=False,now=100)
        with self.assertRaises(ValueError):
            DeviceCodeStore(self.root/"bad.sqlite",hmac_key=b"short")

    def test_operator_lookup_guess_rate_limit_even_on_failure(self):
        p=self.new()
        self.prove(p)
        bad="A"*8
        if bad==p["user_code"].replace("-",""): bad="B"*8
        for i in range(MAX_CODE_LOOKUPS_PER_PRINCIPAL):
            with self.assertRaises(PermissionError):
                self.store.lookup(user_code=bad,
                                   operator_subject="auth0|mallory",now=105+i)
        with self.assertRaises(PermissionError) as err:
            self.store.lookup(user_code=p["user_code"],
                               operator_subject="auth0|mallory",now=130)
        self.assertIn("quota",str(err.exception))


if __name__=="__main__":
    unittest.main()
