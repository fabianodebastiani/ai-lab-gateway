"""OpenSSH SSHSIG real-key interoperability and forgery regression tests."""
import base64
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.sshsig import verify_sshsig, SSHSIG_NAMESPACE


def sshkey(root: Path, name: str):
    path=root/name
    subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(path)],
                   check=True,capture_output=True)
    return path, Path(str(path)+".pub").read_text().strip()


def sshsign(key: Path, data: bytes, *, namespace: str="ai-lab-gateway-device-code"):
    return subprocess.run(["ssh-keygen","-Y","sign","-n",namespace,"-f",str(key)],
                          input=data,check=True,capture_output=True,timeout=10).stdout.decode("ascii")


def pack(value):
    return struct.pack(">I",len(value))+value


def mutate(armor: str, transformation):
    lines=armor.strip().splitlines()
    blob=bytearray(base64.b64decode("".join(lines[1:-1])))
    transformation(blob)
    raw=base64.b64encode(blob).decode("ascii")
    return lines[0]+"\n"+raw+"\n"+lines[-1]+"\n"


class SSHSigTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.key,self.pub=sshkey(self.root,"device")
        self.wrong,self.wrongpub=sshkey(self.root,"other")
        self.challenge=b'{"example":"SSHSIG Ed25519","nonce":12345}\n'

    def test_exact_key_namespace_and_challenge_valid(self):
        signature=sshsign(self.key,self.challenge)
        self.assertIsNone(verify_sshsig(
            armor=signature,challenge=self.challenge,expected_public_key=self.pub))
        self.assertEqual(SSHSIG_NAMESPACE,b"ai-lab-gateway-device-code")

    def test_wrong_key_challenge_namespace_or_corrupt_signature_denied(self):
        signature=sshsign(self.key,self.challenge)
        with self.assertRaises(PermissionError):
            verify_sshsig(armor=signature,challenge=b"other\n",
                          expected_public_key=self.pub)
        with self.assertRaises(PermissionError):
            verify_sshsig(armor=signature,challenge=self.challenge,
                          expected_public_key=self.wrongpub)
        invalid_ns=sshsign(self.key,self.challenge,namespace="unrelated-namespace")
        with self.assertRaises(PermissionError):
            verify_sshsig(armor=invalid_ns,challenge=self.challenge,
                          expected_public_key=self.pub)
        def corrupt(raw):
            raw[-1] ^= 1
        with self.assertRaises(PermissionError):
            verify_sshsig(armor=mutate(signature,corrupt),
                          challenge=self.challenge,expected_public_key=self.pub)

    def test_truncated_modified_armor_or_versions_denied(self):
        signature=sshsign(self.key,self.challenge)
        def change_version(raw):
            raw[9]=2
        with self.assertRaises(ValueError):
            verify_sshsig(armor=mutate(signature,change_version),
                          challenge=self.challenge,expected_public_key=self.pub)
        with self.assertRaises(ValueError):
            verify_sshsig(armor=signature+"GARBAGE\n",
                          challenge=self.challenge,expected_public_key=self.pub)
        with self.assertRaises(ValueError):
            verify_sshsig(armor=signature.replace("BEGIN SSH SIGNATURE","BEGIN OTHER"),
                          challenge=self.challenge,expected_public_key=self.pub)

    def test_full_device_store_accepts_one_sshsig_and_rejects_replay(self):
        store=DeviceCodeStore(self.root/"store.sqlite",hmac_key=b"Q"*32)
        host,hostpub=sshkey(self.root,"host")
        pending=store.start(device_id="linux-sshsig-lab", display_name="Laboratorio",
                            persistent=False,source_id="203.0.113.3",
                            tunnel_public_key=self.pub,host_public_key=hostpub)
        signature=sshsign(self.key,base64.b64decode(pending["challenge_b64"]))
        result=store.prove(request_id=pending["request_id"],
                           device_secret=pending["device_secret"],sshsig=signature)
        self.assertEqual(result["status"],"proven")
        with self.assertRaises(PermissionError):
            store.prove(request_id=pending["request_id"],
                        device_secret=pending["device_secret"],sshsig=signature)
        with self.assertRaises(PermissionError):
            store.confirm(request_id=pending["request_id"],
                          operator_subject="auth0|operator",
                          confirmation=pending["confirmation"])

    def test_prove_rejects_ambiguous_signature_fields(self):
        store=DeviceCodeStore(self.root/"store2.sqlite",hmac_key=b"R"*32)
        _,host=sshkey(self.root,"host2")
        p=store.start(device_id="linux-sshsig-lab",display_name="Laboratorio",
                      persistent=False,source_id="203.0.113.3",
                      tunnel_public_key=self.pub,host_public_key=host)
        data=sshsign(self.key,base64.b64decode(p["challenge_b64"]))
        with self.assertRaises(PermissionError):
            store.prove(request_id=p["request_id"],device_secret=p["device_secret"],
                        sshsig=data,signature_b64=base64.b64encode(b"x"*64).decode())
        with self.assertRaises(PermissionError):
            store.prove(request_id=p["request_id"],device_secret=p["device_secret"])


if __name__=="__main__":
    unittest.main()
