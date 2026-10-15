"""Candidate public SSH offer delivery is never device-controlled."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_offer import validate_offer, fingerprint, OFFER_VERSION


class SSHOfferTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = DeviceCodeStore(self.root/"codes.sqlite", hmac_key=b"P"*32)
        self.identities={}
        for role in ("tunnel","host","gateway_host","gateway_management","other"):
            key=self.root/role
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(key)],
                           check=True,capture_output=True)
            self.identities[role]=(key,Path(str(key)+".pub").read_text().strip())
        self.started=self.store.start(
            device_id="linux-offer-lab",display_name="Offer Linux",
            source_id="203.0.113.3",persistent=False,
            tunnel_public_key=self.identities["tunnel"][1],
            host_public_key=self.identities["host"][1],now=100)

    def prove_and_approve(self):
        started=self.started
        key=serialization.load_ssh_private_key(
            self.identities["tunnel"][0].read_bytes(),password=None)
        proof=base64.b64encode(
            key.sign(base64.b64decode(started["challenge_b64"]))).decode("ascii")
        self.store.prove(request_id=started["request_id"],
                         device_secret=started["device_secret"],
                         signature_b64=proof,now=102)
        self.store.lookup(user_code=started["user_code"],
                          operator_subject="auth0|authorized",now=103)
        self.store.confirm(request_id=started["request_id"],
                           operator_subject="auth0|authorized",
                           confirmation=started["confirmation"],now=104)

    def offer(self, **changes):
        fields={
            "version":OFFER_VERSION,
            "request_id":self.started["request_id"],
            "device_id":"linux-offer-lab",
            "access_mode":"restricted",
            "persistent":False,
            "gateway_host":"gateway.debasti.com",
            "gateway_ssh_port":22,
            "gateway_tunnel_user":"tunnel",
            "gateway_ssh_host_key":self.identities["gateway_host"][1].split(" ")[0]+" "+
                                  self.identities["gateway_host"][1].split(" ")[1],
            "gateway_management_public_key":
                " ".join(self.identities["gateway_management"][1].split(" ")[:2]),
            "reverse_listen_host":"127.0.0.1",
            "reverse_listen_port":10011,
            "management_user":"ai-gateway",
            "device_tunnel_fingerprint":fingerprint(self.identities["tunnel"][1]),
            "device_host_fingerprint":fingerprint(self.identities["host"][1]),
        }
        return {**fields,**changes}

    def stage(self,manifest=None):
        return self.store.stage_connection_offer(
            request_id=self.started["request_id"],offer=manifest or self.offer(),
            provisioner_verified=True,now=105)

    def test_public_offer_requires_separate_approval_and_privileged_source(self):
        with self.assertRaises(PermissionError):
            self.stage()
        self.prove_and_approve()
        with self.assertRaises(PermissionError):
            self.store.stage_connection_offer(request_id=self.started["request_id"],
                offer=self.offer(),now=105)
        self.assertEqual(self.stage()["status"],"candidate_staged")

    def test_only_device_secret_gets_offer_and_only_after_approval(self):
        self.prove_and_approve()
        before=self.store.poll(request_id=self.started["request_id"],
                     device_secret=self.started["device_secret"],now=105)
        self.assertNotIn("connection_offer",before)
        self.stage()
        after=self.store.poll(request_id=self.started["request_id"],
                      device_secret=self.started["device_secret"],now=111)
        self.assertEqual(after["status"],"approved")
        self.assertEqual(after["connection_offer"],self.offer())
        self.assertNotIn("device_secret",json.dumps(after))
        self.assertNotIn("private",json.dumps(after))
        with self.assertRaises(PermissionError):
            self.store.poll(request_id=self.started["request_id"],
                       device_secret="B"*43,now=117)
        self.assertEqual(
            self.store.poll(request_id=self.started["request_id"],
                    device_secret=self.started["device_secret"],now=117)["connection_offer"],
            self.offer())

    def test_offer_exactly_once_cannot_be_replaced_by_another_port(self):
        self.prove_and_approve()
        self.stage()
        with self.assertRaises(PermissionError):
            self.stage(self.offer(reverse_listen_port=12030))

    def test_reject_offers_redirecting_another_user_or_host(self):
        self.prove_and_approve()
        for update in (
            {"gateway_host":"attacker.invalid"},
            {"gateway_ssh_port":2222},
            {"gateway_tunnel_user":"root"},
            {"management_user":"root"},
            {"access_mode":"unrestricted"},
            {"reverse_listen_host":"0.0.0.0"},
            {"reverse_listen_port":22},
            {"reverse_listen_port":True},
            {"persistent":True},
            {"device_id":"other-linux"},
            {"device_tunnel_fingerprint":fingerprint(self.identities["other"][1])},
            {"device_host_fingerprint":fingerprint(self.identities["other"][1])},
            {"gateway_ssh_host_key":self.identities["other"][1]},
            {"command":"sudo -i"},
        ):
            with self.subTest(update=update), self.assertRaises((PermissionError,ValueError)):
                self.stage(self.offer(**update))

    def test_expired_approval_cannot_stage_or_poll_offer(self):
        self.prove_and_approve()
        with self.assertRaises(PermissionError):
            self.store.stage_connection_offer(request_id=self.started["request_id"],
                 offer=self.offer(),provisioner_verified=True,now=701)

    def test_offer_schema_without_store(self):
        offer=self.offer()
        normalized=validate_offer(
            offer,request_id=self.started["request_id"],
            device_id="linux-offer-lab",persistent=False,
            tunnel_key=self.identities["tunnel"][1],
            host_key=self.identities["host"][1])
        self.assertEqual(normalized,offer)
        normalized["reverse_listen_port"]=2222
        self.assertEqual(offer["reverse_listen_port"],10011)


if __name__=="__main__":
    unittest.main()
