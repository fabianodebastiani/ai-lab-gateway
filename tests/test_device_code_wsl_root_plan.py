"""No-network tests: approved one-code WSL identity and pre-pinned host."""
import subprocess
import tempfile
from pathlib import Path
import unittest

from ai_lab_gateway.device_code_wsl_root_plan import build_wsl_one_code_offer


class WSLRootPlanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        directory = Path(tmp.name)
        pubs = []
        for index in range(4):
            key = directory / ("key" + str(index))
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(key)], capture_output=True, check=True)
            pubs.append(" ".join(key.with_suffix(".pub").read_text().split()[:2]))
        self.tunnel, self.target, self.gateway, self.management = pubs
        self.rid = "ABCDEFGHIJKLMNOPQRSTUVWX"
        self.candidate = {
            "request_id": self.rid,
            "device_id": "laptop-5rjj0kbm-8210ee98",
            "device_name": "LAPTOP-5RJJ0KBM",
            "operator_subject": "auth0|operator",
            "tunnel_public_key": self.tunnel,
            "host_public_key": self.target,
            "persistent": False, "expires_at": 9999999999,
        }
        self.registry = {"devices": [
            {"id": "raspberry-lab", "tunnel_port": 10001},
            {"id": "windows-wsl", "tunnel_port": 10002},
        ]}
        self.trusted = (
            "[127.0.0.1]:10002 " + self.target + "\n"
            "[127.0.0.1]:10002 ssh-rsa other-old-key\n"
            "[127.0.0.1]:10003 " + self.target + "\n").encode("ascii")

    def make(self, *, candidate=None, registry=None, known=None):
        return build_wsl_one_code_offer(
            candidate if candidate is not None else self.candidate,
            trusted_registry=registry if registry is not None else self.registry,
            trusted_known_hosts=known if known is not None else self.trusted,
            gateway_ssh_host_key=self.gateway,
            gateway_management_key=self.management)

    def test_preexisting_identical_10003_identity_is_accepted(self):
        offer = self.make()
        self.assertEqual(offer["device_id"], "laptop-5rjj0kbm-8210ee98")
        self.assertEqual(offer["reverse_listen_port"], 10003)
        self.assertEqual(offer["gateway_management_public_key"], self.management)
        self.assertEqual(offer["persistent"], False)
        self.assertEqual(offer["access_mode"], "restricted")
        self.assertNotIn("private_key", offer)
        self.assertNotIn("operator_subject", offer)

    def test_old_rsa_pin_is_not_used_as_host_identity(self):
        known = ("[127.0.0.1]:10002 ssh-rsa irrelevant\n" +
                 "[127.0.0.1]:10003 " + self.target + "\n").encode()
        with self.assertRaises(PermissionError):
            self.make(known=known)

    def test_other_host_and_duplicate_preexisting_pin_denied(self):
        changed = dict(self.candidate, host_public_key=self.gateway)
        with self.assertRaises(PermissionError):
            self.make(candidate=changed)
        with self.assertRaises(PermissionError):
            self.make(known=self.trusted + (
                "[127.0.0.1]:10003 " + self.target + "\n").encode())
        with self.assertRaises(PermissionError):
            self.make(known=self.trusted.replace(
                ("[127.0.0.1]:10003 " + self.target).encode(),
                ("[127.0.0.1]:10003 " + self.gateway).encode()))

    def test_unauthorized_id_mode_or_missing_owner_is_denied(self):
        for change in ({"device_id": "other-linux"},
                       {"persistent": True},
                       {"operator_subject": ""},
                       {"operator_subject": None},
                       {"access_mode": "unrestricted"}):
            with self.subTest(change=change):
                with self.assertRaises(PermissionError):
                    self.make(candidate=dict(self.candidate, **change))

    def test_never_take_port_from_remote_candidate(self):
        with self.assertRaises(PermissionError):
            self.make(candidate=dict(self.candidate, port=10004))
        with self.assertRaises(PermissionError):
            self.make(registry={"devices": self.registry["devices"] +
                                [{"id": "attacker", "tunnel_port": 10003}]})


if __name__ == "__main__":
    unittest.main()
