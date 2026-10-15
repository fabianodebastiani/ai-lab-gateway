"""Only public identities enter the root provisioner preflight policy."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from ai_lab_gateway.device_code_offer import fingerprint, OFFER_VERSION
from ai_lab_gateway.device_code_root_preflight import preflight_wsl_candidate


class WSLRootPreflightTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.pub = {}
        for name in ("tunnel", "host", "gateway_host", "gateway_management", "other"):
            private = self.root / name
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(private)], check=True, capture_output=True)
            self.pub[name] = " ".join(
                Path(str(private) + ".pub").read_text().split()[:2])
        self.request_id = "X" * 26
        self.offer = {
            "version": OFFER_VERSION, "request_id": self.request_id,
            "device_id": "windows-wsl", "access_mode": "restricted",
            "persistent": False, "gateway_host": "gateway.debasti.com",
            "gateway_ssh_port": 22, "gateway_tunnel_user": "tunnel",
            "gateway_ssh_host_key": self.pub["gateway_host"],
            "gateway_management_public_key": self.pub["gateway_management"],
            "reverse_listen_host": "127.0.0.1", "reverse_listen_port": 10003,
            "management_user": "ai-gateway",
            "device_tunnel_fingerprint": fingerprint(self.pub["tunnel"]),
            "device_host_fingerprint": fingerprint(self.pub["host"]),
        }
        self.approved = {
            "request_id": self.request_id, "device_id": "windows-wsl",
            "persistent": False, "access_mode": "restricted",
            "tunnel_public_key": self.pub["tunnel"],
            "host_public_key": self.pub["host"], "offer": self.offer,
        }
        self.registry = {"devices": [
            {"id": "raspberry-lab", "tunnel_port": 10001},
            {"id": "windows-wsl", "tunnel_port": 10002},
            {"id": "oracle-gateway", "tunnel_port": 10000},
        ]}

    def run_check(self, approved=None, registry=None, **pins):
        args = {
            "trusted_gateway_host_key": self.pub["gateway_host"],
            "independently_verified_target_host_key": self.pub["host"],
            "actual_gateway_management_public_key": self.pub["gateway_management"],
        }
        args.update(pins)
        return preflight_wsl_candidate(
            self.approved if approved is None else approved,
            protected_registry=self.registry if registry is None else registry,
            **args)

    def test_exact_restricted_pilot_preserves_legacy_and_root_is_not_granted(self):
        result = self.run_check()
        self.assertEqual(result, {
            "status": "candidate_preflight_ok", "device_id": "windows-wsl",
            "port": 10003, "access_mode": "restricted", "persistent": False,
            "registry_changed": False, "ssh_changed": False,
        })

    def test_independent_host_pin_and_real_sshd_identity_are_required(self):
        for changes in (
            {"trusted_gateway_host_key": self.pub["other"]},
            {"independently_verified_target_host_key": self.pub["other"]},
            {"actual_gateway_management_public_key": self.pub["other"]},
        ):
            with self.subTest(changes=changes), self.assertRaises(PermissionError):
                self.run_check(**changes)

    def test_reject_any_attempt_to_change_port_identity_or_permissions(self):
        for candidate_mod in (
            {"access_mode": "unrestricted"}, {"persistent": True},
            {"device_id": "oracle-gateway"}, {"sudo": True},
            {"tunnel_public_key": self.pub["gateway_host"]},
        ):
            with self.subTest(candidate_mod=candidate_mod), self.assertRaises(
                    (PermissionError, ValueError)):
                self.run_check(approved={**self.approved, **candidate_mod})
        for offer_mod in (
            {"reverse_listen_port": 10002},
            {"gateway_tunnel_user": "root"},
            {"management_user": "root"},
            {"reverse_listen_host": "0.0.0.0"},
        ):
            with self.subTest(offer_mod=offer_mod), self.assertRaises(
                    (PermissionError, ValueError)):
                approved = {**self.approved, "offer": {**self.offer, **offer_mod}}
                self.run_check(approved=approved)

    def test_unexpected_registry_or_port_assignment_fails_closed(self):
        cases = (
            {"devices": [{"id": "windows-wsl", "tunnel_port": 10003}]},
            {"devices": [
                {"id": "windows-wsl", "tunnel_port": 10002},
                {"id": "other-device", "tunnel_port": 10003}]},
            {"devices": [
                {"id": "windows-wsl", "tunnel_port": 10002},
                {"id": "windows-wsl", "tunnel_port": 10002}]},
            {"devices": [{"id": "windows-wsl", "tunnel_port": True}]},
            {"devices": [{"id": "windows-wsl", "tunnel_port": "10002"}]},
        )
        for registry in cases:
            with self.subTest(registry=registry), self.assertRaises(PermissionError):
                self.run_check(registry=registry)

    def test_missing_identity_fields_are_denied(self):
        invalid = dict(self.approved)
        del invalid["host_public_key"]
        with self.assertRaises(PermissionError):
            self.run_check(approved=invalid)
        with self.assertRaises(PermissionError):
            self.run_check(registry={"unexpected": "metadata"})


if __name__ == "__main__":
    unittest.main()
