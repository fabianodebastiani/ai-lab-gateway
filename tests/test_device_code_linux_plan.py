"""Generic Linux onboarding contract: no network, root or service changes."""
import copy
from pathlib import Path
import subprocess
import tempfile
import unittest

from ai_lab_gateway.device_code_linux_plan import (
    plan_generic_linux_enrollment, choose_loopback_port, SSH_ACTIONS
)


class GenericLinuxPlanTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory(prefix="lab-generic-plan-")
        self.addCleanup(td.cleanup)
        p = Path(td.name)
        keys = []
        for i in range(4):
            file = p / str(i)
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519",
                            "-N", "", "-f", str(file)],
                           check=True, capture_output=True, timeout=7)
            keys.append(" ".join(file.with_suffix(".pub").read_text().split()[:2]))
        self.tunnel, self.host, self.gateway, self.management = keys
        self.registry = {"devices": [
            {"id": "raspberry-lab", "name": "Raspberry Pi",
             "tunnel_host": "127.0.0.1", "tunnel_port": 10001,
             "ssh_user": "ai-gateway", "identity_file": "/keys/pi"},
            {"id": "windows-wsl", "name": "Existing WSL",
             "tunnel_host": "127.0.0.1", "tunnel_port": 10002,
             "ssh_user": "ai-gateway", "identity_file": "/keys/wsl"},
        ]}
        self.policy = {"users": [
            {"subject": "auth0|owner",
             "devices": {"windows-wsl": ["status", "exec"]}},
            {"subject": "auth0|other",
             "devices": {"raspberry-lab": ["status"]}},
        ]}
        self.candidate = {
            "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
            "device_id": "ai-lab-experiments-01-aabbccdd",
            "device_name": "AI Lab Experiments Oracle VM",
            "operator_subject": "auth0|owner",
            "tunnel_public_key": self.tunnel, "host_public_key": self.host,
            "persistent": True, "expires_at": 9999999999,
        }

    def plan(self, *, candidate=None, registry=None, policy=None,
             reserved=(11000, 11001)):
        return plan_generic_linux_enrollment(
            approved_candidate=self.candidate if candidate is None else candidate,
            registry=self.registry if registry is None else registry,
            policy=self.policy if policy is None else policy,
            reserved_ports=reserved,
            gateway_ssh_host_key=self.gateway,
            gateway_management_public_key=self.management,
        )

    def test_second_oracle_vm_is_supported_without_replacing_wsl(self):
        before = copy.deepcopy((self.registry, self.policy, self.candidate))
        offer, registry, acl = self.plan()
        self.assertEqual((self.registry, self.policy, self.candidate), before)
        self.assertEqual(offer["device_id"], self.candidate["device_id"])
        self.assertEqual(offer["access_mode"], "restricted")
        self.assertTrue(offer["persistent"])
        self.assertEqual(offer["reverse_listen_host"], "127.0.0.1")
        self.assertEqual(offer["reverse_listen_port"], 11002)
        self.assertEqual(offer["management_user"], "ai-gateway")
        self.assertEqual(registry["devices"][:2], self.registry["devices"])
        self.assertEqual(registry["devices"][-1]["identity_file"],
                         "/etc/ai-lab-gateway/device-code-keys/"
                         "ai-lab-experiments-01-aabbccdd/identity")
        self.assertNotIn("private_key", offer)
        self.assertNotIn("operator_subject", offer)
        self.assertEqual(acl["users"][0]["devices"][self.candidate["device_id"]],
                         list(SSH_ACTIONS))
        self.assertNotIn(self.candidate["device_id"], acl["users"][1]["devices"])

    def test_laptop_and_pi_same_generic_flow_on_demand(self):
        for device_id in ("laptop-5rjj0kbm-fedcba98",
                          "raspberry-remote-b91a2b34",
                          "ordinary-linux-abcd1234"):
            with self.subTest(device_id=device_id):
                c = dict(self.candidate, device_id=device_id, persistent=False)
                offer, r, a = self.plan(candidate=c, reserved=())
                self.assertFalse(offer["persistent"])
                self.assertEqual(offer["reverse_listen_port"], 11000)
                self.assertEqual(r["devices"][-1]["id"], device_id)
                self.assertEqual(
                    a["users"][0]["devices"][device_id], list(SSH_ACTIONS))

    def test_reserved_and_registered_ports_are_not_reused(self):
        existing = copy.deepcopy(self.registry)
        existing["devices"].append(
            {"id": "another-device", "name": "Other Linux",
             "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
             "tunnel_port": 11000, "identity_file": "/keys/a"})
        self.assertEqual(choose_loopback_port(
            registry=existing, reserved_ports=(11001,)), 11002)

    def test_bad_candidates_fail_closed(self):
        bad = [
            {"device_id": "../etc/sudoers"},
            {"device_id": "a" * 60},
            {"operator_subject": "auth0|not-approved"},
            {"operator_subject": ""},
            {"persistent": 1},
            {"expires_at": "forever"},
            {"tunnel_public_key": self.host},
            {"host_public_key": self.tunnel},
            {"management_user": "root"},
            {"reverse_listen_port": 9999},
            {"access_mode": "unrestricted"},
            {"sudo": True},
        ]
        for change in bad:
            with self.subTest(change=change):
                with self.assertRaises((PermissionError, ValueError)):
                    self.plan(candidate=dict(self.candidate, **change))

    def test_legacy_device_cannot_be_overwritten(self):
        with self.assertRaises(PermissionError):
            self.plan(candidate=dict(self.candidate, device_id="windows-wsl"))
        bad = copy.deepcopy(self.policy)
        bad["users"][1]["devices"][self.candidate["device_id"]] = ["exec"]
        with self.assertRaises(PermissionError):
            self.plan(policy=bad)

    def test_port_range_exhausted_and_invalid_reserved_denied(self):
        with self.assertRaises(PermissionError):
            choose_loopback_port(
                registry=self.registry, reserved_ports=tuple(range(11000, 12000)))
        with self.assertRaises(PermissionError):
            choose_loopback_port(registry=self.registry, reserved_ports=(True,))


if __name__ == "__main__":
    unittest.main()
