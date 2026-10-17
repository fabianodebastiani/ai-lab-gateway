"""Isolated, no-IO tests for restricted WSL registration plan."""
import copy
import unittest

from ai_lab_gateway.device_code_registration_plan import (
    plan_restricted_wsl_registration, PERMITTED_ACTIONS)
from ai_lab_gateway.registry import Device


class RegistrationPlanTests(unittest.TestCase):
    def setUp(self):
        self.registry = {"devices": [
            {"id": "raspberry-lab", "name": "Raspberry",
             "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
             "tunnel_port": 10001, "identity_file": "/keys/pi"},
            {"id": "windows-wsl", "name": "Existing WSL",
             "ssh_user": "ai-gateway", "tunnel_host": "127.0.0.1",
             "tunnel_port": 10002, "identity_file": "/keys/wsl"},
        ]}
        self.policy = {"users": [
            {"subject": "auth0|owner", "devices": {
                "windows-wsl": ["status", "exec"],
                "raspberry-lab": ["status"]}},
            {"subject": "auth0|visitor", "devices": {
                "raspberry-lab": ["status"]}},
        ]}
        self.identity = {
            "request_id": "ABCDEFGHIJKLMNOPQRSTUVWX",
            "device_id": "laptop-5rjj0kbm-8210ee98",
            "device_name": "LAPTOP-5RJJ0KBM",
            "operator_subject": "auth0|owner",
            "access_mode": "restricted",
            "persistent": False, "reverse_listen_port": 10003,
        }

    def make(self, *, registry=None, policy=None, identity=None):
        return plan_restricted_wsl_registration(
            protected_registry=self.registry if registry is None else registry,
            protected_policy=self.policy if policy is None else policy,
            approved_identity=self.identity if identity is None else identity)

    def test_plan_preserves_originals_and_grants_only_verified_operator(self):
        old = copy.deepcopy((self.registry, self.policy, self.identity))
        new_registry, new_policy = self.make()
        self.assertEqual((self.registry, self.policy, self.identity), old)
        self.assertEqual(new_registry["devices"][:2], self.registry["devices"])
        new_device = Device.from_dict(new_registry["devices"][-1])
        self.assertEqual(new_device.id, self.identity["device_id"])
        self.assertEqual(new_device.ssh_user, "ai-gateway")
        self.assertEqual(new_device.tunnel_host, "127.0.0.1")
        self.assertEqual(new_device.tunnel_port, 10003)
        self.assertEqual(new_device.identity_file,
            "/etc/ai-lab-gateway/device-code-keys/wsl-10003/identity")
        self.assertEqual(new_policy["users"][0]["devices"][self.identity["device_id"]],
                         list(PERMITTED_ACTIONS))
        self.assertNotIn(self.identity["device_id"],
                         new_policy["users"][1]["devices"])
        self.assertEqual(new_policy["users"][1], self.policy["users"][1])
        self.assertEqual(new_policy["users"][0]["devices"]["windows-wsl"],
                         ["status", "exec"])

    def test_no_unapproved_id_port_owner_access_or_extra_fields(self):
        for change in (
            {"device_id": "oracle-experiments"},
            {"reverse_listen_port": 10002},
            {"reverse_listen_port": 10004},
            {"reverse_listen_port": True},
            {"access_mode": "partial"},
            {"access_mode": "unrestricted"},
            {"persistent": True},
            {"operator_subject": "auth0|unrecognized"},
            {"operator_subject": ""},
            {"request_id": "invalid"},
            {"device_name": ""},
            {"ssh_user": "root"},
            {"identity_file": "/etc/shadow"},
            {"sudo": True},
        ):
            with self.subTest(change=change):
                with self.assertRaises(PermissionError):
                    self.make(identity=dict(self.identity, **change))

    def test_duplicate_device_port_and_permissions_denied(self):
        for overlap in (
            {"id": self.identity["device_id"], "tunnel_port": 11000},
            {"id": "another", "tunnel_port": 10003},
        ):
            bad = copy.deepcopy(self.registry)
            bad["devices"].append(overlap)
            with self.subTest(overlap=overlap):
                with self.assertRaises(PermissionError):
                    self.make(registry=bad)
        bad = copy.deepcopy(self.policy)
        bad["users"][0]["devices"][self.identity["device_id"]] = ["status"]
        with self.assertRaises(PermissionError):
            self.make(policy=bad)

    def test_existing_wsl_cannot_be_reassigned(self):
        bad = copy.deepcopy(self.registry)
        bad["devices"] = [d for d in bad["devices"] if d["id"] != "windows-wsl"]
        with self.assertRaises(PermissionError):
            self.make(registry=bad)

    def test_auth0_subject_collision_denied(self):
        bad = copy.deepcopy(self.policy)
        bad["users"].append(copy.deepcopy(bad["users"][0]))
        with self.assertRaises(PermissionError):
            self.make(policy=bad)


if __name__ == "__main__":
    unittest.main()
