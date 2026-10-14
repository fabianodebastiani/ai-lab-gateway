"""Unit tests for manifest-pinned Oracle v2 deployment planning (no root needed)."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def load():
    path = Path(__file__).resolve().parents[1] / "scripts/install_pairing_pilot_oracle.py"
    spec = importlib.util.spec_from_file_location("oracle_pairing_rollout_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RolloutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m=load()

    def test_source_manifest_matches_destinations(self):
        self.assertEqual(set(self.m.EXPECTED),set(self.m.DEST))
        self.assertEqual(len(self.m.EXPECTED),14)
        self.assertTrue(all(len(x)==64 for x in self.m.EXPECTED.values()))

    def test_policy_extends_one_existing_supervised_user_only(self):
        policy={"users":[
            {"subject":"user-a","devices":{"oracle-gateway":["exec","privilege_request"],
                                           "raspberry-lab":["status"]}},
            {"subject":"user-b","devices":{"oracle-gateway":["status"]}},
        ]}
        result=json.loads(self.m.policy_with_enrollment_grant(
            json.dumps(policy).encode()
        ))
        self.assertIn("device_enroll",
                      result["users"][0]["devices"]["oracle-gateway"])
        self.assertNotIn("device_enroll",
                         result["users"][1]["devices"]["oracle-gateway"])
        self.assertEqual(result["users"][0]["devices"]["raspberry-lab"],["status"])
        again=json.loads(self.m.policy_with_enrollment_grant(
            json.dumps(result).encode()))
        self.assertEqual(result,again)

    def test_ambiguous_admins_refused(self):
        for users in [[],[
            {"subject":"one","devices":{"oracle-gateway":["privilege_request"]}},
            {"subject":"two","devices":{"oracle-gateway":["privilege_request"]}}
        ]]:
            with self.assertRaises(RuntimeError):
                self.m.policy_with_enrollment_grant(
                    json.dumps({"users":users}).encode()
                )

    def test_caddy_route_added_before_existing_routes(self):
        original=b"""gateway.debasti.com {
    handle /approvals* {
        reverse_proxy 127.0.0.1:8001
    }
    handle {
        reverse_proxy 127.0.0.1:8000
    }
}
"""
        result=self.m.caddy_with_pairing(original).decode()
        self.assertLess(result.index("handle /pairing/*"),
                        result.index("handle /approvals*"))
        self.assertIn("reverse_proxy 127.0.0.1:8002",result)
        self.assertIn("reverse_proxy 127.0.0.1:8000",result)
        with self.assertRaises(RuntimeError):
            self.m.caddy_with_pairing(result.encode())

    def test_check_refuses_unprivileged_execution(self):
        with patch.object(self.m.os, "geteuid",return_value=1003):
            with self.assertRaises(PermissionError):
                self.m.verify_stage()


if __name__=="__main__":
    unittest.main()
