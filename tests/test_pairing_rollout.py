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

    def test_health_retry_handles_delayed_service_start(self):
        import subprocess
        from types import SimpleNamespace
        delayed = subprocess.CalledProcessError(7, ["curl", "health"])
        with patch.object(self.m, "run", side_effect=[
            delayed, delayed, SimpleNamespace(stdout='{"status":"ok"}')
        ]) as call, patch.object(self.m.time, "sleep") as sleep:
            reply = self.m.wait_for_health("http://127.0.0.1:8002/pairing/health",
                                           timeout_seconds=5)
        self.assertEqual(reply["status"], "ok")
        self.assertEqual(call.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_plain_text_health_is_accepted_only_for_approved_endpoint(self):
        from types import SimpleNamespace
        with patch.object(self.m, "run", return_value=SimpleNamespace(stdout="ok\\n")):
            self.assertEqual(
                self.m.wait_for_health("https://gateway.debasti.com/approvals/health",
                                       plain_ok=True, timeout_seconds=1),
                {"status": "ok"}
            )
        with patch.object(self.m, "run", return_value=SimpleNamespace(stdout="ok\\n")), patch.object(
            self.m.time, "monotonic", side_effect=[0, 2]
        ), patch.object(self.m.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                self.m.wait_for_health("https://gateway.debasti.com/pairing/health",
                                       timeout_seconds=1)

    def test_health_timeout_is_finite_and_fails_closed(self):
        import subprocess
        with patch.object(self.m, "run", side_effect=subprocess.CalledProcessError(
            7, ["curl", "health"]
        )), patch.object(self.m.time, "monotonic", side_effect=[10.0, 10.4, 11.1]), patch.object(
            self.m.time, "sleep"
        ):
            with self.assertRaisesRegex(RuntimeError, "did not become ready"):
                self.m.wait_for_health("http://127.0.0.1:8002/pairing/health",
                                       timeout_seconds=1)

    def test_check_refuses_unprivileged_execution(self):
        with patch.object(self.m.os, "geteuid",return_value=1003):
            with self.assertRaises(PermissionError):
                self.m.verify_stage()


if __name__=="__main__":
    unittest.main()
