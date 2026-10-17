"""CI-only integration: existing independently approved broker -> signed root voucher.

The tests simulate the *already-authenticated* approver socket callback. They
do NOT prove a real human typed TOTP; that is separately tested/deployed.
No production secrets or host configuration are accessed.
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


broker = load_module("target_issuer_broker_test",
                     ROOT / "scripts" / "privilege_broker_daemon.py")
target = load_module("target_issuer_verifier_test",
                     ROOT / "scripts" / "ai-lab-target-privexec")


@unittest.skipUnless(os.geteuid() == 0, "root only in disposable CI runner")
class SignedHumanApprovalIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ai-lab-isolated-issuer-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.issuer = self.root / "issuer"
        self.issuer.mkdir(mode=0o700)
        self.device = "ai-lab-experiments-01-fd3dab34"
        self.subject = "auth0|synthetic-operator"
        key = self.issuer / "issuer_ed25519"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                        "-N", "", "-f", str(key)], check=True)
        key.chmod(0o600)
        self.write(self.issuer / "targets.json",
                   json.dumps({"version": 1, "devices": [self.device]}))
        self.server = self.root / "broker"
        self.server.mkdir(mode=0o700)
        self.write(self.server / "requests.lock", "")
        self.write(self.server / "requests-audit.jsonl", "")
        self.target_config = self.root / "target-config"
        self.target_state = self.root / "target-state"
        self.target_config.mkdir(mode=0o700)
        self.target_state.mkdir(mode=0o700)
        (self.target_state / "used").mkdir(mode=0o700)
        (self.target_state / "revoked").mkdir(mode=0o700)
        self.write(self.target_state / "lock", "")
        self.write(self.target_config / "device-id", self.device + "\n")
        pub = (self.issuer / "issuer_ed25519.pub").read_text().strip().split()
        self.write(self.target_config / "allowed_signers",
                   target.SIGNER + " " + " ".join(pub[:2]) + "\n")
        patches = [
            patch.multiple(
                broker,
                TARGET_ISSUER_DIR=self.issuer,
                TARGET_ISSUER_KEY=key,
                TARGET_DEVICES=self.issuer / "targets.json",
                STATE=self.server,
                DB=self.server / "requests.json",
                AUDIT=self.server / "requests-audit.jsonl",
                LOCK=self.server / "requests.lock",
            ),
            patch.multiple(target, CONFIG=self.target_config,
                           STATE=self.target_state),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    @staticmethod
    def write(path, payload):
        path.write_text(payload, encoding="utf-8")
        path.chmod(0o600)

    def request(self, subject=None, device=None, operation="root-identity-check"):
        return broker.dispatch({
            "action": "target_request", "subject": subject or self.subject,
            "device_id": device or self.device, "operation": operation,
            "ttl_seconds": 60})

    def voucher(self, request_id, subject=None, device=None):
        return broker.dispatch({
            "action": "target_voucher", "subject": subject or self.subject,
            "request_id": request_id, "device_id": device or self.device})

    def approve_via_web_socket(self, request_id, action="approve"):
        # Synthetic test stands in for the separate TOTP+CSRF approved
        # web handler. Production approval_dispatch is only reachable via
        # Unix socket with SO_PEERCRED=ai-lab-approver.
        return broker.approval_dispatch({"action": action,
                                          "request_id": request_id})

    def test_human_approved_signed_voucher_executes_one_root_operation(self):
        req = self.request()
        self.assertTrue(req["ok"], req)
        rid = req["request_id"]
        denied = self.voucher(rid)
        self.assertFalse(denied["ok"])
        self.assertEqual(denied["error"], "not_approved")
        approvals = broker.approval_dispatch({"action": "list"})
        review = next(r for r in approvals["requests"] if r["request_id"] == rid)
        self.assertEqual(review["device_id"], self.device)
        self.assertEqual(review["argv"], ["/usr/bin/id", "-u"])
        self.assertEqual(review["kind"], "target_single_use")
        approved = self.approve_via_web_socket(rid)
        self.assertTrue(approved["ok"])
        self.assertEqual(approved["status"], "approved")
        issued = self.voucher(rid)
        self.assertTrue(issued["ok"], issued)
        permit = issued["voucher"]["permit"]
        self.assertEqual(permit["device_id"], self.device)
        self.assertEqual(permit["subject"], self.subject)
        self.assertEqual(permit["operation"], "root-identity-check")
        self.assertLessEqual(permit["expires_at"]-permit["issued_at"], 60)
        raw = json.dumps(issued["voucher"]).encode("utf-8")
        self.assertEqual(target.execute_packet(raw), (0, "0\n"))
        with self.assertRaises(FileExistsError):
            target.execute_packet(raw)
        self.assertEqual(self.voucher(rid)["error"], "not_approved")
        self.assertEqual(broker.dispatch({
            "action": "status", "subject": self.subject,
            "device_id": self.device, "request_id": rid})["status"], "consumed")

    def test_identity_boundary_wrong_device_and_subject(self):
        req = self.request()
        rid = req["request_id"]
        self.assertFalse(self.voucher(rid, subject="auth0|different")["ok"])
        self.assertFalse(self.voucher(rid, device="raspberry-lab")["ok"])
        self.assertFalse(broker.dispatch({
            "action": "revoke", "request_id": rid, "subject": self.subject,
            "device_id": "raspberry-lab"})["ok"])
        self.assertTrue(self.approve_via_web_socket(rid)["ok"])
        self.assertFalse(self.voucher(rid, device="raspberry-lab")["ok"])
        self.assertTrue(self.voucher(rid)["ok"])

    def test_issuer_missing_by_default_and_bad_argv_fail_closed(self):
        self.issuer.joinpath("targets.json").unlink()
        self.assertFalse(self.request()["ok"])
        self.write(self.issuer / "targets.json", '{"version":1,"devices":["'+self.device+'"]}')
        self.assertFalse(self.request(operation="sudo-bash")["ok"])
        self.assertFalse(self.request(device="oracle-gateway")["ok"])
        self.assertFalse(self.request(device="raspberry-lab")["ok"])
        self.assertTrue(self.request()["ok"])

    def test_root_trust_permissions_and_symlinks_deny_signing(self):
        rid = self.request()["request_id"]
        self.assertTrue(self.approve_via_web_socket(rid)["ok"])
        self.issuer.joinpath("issuer_ed25519").chmod(0o644)
        self.assertEqual(self.voucher(rid)["error"], "signer_failed_closed")
        # Signing failure consumes prior consent, cannot retry after key repair.
        self.issuer.joinpath("issuer_ed25519").chmod(0o600)
        self.assertFalse(self.voucher(rid)["ok"])
        rid2 = self.request()["request_id"]
        self.assertTrue(self.approve_via_web_socket(rid2)["ok"])
        self.issuer.joinpath("targets.json").chmod(0o644)
        self.assertFalse(self.voucher(rid2)["ok"])

    def test_deny_and_revoke_never_sign(self):
        rid = self.request()["request_id"]
        self.assertTrue(self.approve_via_web_socket(rid, "deny")["ok"])
        self.assertFalse(self.voucher(rid)["ok"])
        rid = self.request()["request_id"]
        self.assertTrue(broker.dispatch({
            "action": "revoke", "subject": self.subject,
            "device_id": self.device, "request_id": rid})["ok"])
        self.assertFalse(self.approve_via_web_socket(rid)["ok"])
        self.assertFalse(self.voucher(rid)["ok"])


    def test_original_root_console_approve_exact_target_one_use(self):
        req = self.request()
        rid = req["request_id"]
        self.assertEqual(broker.admin("approve", rid), 77)
        self.assertFalse(self.voucher(rid)["ok"])
        self.assertEqual(broker.admin(
            "approve_target", rid,
            expected_device="raspberry-lab",
            expected_operation="root-identity-check"), 77)
        self.assertEqual(broker.admin(
            "approve_target", rid,
            expected_device=self.device,
            expected_operation="sudo-bash"), 77)
        state = broker.dispatch({
            "action": "status", "subject": self.subject,
            "device_id": self.device, "request_id": rid})
        self.assertEqual(state["status"], "pending")
        self.assertEqual(broker.admin(
            "approve_target", rid,
            expected_device=self.device,
            expected_operation="root-identity-check"), 0)
        self.assertEqual(broker.load()[rid]["approval_method"],
                         "separate_human_root_console")
        issued = self.voucher(rid)
        self.assertTrue(issued["ok"], issued)
        raw = json.dumps(issued["voucher"]).encode("utf8")
        self.assertEqual(target.execute_packet(raw), (0, "0\\n"))
        self.assertEqual(self.voucher(rid)["error"], "not_approved")
        with self.assertRaises(FileExistsError):
            target.execute_packet(raw)

    def test_root_console_does_not_approve_expired_or_denied_target(self):
        req = self.request()
        rid = req["request_id"]
        self.assertEqual(broker.admin("deny", rid), 0)
        self.assertEqual(broker.admin(
            "approve_target", rid,
            expected_device=self.device,
            expected_operation="root-identity-check"), 77)
        req2 = self.request()
        rid2 = req2["request_id"]
        state = broker.load()
        state[rid2]["approval_deadline"] = 1
        broker.save(state)
        self.assertEqual(broker.admin(
            "approve_target", rid2,
            expected_device=self.device,
            expected_operation="root-identity-check"), 77)
        self.assertFalse(self.voucher(rid2)["ok"])

    def test_legacy_oracle_broker_rejects_target_request_on_execute(self):
        req = self.request()
        rid = req["request_id"]
        self.assertTrue(self.approve_via_web_socket(rid)["ok"])
        result = broker.dispatch({
            "action": "execute", "subject": self.subject, "request_id": rid,
            "device_id": self.device})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "wrong_request_kind")


if __name__ == "__main__":
    unittest.main()
