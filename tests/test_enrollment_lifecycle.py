"""Unit tests: distinct invite, pending, independent review and activation phases."""
from concurrent.futures import ThreadPoolExecutor
import tempfile
from pathlib import Path
import unittest

from ai_lab_gateway.enrollment import EnrollmentStore, PENDING_APPROVAL_TTL
from test_enrollment import public_key


class ApprovalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = EnrollmentStore(Path(self.tmp.name) / "enrollment.sqlite3")

    def new_pending(self, *, moment=100):
        invite = self.store.invite("oauth-subject", now=moment)
        return self.store.claim(
            invite, device_id="new-linux-001", device_name="Lab Linux",
            tunnel_public_key=public_key(1),
            ssh_host_public_key=public_key(2),
            persistent=False, now=moment+1
        )

    def test_pending_request_separate_from_invitation(self):
        claimed = self.new_pending()
        self.assertEqual(claimed["status"], "pending")
        self.assertTrue(claimed["request_id"])
        requests = self.store.pending_requests(now=120)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["access_mode"], "restricted")
        self.assertEqual(requests[0]["operator_subject"], "oauth-subject")
        self.assertNotIn("token_hash", requests[0])

    def test_approval_requires_independent_human_and_is_one_time(self):
        claimed = self.new_pending()
        with self.assertRaises(ValueError):
            self.store.review(claimed["request_id"], human_actor="",
                              approve=True, now=105)
        approved = self.store.review(claimed["request_id"],
                                     human_actor="authenticated-ui", approve=True, now=110)
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["access_mode"], "restricted")
        self.assertEqual(self.store.pending_requests(now=120), [])
        with self.assertRaises(PermissionError):
            self.store.review(claimed["request_id"],
                              human_actor="authenticated-ui", approve=True, now=120)

    def test_denied_request_cannot_be_activated(self):
        claimed = self.new_pending()
        denied = self.store.review(claimed["request_id"], human_actor="human",
                                    approve=False, now=103)
        self.assertEqual(denied["status"], "denied")
        with self.assertRaises(PermissionError):
            self.store.activation_record(
                claimed["request_id"], host_public_key=public_key(2),
                tunnel_public_key=public_key(1), now=120
            )

    def test_approval_window_expires(self):
        claimed = self.new_pending()
        self.assertEqual(self.store.pending_requests(now=103), self.store.pending_requests(now=103))
        with self.assertRaises(PermissionError):
            self.store.review(
                claimed["request_id"], human_actor="human", approve=True,
                now=101 + PENDING_APPROVAL_TTL
            )
        self.assertEqual(self.store.pending_requests(now=101 + PENDING_APPROVAL_TTL), [])

    def test_stale_pending_does_not_block_same_device(self):
        self.new_pending()
        invitation2 = self.store.invite("oauth-subject", now=4000)
        pair2 = self.store.claim(
            invitation2, device_id="new-linux-001", device_name="Lab Linux",
            tunnel_public_key=public_key(3),
            ssh_host_public_key=public_key(4),
            persistent=True, now=4001
        )
        self.assertTrue(pair2["persistent"])

    def test_ssh_host_and_tunnel_pins_required_for_activation(self):
        claimed = self.new_pending()
        self.store.review(claimed["request_id"], human_actor="human",
                          approve=True, now=110)
        for badhost,badtunnel in [(public_key(2),public_key(3)),
                                  (public_key(3),public_key(1))]:
            with self.assertRaises(PermissionError):
                self.store.activation_record(
                    claimed["request_id"], host_public_key=badhost,
                    tunnel_public_key=badtunnel, now=112
                )
        active = self.store.activation_record(
            claimed["request_id"], host_public_key=public_key(2),
            tunnel_public_key=public_key(1), now=113
        )
        self.assertEqual(active["access_mode"], "restricted")
        self.assertEqual(active["status"], "active")
        with self.assertRaises(PermissionError):
            self.store.activation_record(
                claimed["request_id"], host_public_key=public_key(2),
                tunnel_public_key=public_key(1), now=114
            )

    def test_concurrent_review_one_wins(self):
        claimed = self.new_pending()
        def race(_):
            try:
                self.store.review(claimed["request_id"], human_actor="human",
                                  approve=True, now=110)
                return True
            except PermissionError:
                return False
        with ThreadPoolExecutor(max_workers=7) as executor:
            ok = list(executor.map(race, range(7)))
        self.assertEqual(sum(ok), 1)


if __name__ == "__main__":
    unittest.main()
