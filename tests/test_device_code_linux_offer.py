"""Non-root Linux-side SSH public offer acceptance: fail closed and no install."""
import importlib.util
import base64
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import urllib.request
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import run_device_code_server


CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "device_code_pair_linux.py"
spec = importlib.util.spec_from_file_location("device_code_linux_offer_client", CLI_PATH)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


class LinuxSSHOfferTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.keys = {}
        for role in ("gateway_host", "gateway_manage", "device_tunnel", "device_host", "attacker"):
            p = self.root / role
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(p)], check=True, capture_output=True)
            self.keys[role] = client.ed25519_public(
                Path(str(p) + ".pub").read_text(encoding="ascii"))
        self.req = "LabRequestABCD1234567890abcdef"
        self.dev = "fresh-linux-offer"
        self.offer = {
            "version": client.OFFER_VERSION,
            "request_id": self.req,
            "device_id": self.dev,
            "access_mode": "restricted",
            "persistent": False,
            "gateway_host": "gateway.debasti.com",
            "gateway_ssh_port": 22,
            "gateway_tunnel_user": "tunnel",
            "gateway_ssh_host_key": self.keys["gateway_host"],
            "gateway_management_public_key": self.keys["gateway_manage"],
            "reverse_listen_host": "127.0.0.1",
            "reverse_listen_port": 10011,
            "management_user": "ai-gateway",
            "device_tunnel_fingerprint": client.fingerprint(self.keys["device_tunnel"]),
            "device_host_fingerprint": client.fingerprint(self.keys["device_host"]),
        }

    def validate(self, offer=None, pin=None):
        return client.validate_connection_offer(
            offer if offer is not None else self.offer,
            request_id=self.req, device_id=self.dev, persistent=False,
            tunnel_key=self.keys["device_tunnel"],
            host_key=self.keys["device_host"],
            trusted_gateway_host_key=self.keys["gateway_host"] if pin is None else pin)

    def poll(self, status="approved", offer=None, pin=None, **extra):
        response = {"status": status, "request_id": self.req, "access_mode": "restricted"}
        if offer is not None:
            response["connection_offer"] = offer
        response.update(extra)
        return client.validate_poll_response(
            response, request_id=self.req, device_id=self.dev, persistent=False,
            tunnel_key=self.keys["device_tunnel"],
            host_key=self.keys["device_host"],
            trusted_gateway_host_key=pin)

    def test_accepts_exact_verified_offer_without_side_effects(self):
        self.assertEqual(self.validate(), self.offer)
        self.assertEqual(self.poll(offer=self.offer, pin=self.keys["gateway_host"]),
                         self.offer)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()),
                         sorted([role + suffix for role in self.keys for suffix in ("", ".pub")]))
        self.assertIsNone(self.poll(status="proven"))
        self.assertIsNone(self.poll(status="approved"))

    def test_never_trusts_gateway_key_from_offer_itself(self):
        with self.assertRaises(PermissionError):
            self.poll(offer=self.offer, pin=None)
        with self.assertRaises(PermissionError):
            self.validate(pin=self.keys["attacker"])
        switched = {**self.offer, "gateway_ssh_host_key": self.keys["attacker"]}
        with self.assertRaises(PermissionError):
            self.validate(switched)

    def test_rejects_unapproved_and_unbound_status(self):
        for status in ("pending", "proven", "expired", "denied"):
            with self.subTest(status=status), self.assertRaises(PermissionError):
                self.poll(status=status, offer=self.offer, pin=self.keys["gateway_host"])
        for changed in ({"request_id": "other"}, {"access_mode": "unrestricted"},
                        {"invented": True}, {"status": "unknown"}):
            with self.subTest(changed=changed), self.assertRaises((PermissionError, ValueError)):
                self.poll(offer=self.offer, pin=self.keys["gateway_host"], **changed)
        with self.assertRaises(PermissionError):
            self.poll(status="active")

    def test_rejects_tampered_fields_and_unsafe_ports(self):
        mutations = [
            {"request_id": "other"}, {"device_id": "other"},
            {"access_mode": "unrestricted"}, {"persistent": True},
            {"gateway_host": "attacker.invalid"}, {"gateway_ssh_port": 2222},
            {"gateway_tunnel_user": "root"}, {"management_user": "root"},
            {"reverse_listen_host": "0.0.0.0"},
            {"reverse_listen_port": 22}, {"reverse_listen_port": True},
            {"reverse_listen_port": "10011"}, {"version": "unknown"},
            {"device_host_fingerprint": client.fingerprint(self.keys["attacker"])},
            {"device_tunnel_fingerprint": client.fingerprint(self.keys["attacker"])},
            {"gateway_management_public_key": self.keys["attacker"] + " extra"},
            {"gateway_management_public_key": self.keys["gateway_host"]},
            {"new_command": "sudo -i"},
        ]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises((ValueError, PermissionError)):
                self.validate({**self.offer, **change})

    def test_protected_pin_file_is_required(self):
        pin = self.root / "trusted_gateway.pub"
        pin.write_text(self.keys["gateway_host"] + "\n", encoding="ascii")
        pin.chmod(0o600)
        self.assertEqual(client.load_trusted_gateway_host_key(pin), self.keys["gateway_host"])
        pin.chmod(0o666)
        with self.assertRaises(PermissionError):
            client.load_trusted_gateway_host_key(pin)
        pin.chmod(0o600)
        alias = self.root / "symlink_pin"
        alias.symlink_to(pin)
        with self.assertRaises(PermissionError):
            client.load_trusted_gateway_host_key(alias)
        with self.assertRaises(PermissionError):
            client.load_trusted_gateway_host_key(None)


    def test_http_redirect_never_reaches_target(self):
        visited = []
        redirect_status = [302]

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                visited.append(("POST", self.path))
                self.send_response(redirect_status[0])
                self.send_header("Location", "/stolen")
                self.end_headers()

            def do_GET(self):
                visited.append(("GET", self.path))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                return

        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                base = "http://127.0.0.1:" + str(server.server_port)
                for code in (301, 302, 303, 307, 308):
                    redirect_status[0] = code
                    with self.subTest(code=code), self.assertRaises(
                            (PermissionError, urllib.error.HTTPError)):
                        client.post(base, "/pairing/device/poll",
                                    {"device_secret": "do-not-forward"})
                self.assertEqual(visited, [("POST", "/pairing/device/poll")] * 5)
            finally:
                server.shutdown()
                worker.join(timeout=3)


    def test_approved_offer_reaches_linux_validator_over_real_loopback_http(self):
        """Full laboratory HTTP polling, still no SSH installer or root action."""
        store = DeviceCodeStore(self.root / "offer.sqlite", hmac_key=b"L" * 32)
        started = store.start(
            device_id=self.dev, display_name="Linux offer lab",
            source_id="127.0.0.1", persistent=False,
            tunnel_public_key=self.keys["device_tunnel"],
            host_public_key=self.keys["device_host"])
        private = serialization.load_ssh_private_key(
            (self.root / "device_tunnel").read_bytes(), password=None)
        proof = base64.b64encode(
            private.sign(base64.b64decode(started["challenge_b64"]))).decode("ascii")
        store.prove(request_id=started["request_id"],
                    device_secret=started["device_secret"], signature_b64=proof)
        store.lookup(user_code=started["user_code"],
                     operator_subject="auth0|test-person")
        store.confirm(request_id=started["request_id"],
                      operator_subject="auth0|test-person",
                      confirmation=started["confirmation"])
        offer = {**self.offer, "request_id": started["request_id"]}
        store.stage_connection_offer(
            request_id=started["request_id"], offer=offer,
            trusted_gateway_host_public_key=self.keys["gateway_host"],
            provisioner_verified=True)
        with run_device_code_server(store) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                origin = "http://127.0.0.1:" + str(server.server_port)
                polled = client.post(origin, "/pairing/device/poll", {
                    "request_id": started["request_id"],
                    "device_secret": started["device_secret"]})
                self.assertEqual(polled["status"], "approved")
                self.assertEqual(client.validate_poll_response(
                    polled, request_id=started["request_id"],
                    device_id=self.dev, persistent=False,
                    tunnel_key=self.keys["device_tunnel"],
                    host_key=self.keys["device_host"],
                    trusted_gateway_host_key=self.keys["gateway_host"]), offer)
            finally:
                server.shutdown()
                worker.join(timeout=3)


    def test_stage_linux_candidate_does_not_edit_ssh_system_files(self):
        state = self.root / "linux-state"
        marker = self.root / "legacy-ssh-untouched"
        marker.write_text("old tunnel port 10002\n")
        target = client.stage_local_candidate(
            self.offer, state_dir=state, request_id=self.req,
            device_id=self.dev, persistent=False,
            tunnel_key=self.keys["device_tunnel"],
            host_key=self.keys["device_host"],
            trusted_gateway_host_key=self.keys["gateway_host"])
        self.assertEqual(target.parent, state)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        for p in target.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(json.loads((target/"offer.json").read_text()), self.offer)
        self.assertEqual((target/"management-authorized_keys.append").read_text(),
                         self.keys["gateway_manage"] + "\n")
        self.assertEqual((target/"gateway-known_hosts.append").read_text(),
                         "gateway.debasti.com " + self.keys["gateway_host"] + "\n")
        self.assertEqual(marker.read_text(), "old tunnel port 10002\n")
        self.assertFalse(any("PRIVATE KEY" in p.read_text() for p in target.iterdir()))
        with self.assertRaises(FileExistsError):
            client.stage_local_candidate(
                self.offer, state_dir=state, request_id=self.req,
                device_id=self.dev, persistent=False,
                tunnel_key=self.keys["device_tunnel"],
                host_key=self.keys["device_host"],
                trusted_gateway_host_key=self.keys["gateway_host"])

    def test_local_staging_rejects_unpinned_offer_without_files(self):
        state = self.root / "linux-state"
        with self.assertRaises(PermissionError):
            client.stage_local_candidate(
                self.offer, state_dir=state, request_id=self.req,
                device_id=self.dev, persistent=False,
                tunnel_key=self.keys["device_tunnel"],
                host_key=self.keys["device_host"],
                trusted_gateway_host_key=self.keys["attacker"])
        self.assertFalse(state.exists())
        symlink = self.root / "alias-state"
        symlink.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(PermissionError):
            client.stage_local_candidate(
                self.offer, state_dir=symlink, request_id=self.req,
                device_id=self.dev, persistent=False,
                tunnel_key=self.keys["device_tunnel"],
                host_key=self.keys["device_host"],
                trusted_gateway_host_key=self.keys["gateway_host"])



if __name__ == "__main__":
    unittest.main()
