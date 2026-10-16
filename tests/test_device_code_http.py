"""Live loopback HTTP integration tests for ADR-029 (never production)."""
from contextlib import redirect_stdout
import base64
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import serialization
from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import (
    MAX_STARTS_PER_HOUR_PER_PEER, device_code_handler, run_device_code_server
)

CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "device_code_pair_linux.py"


def cli_module():
    spec = importlib.util.spec_from_file_location("device_code_cli_under_test", CLI_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeviceHTTPTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.store = DeviceCodeStore(self.root / "codes.sqlite", hmac_key=b"H" * 32)
        self.server = run_device_code_server(self.store)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.keys = {}
        for role in ("tunnel", "host", "wrong"):
            name = self.root / role
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(name)], check=True, capture_output=True)
            self.keys[role] = (name, Path(str(name) + ".pub").read_text().strip())

    def start_data(self, device_id="fresh-linux-01"):
        return {
            "device_id": device_id, "display_name": "Novo Linux",
            "tunnel_public_key": self.keys["tunnel"][1],
            "host_public_key": self.keys["host"][1],
            "persistent": False,
        }

    def request(self, path, payload, *, content_type="application/json",
                extra_headers=None, expected=201):
        headers = {"Content-Type": content_type}
        headers.update(extra_headers or {})
        req = urllib.request.Request(self.origin+path, data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as res:
                self.assertEqual(res.status, expected)
                self.assertEqual(res.headers["Cache-Control"], "no-store")
                self.assertEqual(res.headers["X-Content-Type-Options"], "nosniff")
                value = json.load(res)
                return value
        except urllib.error.HTTPError as err:
            self.assertEqual(err.code, expected)
            self.assertEqual(err.headers["Cache-Control"], "no-store")
            return json.load(err)

    def test_end_to_end_start_proof_then_code_lookup_requires_consent(self):
        pending = self.request("/pairing/device/start", self.start_data())
        self.assertRegex(pending["user_code"], "^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
        self.assertTrue(pending["device_secret"])
        challenge = base64.b64decode(pending["challenge_b64"])
        key = serialization.load_ssh_private_key(self.keys["tunnel"][0].read_bytes(), None)
        signed = base64.b64encode(key.sign(challenge)).decode()
        proof = self.request("/pairing/device/prove", {
            "request_id": pending["request_id"],
            "device_secret": pending["device_secret"],
            "signature_b64": signed,
        }, expected=200)
        self.assertEqual(proof["status"], "proven")
        pending_status = self.request("/pairing/device/poll", {
            "request_id": pending["request_id"],
            "device_secret": pending["device_secret"],
        }, expected=200)
        self.assertEqual(pending_status["status"], "proven")
        lookup = self.store.lookup(user_code=pending["user_code"],
                         operator_subject="auth0|test-operator")
        self.assertEqual(lookup["request_id"], pending["request_id"])
        self.assertNotIn("confirmation", lookup)
        with self.assertRaises(PermissionError):
            self.store.confirm(request_id=pending["request_id"],
                operator_subject="auth0|test-operator",
                confirmation="AAAA-AAAA")
        self.assertEqual(self.store.confirm(request_id=pending["request_id"],
                operator_subject="auth0|test-operator",
                confirmation=pending["confirmation"])["status"],"approved")
        unknown = self.request("/pairing/device/poll", {
            "request_id": pending["request_id"],
            "device_secret": "X" * 43
        }, expected=403)
        self.assertEqual(unknown, {"error": "pairing_unavailable"})

    def test_bad_public_input_does_not_approve_or_leak_secrets(self):
        malformed = self.request("/pairing/device/start", {
            **self.start_data(), "force_access": "unrestricted",
        }, expected=403)
        self.assertEqual(malformed, {"error": "pairing_unavailable"})
        bad_type = self.request("/pairing/device/start", {
            **self.start_data(), "persistent": "true",
        }, expected=403)
        self.assertEqual(bad_type, {"error": "pairing_unavailable"})
        bad_mime = self.request("/pairing/device/start", self.start_data(),
                                content_type="text/plain", expected=415)
        self.assertEqual(bad_mime["error"], "json_required")
        bad_path = self.request("/pairing/device/approve", self.start_data(),
                                expected=404)
        self.assertEqual(bad_path["error"], "not_found")
        req = urllib.request.Request(self.origin+"/pairing/device/health", method="GET")
        with urllib.request.urlopen(req, timeout=5) as health:
            self.assertEqual(json.load(health), {"status": "ok"})

    def test_source_rate_limit_uses_tcp_peer_not_untrusted_forwarded_header(self):
        # Distinct device IDs avoid the per-ID pending quota; the source quota
        # rejects long before the transport quota. Repeated requests still
        # count and cannot use a spoofed X-Forwarded-For header to evade it.
        for i in range(MAX_STARTS_PER_HOUR_PER_PEER):
            response=self.request("/pairing/device/start",
                self.start_data("fresh-linux-%02d" % i),
                extra_headers={"X-Forwarded-For": "192.0.2.%d" % (i+1)},
                expected=(201 if i < 4 else 403))
            self.assertIn(("user_code" if i < 4 else "error"), response)
        blocked=self.request("/pairing/device/start",
               self.start_data("fresh-linux-over-limit"),
               extra_headers={"X-Forwarded-For": "198.51.100.1"},
               expected=429)
        self.assertEqual(blocked, {"error": "rate_limited"})

    def test_linux_cli_starts_and_proves_without_old_ssh_or_mcp(self):
        cli = cli_module()
        state = self.root / "brand-new-user-ssh" / "device-code"
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cli.run(url=self.origin, device_id="fresh-linux-01",
                   name="Linux independente", persistent=False,
                   state_dir=state,
                   host_key_path=Path(str(self.keys["host"][0])+".pub"),
                   wait=False)
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("No ChatGPT: Conectar dispositivo", output)
        self.assertNotIn("Confirmação:", output)
        user_code = re.search(r"Código: ([A-Z2-9]{4}-[A-Z2-9]{4})", output).group(1)
        looked_up = self.store.lookup(user_code=user_code,operator_subject="auth0|owner")
        self.assertEqual(looked_up["status"], "awaiting_human_confirmation")
        self.assertEqual(stat.S_IMODE(state.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE((state/"tunnel-ed25519").stat().st_mode),0o600)
        self.assertNotIn("device_secret",output)
        self.assertNotIn("challenge_b64",output)

    def test_client_rejects_insecure_remote_url(self):
        cli = cli_module()
        with self.assertRaises(ValueError):
            cli.base_url("http://gateway.debasti.com")
        with self.assertRaises(ValueError):
            cli.base_url("https://user:pass@gateway.debasti.com")
        with self.assertRaises(ValueError):
            cli.base_url("https://gateway.debasti.com/attacker")
        self.assertEqual(cli.base_url("http://127.0.0.1:8899"),
                         "http://127.0.0.1:8899")
        self.assertEqual(cli.base_url("https://gateway.debasti.com"),
                         "https://gateway.debasti.com")


if __name__ == "__main__":
    unittest.main()
