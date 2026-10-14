"""Browser pairing: password session+CSRF, no OTP for identity-only approval."""
import base64
import http.client
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
import urllib.parse

from test_enrollment import public_key


def load_ui():
    path = Path(__file__).resolve().parents[1] / "scripts" / "approval_web.py"
    spec = importlib.util.spec_from_file_location("pairing_approval_web_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PairingWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ui = load_ui()
        ui = self.ui
        self.password = "synthetic-pairing-test-password"
        salt = b"synthetic-random-salt"
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.secret = secret
        creds = Path(self.tmp.name) / "creds.json"
        creds.write_text(json.dumps({
            "version": 1, "salt": salt.hex(),
            "password_hash": ui.password_hash(self.password, salt).hex(),
            "totp_secret": secret
        }))
        ui.CREDENTIALS = creds
        ui.LAST_STEP_FILE = Path(self.tmp.name) / "last_totp_step"
        ui.SESSIONS.clear()
        ui.LOGIN_FORMS.clear()
        ui.FAILURES.clear()
        self.actions = []
        def pair_rpc(msg):
            self.actions.append(("pairing", msg))
            if msg["action"] == "list":
                return {"ok": True, "requests": [{
                    "request_id": "A" * 24,
                    "operator_subject": "verified-oauth-subject",
                    "device_id": "test-wsl-v2",
                    "device_name": "<script>alert(1)</script>",
                    "tunnel_public_key": public_key(1),
                    "ssh_host_public_key": public_key(2),
                    "persistent": False,
                    "approval_deadline": 5000000000
                }]}
            return {"ok": True, "status": "approved"}
        def admin_rpc(msg):
            self.actions.append(("broker", msg))
            if msg["action"] == "list":
                return {"ok": True, "requests": [{
                    "request_id": "B" * 24,
                    "operation": "gateway-service-status",
                    "subject": "verified-oauth-subject",
                    "device_id": "oracle-gateway",
                    "approval_deadline": 5000000000,
                    "ttl_seconds": 1800,
                }]}
            return {"ok": True}
        ui.pairing_rpc = pair_rpc
        ui.admin_rpc = admin_rpc
        self.server = ui.ThreadingHTTPServer(("127.0.0.1", 0), ui.ApprovalHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def req(self, method, path, form=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1",self.server.server_port,timeout=4)
        headers = {"Host": "gateway.debasti.com"}
        body = None
        if cookie:
            headers["Cookie"] = cookie
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        data = (response.status, dict(response.getheaders()), response.read().decode())
        conn.close()
        return data

    def login(self):
        status, headers, body = self.req("GET", "/approvals")
        self.assertEqual(status, 200)
        csrf = re.search(r"name='csrf' value='([^']+)'", body).group(1)
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, headers, _ = self.req("POST", "/approvals/login", {
            "password": self.password, "csrf": csrf
        }, cookie)
        self.assertEqual(status, 303)
        return headers["Set-Cookie"].split(";", 1)[0]

    def test_session_required_for_fingerprint_review(self):
        status,_,body=self.req("GET","/approvals/pairing")
        self.assertEqual(status,200)
        self.assertIn("Senha do aprovador",body)
        self.assertNotIn("verified-oauth-subject",body)

    def test_pairing_requires_csrf_but_no_totp(self):
        cookie=self.login()
        status,_,page=self.req("GET","/approvals/pairing",cookie=cookie)
        self.assertEqual(status,200)
        self.assertIn("SHA256:",page)
        self.assertIn("Restrito",page)
        self.assertIn("Persistente",page)
        self.assertNotIn("<script>",page)
        self.assertNotIn("Código do autenticador",page)
        csrf=re.search(r"name='csrf' value='([^']+)'",page).group(1)
        rid="A"*24
        self.assertEqual(self.req("POST","/approvals/pairing-decision",{
            "csrf":csrf,"request_id":rid,"decision":"approve"
        })[0],403)
        self.assertEqual(self.req("POST","/approvals/pairing-decision",{
            "csrf":"invalid","request_id":rid,"decision":"approve"
        },cookie)[0],403)
        self.assertEqual(self.req("POST","/approvals/pairing-decision",{
            "csrf":csrf,"request_id":rid,"decision":"approve"
        },cookie)[0],303)
        self.assertEqual(sum(
            typ=="pairing" and msg["action"]=="approve"
            for typ,msg in self.actions
        ),1)

    def test_root_broker_still_demands_totp(self):
        cookie=self.login()
        _,_,page=self.req("GET","/approvals",cookie=cookie)
        csrf=re.search(r"name='csrf' value='([^']+)'",page).group(1)
        self.assertEqual(self.req("POST","/approvals/decision",{
            "csrf":csrf,"request_id":"B"*24,
            "decision":"approve"
        },cookie)[0],403)
        self.assertEqual(sum(
            typ=="broker" and msg["action"]=="approve"
            for typ,msg in self.actions
        ),0)


if __name__ == "__main__":
    unittest.main()
