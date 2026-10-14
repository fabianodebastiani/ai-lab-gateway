"""Regression tests for the separate, password+TOTP human approval UI."""
import base64
import http.client
import importlib.util
import json
import re
import secrets
import threading
import urllib.parse
from pathlib import Path

import pytest


@pytest.fixture
def ui(monkeypatch, tmp_path):
    path = Path(__file__).resolve().parents[1] / "scripts" / "approval_web.py"
    spec = importlib.util.spec_from_file_location("approval_web_test_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    salt = b"test_salt_for_lab"
    password = "very-strong-test-password"
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    config = {"version": 1, "salt": salt.hex(),
              "password_hash": module.password_hash(password, salt).hex(),
              "totp_secret": secret}
    location = tmp_path / "credentials.json"
    location.write_text(json.dumps(config))
    monkeypatch.setattr(module, "CREDENTIALS", location)
    module.SESSIONS.clear()
    module.LOGIN_FORMS.clear()
    module.FAILURES.clear()
    monkeypatch.setattr(module, "LAST_STEP_FILE", tmp_path / "last_totp_step")
    return module, password, secret


def test_totp_rfc6238_known_vector(ui):
    module, _, secret = ui
    assert module.totp(secret, 59) == "287082"
    assert module.valid_totp(secret, "287082", 59) == 1
    assert module.valid_totp(secret, "000000", 59) is None


def test_password_is_salted_and_verified(ui):
    module, password, _ = ui
    config = module.read_credentials()
    assert module.verify_password(password, config)
    assert module.verify_password("  " + password + "  ", config)
    assert not module.verify_password("incorrect", config)
    assert password not in module.CREDENTIALS.read_text()


def test_approval_web_login_otp_csrf_and_decision(ui, monkeypatch):
    module, password, secret = ui
    received = []
    rid = "test_request_one"
    def mock_broker(message):
        received.append(message)
        if message["action"] == "list":
            return {"ok": True, "requests": [{
                "request_id": rid,
                "operation": "gateway-service-status",
                "subject": "test-subject",
                "device_id": "oracle-gateway",
                "created_at": 1,
                "approval_deadline": 5_000_000_000,
                "ttl_seconds": 1800,
            }]}
        return {"ok": True, "status": "approved", "request_id": rid}
    monkeypatch.setattr(module, "admin_rpc", mock_broker)
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.ApprovalHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    def req(method, target, form=None, cookie=None, origin=True):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Host": "gateway.debasti.com"}
        if cookie:
            headers["Cookie"] = cookie
        body = None
        if form is not None:
            body = urllib.parse.urlencode(form)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            if origin is True:
                headers["Origin"] = module.SITE
            elif isinstance(origin, str):
                headers["Origin"] = origin
        conn.request(method, target, body=body, headers=headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read().decode("utf8")
        conn.close()
        return result

    try:
        status, login_headers, login_body = req("GET", "/approvals")
        assert status == 200
        login_cookie = login_headers["Set-Cookie"].split(";", 1)[0]
        match = re.search("name='csrf' value='([^']+)'", login_body)
        assert match
        login_csrf = match.group(1)
        assert req("POST", "/approvals/login", {"password": password})[0] == 403
        assert req("POST", "/approvals/login", {"password": "wrong", "csrf": login_csrf},
                   cookie=login_cookie)[0] == 403
        form = {"password": password, "csrf": login_csrf}
        status, headers, _ = req("POST", "/approvals/login", form,
                                 cookie=login_cookie, origin=False)
        assert status == 303
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert "Secure" in headers["Set-Cookie"] and "HttpOnly" in headers["Set-Cookie"]
        status, _, body = req("GET", "/approvals", cookie=cookie)
        assert status == 200 and rid in body
        match = re.search("name='csrf' value='([^']+)'", body)
        assert match
        csrf = match.group(1)
        fields = {"csrf": csrf, "request_id": rid, "decision": "approve",
                  "otp": module.totp(secret)}
        assert req("POST", "/approvals/decision", fields)[0] == 403
        assert req("POST", "/approvals/decision", fields, cookie=cookie,
                   origin="https://evil.example")[0] == 403
        assert not any(msg["action"] == "approve" for msg in received)
        assert req("POST", "/approvals/decision", fields, cookie=cookie)[0] == 303
        assert sum(msg["action"] == "approve" for msg in received) == 1
        assert req("POST", "/approvals/decision", fields, cookie=cookie)[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_totp_claim_is_persistent_across_restart(ui):
    module, _, _ = ui
    assert module.claim_totp_step(100000)
    assert not module.claim_totp_step(100000)
    assert not module.claim_totp_step(99999)
    assert module.LAST_STEP_FILE.read_text().strip() == "100000"
    assert module.claim_totp_step(100001)
    assert module.LAST_STEP_FILE.read_text().strip() == "100001"


def test_origin_policy_allows_safe_browser_fallback(ui):
    module, _, _ = ui
    handler = module.ApprovalHandler.__new__(module.ApprovalHandler)
    from email.message import Message

    def check(**headers):
        message = Message()
        for key, value in headers.items():
            message[key.replace("_", "-")] = value
        handler.headers = message
        return handler._origin_ok()

    base = {"Host": "gateway.debasti.com",
            "Content_Type": "application/x-www-form-urlencoded"}
    assert check(**base, Origin=module.SITE)
    assert check(**base, Sec_Fetch_Site="same-origin", Sec_Fetch_Mode="navigate")
    assert check(**base)  # CSRF required at a higher layer
    assert not check(**base, Origin="null", Sec_Fetch_Site="same-origin", Sec_Fetch_Mode="navigate")
    assert not check(**base, Origin="https://evil.example", Sec_Fetch_Site="same-origin", Sec_Fetch_Mode="navigate")
    assert not check(**base, Sec_Fetch_Site="cross-site", Sec_Fetch_Mode="navigate")
    assert not check(**base, Sec_Fetch_Site="same-site", Sec_Fetch_Mode="navigate")
    assert not check(**{**base, "Host": "wrong.example"}, Origin=module.SITE)


def test_login_csrf_cookie_is_bound_and_required(ui):
    module, _, _ = ui
    key, token = module.issue_login_csrf()
    assert module.verify_login_csrf("ai_lab_login=" + key, token)
    assert not module.verify_login_csrf("ai_lab_login=" + key, "wrong")
    assert not module.verify_login_csrf("", token)
    assert not module.verify_login_csrf("ai_lab_login=wrong", token)
