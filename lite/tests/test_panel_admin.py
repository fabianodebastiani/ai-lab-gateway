import base64
import json
from itsdangerous import TimestampSigner
from starlette.testclient import TestClient

from ai_lab_gateway_lite.panel import create_panel
from ai_lab_gateway_lite.store import Store


def test_administrator_can_add_device_and_grant_access(tmp_path, monkeypatch):
    base = "https://ai-gateway-lite.debasti.com"
    secret = "synthetic-test-session-secret-over-32-characters"
    monkeypatch.setenv("LITE_BASE_URL", base)
    monkeypatch.setenv("LITE_SESSION_SECRET", secret)
    monkeypatch.setenv("LITE_WEB_CLIENT_ID", "test-client")
    monkeypatch.setenv("LITE_WEB_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("LITE_OAUTH_ISSUER", "https://test.auth0.com/")
    monkeypatch.setenv("LITE_ADMIN_SUBJECTS", "google-oauth2|admin")
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    store = Store(tmp_path / "db.sqlite")
    store.initialize()
    store.record_user("google-oauth2|natan", "natan@example.invalid", "Natan")

    # Synthetic signed session: tests the exact panel code without contacting Auth0.
    data = base64.b64encode(json.dumps({
        "sub": "google-oauth2|admin", "email": "admin@example.invalid", "csrf": "test-csrf"
    }).encode())
    signed = TimestampSigner(secret).sign(data).decode()

    with TestClient(create_panel(store), base_url=base) as client:
        client.cookies.set("lite_admin_session", signed, domain="ai-gateway-lite.debasti.com")
        response = client.get("/admin")
        assert response.status_code == 200
        assert "Natan" in response.text
        fields = {
            "csrf": "test-csrf", "id": "linux-lab", "name": "Linux Lab",
            "host": "10.200.0.8", "port": "22", "ssh_user": "ai-gateway",
            "key_name": "linux-lab", "enabled": "on",
        }
        response = client.post("/admin/device", data=fields, headers={"Origin": base},
                               follow_redirects=False)
        assert response.status_code == 303
        assert store.get_device("linux-lab").host == "10.200.0.8"

        grant = {"csrf": "test-csrf", "subject": "google-oauth2|natan",
                 "device_id": "linux-lab", "action": "status", "enabled": "1"}
        response = client.post("/admin/grant", data=grant, headers={"Origin": base},
                               follow_redirects=False)
        assert response.status_code == 303
        assert store.permits("google-oauth2|natan", "linux-lab", "status")

        # CSRF protection prevents a different site from modifying the matrix.
        grant["enabled"] = "0"
        response = client.post("/admin/grant", data=grant,
                               headers={"Origin": "https://evil.example"}, follow_redirects=False)
        assert response.status_code == 403
        assert store.permits("google-oauth2|natan", "linux-lab", "status")
