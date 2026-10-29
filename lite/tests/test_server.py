from starlette.testclient import TestClient
from ai_lab_gateway_lite.server import build_app


def test_mcp_requires_auth_and_panel_separate(tmp_path, monkeypatch):
    base = "https://ai-gateway-lite.debasti.com"
    monkeypatch.setenv("LITE_BASE_URL", base)
    monkeypatch.setenv("LITE_OAUTH_ISSUER", "https://test.auth0.com/")
    monkeypatch.setenv("LITE_OAUTH_AUDIENCE", base + "/mcp")
    monkeypatch.setenv("LITE_OAUTH_JWKS_URL", "https://test.auth0.com/.well-known/jwks.json")
    monkeypatch.setenv("LITE_SESSION_SECRET", "test-only-session-secret-much-longer-than-32")
    monkeypatch.setenv("LITE_WEB_CLIENT_ID", "test")
    monkeypatch.setenv("LITE_WEB_CLIENT_SECRET", "test")
    monkeypatch.setenv("LITE_ADMIN_SUBJECTS", "google-oauth2|test-admin")
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    monkeypatch.setenv("LITE_DATABASE", str(tmp_path / "db.sqlite"))
    monkeypatch.setenv("LITE_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    app = build_app()
    with TestClient(app, base_url=base) as client:
        assert client.get("/admin").status_code == 200
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == base + "/mcp"
        assert set(metadata.json()["scopes_supported"]) == {"gateway:read", "gateway:control"}
        response = client.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}
        }, headers={"Accept": "application/json, text/event-stream"})
        assert response.status_code == 401
