from starlette.testclient import TestClient
from ai_lab_gateway_lite.panel import create_panel
from ai_lab_gateway_lite.store import Store


def test_anonymous_panel_cannot_mutate(tmp_path, monkeypatch):
    monkeypatch.setenv("LITE_BASE_URL", "https://ai-gateway-lite.debasti.com")
    monkeypatch.setenv("LITE_SESSION_SECRET", "test-only-secret-with-32-or-more-characters")
    monkeypatch.setenv("LITE_WEB_CLIENT_ID", "test-client")
    monkeypatch.setenv("LITE_WEB_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("LITE_OAUTH_ISSUER", "https://test.auth0.com/")
    monkeypatch.setenv("LITE_ADMIN_SUBJECTS", "google-oauth2|admin")
    store = Store(tmp_path / "db.sqlite")
    store.initialize()
    with TestClient(create_panel(store), base_url="https://ai-gateway-lite.debasti.com") as client:
        response = client.get("/admin")
        assert response.status_code == 200
        assert "Entrar com Google" in response.text
        response = client.post("/admin/device", data={"id": "box"},
                               headers={"Origin": "https://ai-gateway-lite.debasti.com"})
        assert response.status_code == 403
        assert store.list_devices() == []
