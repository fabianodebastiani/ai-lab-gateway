from types import SimpleNamespace
import pytest

from ai_lab_gateway_lite.audit import JsonlAuditLog
from ai_lab_gateway_lite.auth import VerifiedIdentity
from ai_lab_gateway_lite.control import ControlPlane
from ai_lab_gateway_lite.store import Device, Store


@pytest.fixture
def plane(tmp_path, monkeypatch):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    store = Store(tmp_path / "db.sqlite")
    store.initialize()
    store.record_user("google-oauth2|alice")
    store.save_device(Device("box", "Box", "10.200.0.2", 22, "ai-gateway", "box"))
    return ControlPlane(store, JsonlAuditLog(tmp_path / "audit.jsonl"))


def identity(*scopes):
    return VerifiedIdentity("google-oauth2|alice", frozenset(scopes), {})


def test_control_denied_without_scope_even_with_grant(plane, monkeypatch):
    plane.store.set_grant("google-oauth2|alice", "box", "exec", True)
    monkeypatch.setattr("ai_lab_gateway_lite.control.execute",
                        lambda *args, **kwargs: pytest.fail("SSH must not run"))
    with pytest.raises(PermissionError):
        plane.exec(identity("gateway:read"), "box", "uname")


def test_control_denied_without_device_grant(plane, monkeypatch):
    monkeypatch.setattr("ai_lab_gateway_lite.control.execute",
                        lambda *args, **kwargs: pytest.fail("SSH must not run"))
    with pytest.raises(PermissionError):
        plane.exec(identity("gateway:read", "gateway:control"), "box", "uname")


def test_granted_status_and_audit(plane, tmp_path, monkeypatch):
    plane.store.set_grant("google-oauth2|alice", "box", "status", True)
    monkeypatch.setattr("ai_lab_gateway_lite.control.execute",
                        lambda *args, **kwargs: SimpleNamespace(stdout="box\n", stderr="", exit_code=0))
    result = plane.device_status(identity("gateway:read"), "box")
    assert result["status"] == "online"
    data = (tmp_path / "audit.jsonl").read_text()
    assert '"action":"status"' in data
    assert "box\\n" not in data
