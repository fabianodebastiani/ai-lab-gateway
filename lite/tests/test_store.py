import pytest
from ai_lab_gateway_lite.store import Store, Device, validate_device, allowed_networks


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    s = Store(tmp_path / "lite.sqlite")
    s.initialize()
    return s


def test_new_user_has_no_permissions(store):
    store.record_user("google-oauth2|alice", "alice@example.invalid")
    store.save_device(Device("linux-a", "Linux A", "10.200.0.15", 22, "ai-gateway", "linux-a"))
    assert store.list_devices("google-oauth2|alice") == []
    with pytest.raises(PermissionError):
        store.require("google-oauth2|alice", "linux-a", "exec")


def test_grant_revocation_is_immediate(store):
    sub = "google-oauth2|alice"
    store.record_user(sub)
    store.save_device(Device("linux-a", "Linux A", "10.200.0.15", 22, "ai-gateway", "linux-a"))
    store.save_device(Device("linux-b", "Linux B", "10.200.0.16", 22, "ai-gateway", "linux-b"))
    store.set_grant(sub, "linux-a", "status", True)
    assert store.permits(sub, "linux-a", "status")
    assert not store.permits(sub, "linux-a", "exec")
    assert [d.id for d in store.list_devices(sub)] == ["linux-a"]
    store.set_grant(sub, "linux-a", "status", False)
    assert not store.permits(sub, "linux-a", "status")
    assert store.list_devices(sub) == []


def test_device_disable_denies_existing_grant(store):
    sub = "auth0|bob"
    store.record_user(sub)
    store.save_device(Device("box", "Box", "10.200.0.2", 22, "ai-gateway", "box"))
    store.set_grant(sub, "box", "exec", True)
    store.save_device(Device("box", "Box", "10.200.0.2", 22, "ai-gateway", "box", False))
    assert not store.permits(sub, "box", "exec")
    with pytest.raises(PermissionError):
        store.get_device("box")


@pytest.mark.parametrize("ip", ["8.8.8.8", "127.0.0.1", "10.201.0.5", "example.com", "169.254.1.5"])
def test_network_boundary_rejects_invalid_target(store, ip):
    with pytest.raises(ValueError):
        validate_device(Device("box", "Box", ip, 22, "ai-gateway", "box"))


def test_allowlist_required(monkeypatch):
    monkeypatch.delenv("LITE_ALLOWED_SSH_CIDRS", raising=False)
    with pytest.raises(ValueError):
        allowed_networks()
    with pytest.raises(ValueError):
        allowed_networks("0.0.0.0/0")


def test_cannot_grant_unknown_action(store):
    with pytest.raises(ValueError):
        store.set_grant("a", "b", "sudo", True)
