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

def test_self_ssh_pilot_is_disabled_by_default(store, monkeypatch):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "127.0.0.1/32")
    monkeypatch.delenv("LITE_ENABLE_LOOPBACK_TARGET", raising=False)
    with pytest.raises(ValueError):
        store.save_device(Device("self", "Local test", "127.0.0.1", 22, "lite-target", "self"))


def test_self_ssh_pilot_exact_opt_in(store, monkeypatch):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "127.0.0.1/32")
    monkeypatch.setenv("LITE_ENABLE_LOOPBACK_TARGET", "1")
    device = Device("self", "Local test", "127.0.0.1", 22, "lite-target", "self")
    store.save_device(device)
    assert store.get_device("self") == device


@pytest.mark.parametrize("host,port,user", [
    ("127.0.0.2", 22, "lite-target"),
    ("::1", 22, "lite-target"),
    ("127.0.0.1", 2222, "lite-target"),
    ("127.0.0.1", 22, "ai-gateway"),
    ("127.0.0.1", 22, "ubuntu"),
])
def test_self_ssh_pilot_does_not_expand_trust(store, monkeypatch, host, port, user):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "127.0.0.0/8,::1/128")
    monkeypatch.setenv("LITE_ENABLE_LOOPBACK_TARGET", "1")
    with pytest.raises(ValueError):
        store.save_device(Device("self", "Local test", host, port, user, "self"))


def test_self_ssh_pilot_requires_explicit_approved_address(store, monkeypatch):
    monkeypatch.setenv("LITE_ENABLE_LOOPBACK_TARGET", "1")
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    with pytest.raises(ValueError):
        store.save_device(Device("self", "Local test", "127.0.0.1", 22, "lite-target", "self"))


def test_self_ssh_pilot_does_not_allow_public_target(store, monkeypatch):
    monkeypatch.setenv("LITE_ENABLE_LOOPBACK_TARGET", "1")
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "127.0.0.1/32,8.8.8.8/32")
    with pytest.raises(ValueError):
        store.save_device(Device("remote", "Public", "8.8.8.8", 22, "lite-target", "remote"))

def test_self_ssh_rejects_broad_loopback_allowlist(store, monkeypatch):
    monkeypatch.setenv("LITE_ENABLE_LOOPBACK_TARGET", "1")
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "127.0.0.0/8")
    with pytest.raises(ValueError):
        store.save_device(Device("self", "Local test", "127.0.0.1", 22, "lite-target", "self"))
