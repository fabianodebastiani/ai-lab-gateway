from ai_lab_gateway.audit import JsonlAuditLog
from ai_lab_gateway.auth import VerifiedIdentity
from ai_lab_gateway.authz import AuthorizationPolicy
from ai_lab_gateway.control import ControlPlane
from ai_lab_gateway.registry import Device, DeviceRegistry
from ai_lab_gateway.ssh_exec import CommandResult


def make_control(tmp_path):
    registry = DeviceRegistry({"pi": Device(
        id="pi", name="Pi", ssh_user="ai-gateway",
        tunnel_host="127.0.0.1", tunnel_port=10001,
        identity_file="/keys/pi",
    )})
    policy = AuthorizationPolicy({
        "alice": {"pi": {"status", "exec"}},
        "bob": {"pi": {"status"}},
    })
    return ControlPlane(registry, policy, JsonlAuditLog(tmp_path / "audit.jsonl"))


def identity(subject, *scopes):
    return VerifiedIdentity(subject, frozenset(scopes), {"sub": subject})


def test_list_devices_filters_by_subject(tmp_path):
    control = make_control(tmp_path)
    assert control.list_devices(identity("alice", "gateway:read")) == [
        {"id": "pi", "name": "Pi"}
    ]
    assert control.list_devices(identity("unknown", "gateway:read")) == []


def test_exec_requires_control_scope(tmp_path):
    control = make_control(tmp_path)
    try:
        control.exec(identity("alice", "gateway:read"), "pi", "true")
    except PermissionError:
        pass
    else:
        raise AssertionError("control scope should be required")


def test_exec_requires_device_grant(tmp_path):
    control = make_control(tmp_path)
    try:
        control.exec(identity("bob", "gateway:control"), "pi", "true")
    except PermissionError:
        pass
    else:
        raise AssertionError("exec grant should be required")


def test_exec_calls_backend_and_audits(monkeypatch, tmp_path):
    control = make_control(tmp_path)

    def fake_execute(device, command, timeout):
        assert device.id == "pi"
        assert command == "uname -a"
        return CommandResult("Linux pi", "", 0)

    monkeypatch.setattr("ai_lab_gateway.control.execute", fake_execute)
    result = control.exec(
        identity("alice", "gateway:control"), "pi", "uname -a", timeout=5
    )
    assert result.stdout == "Linux pi"
    assert '"subject":"alice"' in (tmp_path / "audit.jsonl").read_text()
