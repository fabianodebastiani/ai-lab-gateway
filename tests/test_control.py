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
        "alice": {"pi": {"status", "exec", "read_file", "write_file"}},
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


def test_device_status_calls_hostname_and_audits(monkeypatch, tmp_path):
    control = make_control(tmp_path)
    monkeypatch.setattr("ai_lab_gateway.control.execute", lambda device, command, timeout: CommandResult("pi-host\n", "", 0))
    result = control.device_status(identity("alice", "gateway:read"), "pi")
    assert result["hostname"] == "pi-host"
    assert result["status"] == "online"
    assert '"action":"status"' in (tmp_path / "audit.jsonl").read_text()


def test_read_file_requires_read_scope(monkeypatch, tmp_path):
    control = make_control(tmp_path)
    monkeypatch.setattr("ai_lab_gateway.control.execute", lambda device, command, timeout: CommandResult("hello", "", 0))
    assert control.read_file(identity("alice", "gateway:read"), "pi", "/tmp/x") == "hello"
    assert '"action":"read_file"' in (tmp_path / "audit.jsonl").read_text()
    try:
        control.read_file(identity("alice", "gateway:control"), "pi", "/tmp/x")
    except PermissionError:
        pass
    else:
        raise AssertionError("read scope should be required")


def test_write_file_requires_control_scope(monkeypatch, tmp_path):
    control = make_control(tmp_path)
    seen = {}
    def fake_execute(device, command, timeout):
        seen["command"] = command
        return CommandResult("", "", 0)
    monkeypatch.setattr("ai_lab_gateway.control.execute", fake_execute)
    control.write_file(identity("alice", "gateway:control"), "pi", "/tmp/x", "hello")
    assert "base64 -d" in seen["command"]
    assert '"action":"write_file"' in (tmp_path / "audit.jsonl").read_text()
    try:
        control.write_file(identity("alice", "gateway:read"), "pi", "/tmp/x", "hello")
    except PermissionError:
        pass
    else:
        raise AssertionError("control scope should be required")
