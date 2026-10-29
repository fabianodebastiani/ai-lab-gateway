from types import SimpleNamespace
import pytest
from ai_lab_gateway_lite.ssh_exec import _ssh_argv, execute, safe_read_command, safe_write_command
from ai_lab_gateway_lite.store import Device


@pytest.fixture
def device(tmp_path, monkeypatch):
    monkeypatch.setenv("LITE_ALLOWED_SSH_CIDRS", "10.200.0.0/24")
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "linux-a").write_text("test identity placeholder")
    (keys / "linux-a").chmod(0o600)
    hosts = tmp_path / "known_hosts"
    hosts.write_text("10.200.0.2 ssh-ed25519 TEST-PIN\n")
    monkeypatch.setenv("LITE_SSH_KEY_DIR", str(keys))
    monkeypatch.setenv("LITE_SSH_KNOWN_HOSTS", str(hosts))
    return Device("linux-a", "Linux A", "10.200.0.2", 22, "ai-gateway", "linux-a")


def test_ssh_command_uses_pinned_host_and_key(device):
    args = _ssh_argv(device)
    assert "StrictHostKeyChecking=yes" in args
    assert "BatchMode=yes" in args
    assert "ForwardAgent=no" in args
    assert args[-2:] == ["ai-gateway@10.200.0.2", "--"]


def test_remote_command_is_argument_not_local_shell(device, monkeypatch):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(stdout="hello\n", stderr="", returncode=0)
    monkeypatch.setattr("ai_lab_gateway_lite.ssh_exec.subprocess.run", run)
    result = execute(device, "printf hello; echo done", timeout=8)
    assert result.exit_code == 0
    assert calls[0][0][-1] == "printf hello; echo done"
    assert calls[0][1]["check"] is False


def test_unsafe_permissions_rejected(device, tmp_path, monkeypatch):
    (tmp_path / "keys" / "linux-a").chmod(0o644)
    with pytest.raises(PermissionError):
        _ssh_argv(device)


def test_escape_file_names():
    assert safe_read_command("/tmp/a' b").startswith("cat -- ")
    assert "'\"'\"'" in safe_write_command("/tmp/a' b")
    with pytest.raises(ValueError):
        safe_read_command("relative.txt")


def test_limit_timeout_and_payload(device):
    with pytest.raises(ValueError):
        execute(device, "id", 301)
    with pytest.raises(ValueError):
        execute(device, "cat", 30, "a" * 65537)
