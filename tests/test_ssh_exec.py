import subprocess

import pytest

from ai_lab_gateway.registry import Device
from ai_lab_gateway.ssh_exec import execute


def device():
    return Device(
        id="pi",
        name="Pi",
        ssh_user="ai-gateway",
        tunnel_host="127.0.0.1",
        tunnel_port=10001,
        identity_file="/keys/pi",
    )


def test_builds_bounded_ssh_call(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 7, "out", "err")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = execute(device(), "uname -a", timeout=20)

    assert result.exit_code == 7
    assert result.stdout == "out"
    assert "-p" in seen["argv"]
    assert "10001" in seen["argv"]
    assert seen["argv"][-1] == "uname -a"
    assert seen["kwargs"]["timeout"] == 20


def test_rejects_unbounded_timeout():
    with pytest.raises(ValueError):
        execute(device(), "true", timeout=301)
