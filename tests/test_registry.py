import json

import pytest

from ai_lab_gateway.registry import DeviceRegistry


def test_load_and_get_device(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text(json.dumps({"devices": [{
        "id": "pi",
        "name": "Pi",
        "ssh_user": "ai-gateway",
        "tunnel_host": "127.0.0.1",
        "tunnel_port": 10001,
        "identity_file": "/keys/pi"
    }]}))

    registry = DeviceRegistry.load(path)
    assert registry.get("pi").tunnel_port == 10001


def test_rejects_non_loopback_tunnel(tmp_path):
    path = tmp_path / "devices.json"
    path.write_text(json.dumps({"devices": [{
        "id": "pi",
        "name": "Pi",
        "ssh_user": "ai-gateway",
        "tunnel_host": "0.0.0.0",
        "tunnel_port": 10001,
        "identity_file": "/keys/pi"
    }]}))

    with pytest.raises(ValueError, match="loopback"):
        DeviceRegistry.load(path)
