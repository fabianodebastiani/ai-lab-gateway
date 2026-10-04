"""Device registry primitives.

The registry deliberately contains routing metadata only. SSH private keys and
other secrets are referenced by path and are never stored in the registry.
"""

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    ssh_user: str
    tunnel_host: str
    tunnel_port: int
    identity_file: str
    enabled: bool = True

    @classmethod
    def from_dict(cls, raw: dict) -> "Device":
        required = ("id", "name", "ssh_user", "tunnel_host", "tunnel_port", "identity_file")
        missing = [key for key in required if key not in raw]
        if missing:
            raise ValueError(f"device is missing required fields: {', '.join(missing)}")

        port = int(raw["tunnel_port"])
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid tunnel_port for {raw['id']}: {port}")

        host = str(raw["tunnel_host"])
        if host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError(
                f"device {raw['id']} tunnel_host must be loopback; got {host!r}"
            )

        return cls(
            id=str(raw["id"]),
            name=str(raw["name"]),
            ssh_user=str(raw["ssh_user"]),
            tunnel_host=host,
            tunnel_port=port,
            identity_file=str(raw["identity_file"]),
            enabled=bool(raw.get("enabled", True)),
        )


class DeviceRegistry:
    def __init__(self, devices: dict[str, Device]):
        self._devices = devices

    @classmethod
    def load(cls, path: str | Path) -> "DeviceRegistry":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        devices: dict[str, Device] = {}
        ports: set[int] = set()

        for item in raw.get("devices", []):
            device = Device.from_dict(item)
            if device.id in devices:
                raise ValueError(f"duplicate device id: {device.id}")
            if device.tunnel_port in ports:
                raise ValueError(f"duplicate tunnel port: {device.tunnel_port}")
            devices[device.id] = device
            ports.add(device.tunnel_port)

        return cls(devices)

    def get(self, device_id: str) -> Device:
        try:
            device = self._devices[device_id]
        except KeyError as exc:
            raise KeyError(f"unknown device: {device_id}") from exc
        if not device.enabled:
            raise PermissionError(f"device is disabled: {device_id}")
        return device

    def list_enabled(self) -> list[Device]:
        return [device for device in self._devices.values() if device.enabled]
