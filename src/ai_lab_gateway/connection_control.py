"""Per-device connection policy, independent of SSH pairing and sudo profiles.

Persistence is a BOOL (systemd enabled/disabled) for every Linux device.
Runtime connectivity is a separate BOOL. The remote MCP cannot connect a
device after its only reverse SSH tunnel is down.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from .registry import Device
from .ssh_exec import CommandResult, execute

TUNNEL_UNIT = re.compile(r"^ai-lab-[a-z0-9-]+-tunnel\.service$")
REMOTE_HELPER = "/usr/local/libexec/ai-lab-device-connectionctl"


def unit_for(device: Device) -> str:
    unit = device.connection_unit
    if not isinstance(unit, str) or not TUNNEL_UNIT.fullmatch(unit):
        raise ValueError(
            f"device {device.id} has no explicitly configured connection unit"
        )
    return unit


def persistent_flag(value: bool) -> bool:
    """Reject strings/integers: flag is boolean, not a list of modes."""
    if type(value) is not bool:
        raise ValueError("persistent must be a boolean")
    return value


@dataclass(frozen=True)
class DeviceConnectionState:
    device_id: str
    connected: bool
    persistent: bool | None
    unit: str
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "connected": self.connected,
            "persistent": self.persistent,
            "unit": self.unit,
            "detail": self.detail,
        }


def read_connection(device: Device) -> DeviceConnectionState:
    """Read actual target systemd status through an authorized SSH tunnel.

    A disconnected device cannot be queried live; return persistent=None
    rather than pretend a cached preference represents the current target.
    """
    unit = unit_for(device)
    # Unit name is validated. The shell receives only this fixed argument.
    command = (
        "systemctl show --no-pager --property=ActiveState,UnitFileState "
        "-- " + unit
    )
    result: CommandResult = execute(device, command, timeout=12)
    if result.exit_code != 0:
        return DeviceConnectionState(
            device.id, False, None, unit, "device_unreachable_or_unit_unavailable"
        )
    fields = {}
    for line in result.stdout.splitlines():
        name, sep, value = line.partition("=")
        if sep and name in {"ActiveState", "UnitFileState"}:
            fields[name] = value
    active = fields.get("ActiveState")
    enabled = fields.get("UnitFileState")
    if active not in {"active", "inactive", "activating", "deactivating", "failed"}:
        raise RuntimeError("invalid target connection service state")
    if enabled not in {"enabled", "disabled", "enabled-runtime", "static", "masked"}:
        raise RuntimeError("invalid target connection startup state")
    if enabled in {"static", "masked"}:
        raise RuntimeError("connection unit cannot be managed: " + enabled)
    return DeviceConnectionState(
        device.id,
        active == "active",
        enabled in {"enabled", "enabled-runtime"},
        unit,
        "ok",
    )


def update_persistent_flag(device: Device, persistent: bool) -> DeviceConnectionState:
    """Toggle ONLY systemd enablement, not Linux sudo access or pairing.

    Requires separately provisioned, root-owned target helper and a narrow
    sudoers command allowlist. If SSH is down, this MUST fail closed.
    Does not stop the currently active tunnel when persistent becomes False.
    """
    persistent_flag(persistent)
    unit = unit_for(device)
    arg = "1" if persistent else "0"
    command = f"sudo -n {REMOTE_HELPER} set-persistent {unit} {arg}"
    result = execute(device, command, timeout=20)
    if result.exit_code != 0:
        raise RuntimeError(
            "connection preference was not changed; target helper unavailable "
            "or SSH disconnected (exit " + str(result.exit_code) + ")"
        )
    state = read_connection(device)
    if state.persistent is not persistent:
        raise RuntimeError("target did not confirm requested persistence flag")
    return state
