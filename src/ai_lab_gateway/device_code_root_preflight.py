"""Read-only root-provisioner policy preflight for WSL v2 candidate.

NOT DEPLOYED and NEVER writes SSH/systemd/registry. This is a pure policy
check a later root-owned adapter must run after independently verifying
the kernel peer UID, receiving approved public-only handoff through a
root-only socket, and obtaining trusted host identities and the registry
from root-owned sources (never model, HTTP or device-supplied values).

Passing this function is necessary, never sufficient, for real installation.
A real root service must check filesystem ownership, locks, port availability,
TOCTOU, rollback journal, audit, secure OpenSSH options and expiry *again* at
commit time. No sudo grant follows from pairing.
"""
from __future__ import annotations

from .device_code_candidate import PILOT_DEVICE, PILOT_PORT, LEGACY_PORT
from .device_code_offer import validate_offer
from .enrollment import _validate_public_key


def preflight_wsl_candidate(candidate: object, *, trusted_gateway_host_key: str,
                            independently_verified_target_host_key: str,
                            actual_gateway_management_public_key: str,
                            protected_registry: object) -> dict:
    """Return only a fixed safe candidate statement or raise PermissionError."""
    if not isinstance(candidate, dict) or set(candidate) != {
            "request_id", "device_id", "persistent", "access_mode",
            "tunnel_public_key", "host_public_key", "offer"}:
        raise PermissionError("invalid approved candidate contract")
    request_id = candidate["request_id"]
    if (not isinstance(request_id, str)
            or candidate["device_id"] != PILOT_DEVICE
            or candidate["persistent"] is not False
            or candidate["access_mode"] != "restricted"):
        raise PermissionError("WSL pilot must be restricted and on-demand")
    tunnel = _validate_public_key(candidate["tunnel_public_key"])
    host = _validate_public_key(candidate["host_public_key"])
    gw_host = _validate_public_key(trusted_gateway_host_key)
    target_actual = _validate_public_key(independently_verified_target_host_key)
    management = _validate_public_key(actual_gateway_management_public_key)
    if host != target_actual:
        raise PermissionError("candidate host identity differs from target sshd")
    if len({tunnel, host, gw_host, management}) != 4:
        raise PermissionError("all SSH identities must be distinct")
    offer = validate_offer(
        candidate["offer"], request_id=request_id, device_id=PILOT_DEVICE,
        persistent=False, tunnel_key=tunnel, host_key=host)
    if (offer["gateway_ssh_host_key"] != gw_host
            or offer["gateway_management_public_key"] != management
            or offer["reverse_listen_port"] != PILOT_PORT):
        raise PermissionError("candidate disagrees with independently verified roots")
    if not isinstance(protected_registry, dict) or set(protected_registry) != {"devices"}:
        raise PermissionError("invalid protected device registry shape")
    devices = protected_registry["devices"]
    if not isinstance(devices, list):
        raise PermissionError("invalid protected registry devices")
    wsl = [d for d in devices if isinstance(d, dict) and d.get("id") == PILOT_DEVICE]
    if len(wsl) != 1 or type(wsl[0].get("tunnel_port")) is not int:
        raise PermissionError("legacy WSL not uniquely registered")
    if wsl[0]["tunnel_port"] != LEGACY_PORT:
        raise PermissionError("legacy WSL must remain on 10002")
    for d in devices:
        if not isinstance(d, dict) or type(d.get("tunnel_port")) is not int:
            raise PermissionError("invalid existing registry entry")
        if d["tunnel_port"] == PILOT_PORT:
            raise PermissionError("candidate port 10003 already assigned")
    return {
        "status": "candidate_preflight_ok",
        "device_id": PILOT_DEVICE,
        "port": PILOT_PORT,
        "access_mode": "restricted",
        "persistent": False,
        "registry_changed": False,
        "ssh_changed": False,
    }
