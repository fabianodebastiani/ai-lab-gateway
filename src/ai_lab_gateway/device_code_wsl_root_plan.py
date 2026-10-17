"""Pure, bounded root staging plan for the first WSL one-code enrollment.

This exact pilot checks a *new* device ID against the legacy WSL host key.
It cannot authorize another host, a different port, elevated privilege,
persistent tunnel, arbitrary SSH username or changed gateway trust.
"""
from __future__ import annotations

import json
import re

from .device_code_offer import OFFER_VERSION, fingerprint, validate_offer
from .enrollment import _validate_public_key

PILOT_PORT = 10003
OLD_PORT = 10002
PILOT_ID = re.compile(r"laptop-5rjj0kbm-[a-f0-9]{8}\Z")


def _host_keys_for_endpoint(raw: bytes, endpoint: str) -> list[str]:
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise PermissionError("invalid gateway known_hosts") from exc
    result = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        items = stripped.split()
        if len(items) < 3:
            raise PermissionError("malformed gateway known_hosts")
        if items[0] == endpoint:
            if len(items) != 3:
                raise PermissionError("malformed host identity pin")
            if items[1] != "ssh-ed25519":
                # The legacy 10002 connection also pins RSA/ECDSA keys;
                # these cannot substitute for its separate Ed25519 pin.
                if endpoint == "[127.0.0.1]:10002":
                    continue
                raise PermissionError("candidate host pin is not Ed25519")
            result.append(_validate_public_key(" ".join(items[1:])))
        elif endpoint in items[0].split(",") or (
                items[0].startswith("@") and endpoint in stripped):
            raise PermissionError("marked, hashed or merged host pin unsupported")
    return result


def build_wsl_one_code_offer(candidate: dict, *,
                             trusted_registry: dict,
                             trusted_known_hosts: bytes,
                             gateway_ssh_host_key: str,
                             gateway_management_key: str) -> dict:
    """All inputs except approved candidate must come from protected root files."""
    if not isinstance(candidate, dict) or set(candidate) != {
        "request_id", "device_id", "device_name", "operator_subject",
        "tunnel_public_key", "host_public_key", "persistent", "expires_at"}:
        raise PermissionError("unexpected approved-device root schema")
    device_id = candidate["device_id"]
    if (not isinstance(device_id, str) or not PILOT_ID.fullmatch(device_id)
            or candidate["persistent"] is not False
            or not isinstance(candidate["operator_subject"], str)
            or not candidate["operator_subject"]
            or not isinstance(candidate["device_name"], str)
            or not isinstance(candidate["request_id"], str)
            or not isinstance(candidate["expires_at"], int)):
        raise PermissionError("WSL pilot identity or approval not permitted")
    if not isinstance(trusted_registry, dict) or set(trusted_registry) != {"devices"}:
        raise PermissionError("invalid registered device schema")
    records = trusted_registry["devices"]
    if (not isinstance(records, list)
            or any(not isinstance(d, dict) for d in records)):
        raise PermissionError("invalid registered device list")
    legacy = [d for d in records if d.get("id") == "windows-wsl"]
    if (len(legacy) != 1 or type(legacy[0].get("tunnel_port")) is not int
            or legacy[0]["tunnel_port"] != OLD_PORT):
        raise PermissionError("legacy WSL must remain uniquely on 10002")
    if any(d.get("id") == device_id or d.get("tunnel_port") == PILOT_PORT
           for d in records):
        raise PermissionError("candidate ID or port already registered")

    actual = _validate_public_key(candidate["host_public_key"])
    historical = _host_keys_for_endpoint(
        trusted_known_hosts, "[127.0.0.1]:10002")
    candidate_pins = _host_keys_for_endpoint(
        trusted_known_hosts, "[127.0.0.1]:10003")
    if len(historical) != 1 or historical[0] != actual:
        raise PermissionError("requested WSL does not match trusted old sshd")
    if len(candidate_pins) > 1 or (candidate_pins and candidate_pins[0] != actual):
        raise PermissionError("preexisting candidate host identity differs")
    tunnel = _validate_public_key(candidate["tunnel_public_key"])
    host = _validate_public_key(gateway_ssh_host_key)
    mgmt = _validate_public_key(gateway_management_key)
    if len({tunnel, actual, host, mgmt}) != 4:
        raise PermissionError("four independent SSH identities are required")
    offer = {
        "version": OFFER_VERSION,
        "request_id": candidate["request_id"],
        "device_id": device_id,
        "access_mode": "restricted",
        "persistent": False,
        "gateway_host": "gateway.debasti.com",
        "gateway_ssh_port": 22,
        "gateway_tunnel_user": "tunnel",
        "gateway_ssh_host_key": host,
        "gateway_management_public_key": mgmt,
        "reverse_listen_host": "127.0.0.1",
        "reverse_listen_port": PILOT_PORT,
        "management_user": "ai-gateway",
        "device_tunnel_fingerprint": fingerprint(tunnel),
        "device_host_fingerprint": fingerprint(actual),
    }
    return validate_offer(
        offer, request_id=candidate["request_id"], device_id=device_id,
        persistent=False, tunnel_key=tunnel, host_key=actual)
