"""Pure, side-effect-free registry and authorization plan after verified SSH.

This is NOT a root finalizer: no filesystem writes, subprocess, service
restart, sudo, privilege escalation, or mutation of input objects.

The trusted root installer must independently verify live SSH at a pinned
loopback port and confirm an unexpired Auth0-approved candidate before using
the resulting configuration. A model-supplied flag is never proof of SSH.
"""
from __future__ import annotations

import copy
import re

from .registry import Device
from .device_code_wsl_root_plan import PILOT_ID, PILOT_PORT

PILOT_KEY = "/etc/ai-lab-gateway/device-code-keys/wsl-10003/identity"
PERMITTED_ACTIONS = ("status", "exec", "read_file", "write_file")


def plan_restricted_wsl_registration(
    *, protected_registry: dict, protected_policy: dict, approved_identity: dict
) -> tuple[dict, dict]:
    """Return new config objects for *only* the independently verified WSL pilot.

    approved_identity must come from the already Auth0-bound root handoff,
    not directly from MCP, HTTP or a request-body value. The caller must
    separately check SSH and approval at the privileged commit boundary.
    """
    if not isinstance(approved_identity, dict) or set(approved_identity) != {
        "device_id", "device_name", "operator_subject", "request_id",
        "access_mode", "persistent", "reverse_listen_port",
    }:
        raise PermissionError("untrusted staged enrollment identity")
    identity = approved_identity
    device_id = identity["device_id"]
    subject = identity["operator_subject"]
    name = identity["device_name"]
    if (not isinstance(device_id, str) or not PILOT_ID.fullmatch(device_id)
            or not isinstance(subject, str) or not 1 <= len(subject) <= 256
            or not isinstance(name, str) or not 1 <= len(name) <= 80
            or identity["access_mode"] != "restricted"
            or identity["persistent"] is not False
            or type(identity["reverse_listen_port"]) is not int
            or identity["reverse_listen_port"] != PILOT_PORT
            or not isinstance(identity["request_id"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", identity["request_id"])):
        raise PermissionError("unauthorized device identity or access mode")
    if (not isinstance(protected_registry, dict)
            or set(protected_registry) != {"devices"}
            or not isinstance(protected_registry["devices"], list)):
        raise PermissionError("invalid trusted device registry")
    if (not isinstance(protected_policy, dict)
            or set(protected_policy) != {"users"}
            or not isinstance(protected_policy["users"], list)):
        raise PermissionError("invalid trusted authorization policy")

    registered = protected_registry["devices"]
    users = protected_policy["users"]
    if any(not isinstance(item, dict) for item in registered):
        raise PermissionError("invalid registered device")
    if any(item.get("id") == device_id or item.get("tunnel_port") == PILOT_PORT
           for item in registered):
        raise PermissionError("candidate is already registered")
    if len([d for d in registered
            if d.get("id") == "windows-wsl" and d.get("tunnel_port") == 10002]) != 1:
        raise PermissionError("existing WSL connection must be preserved")
    if any(not isinstance(user, dict) or not isinstance(user.get("devices"), dict)
           for user in users):
        raise PermissionError("invalid trusted principal")
    owners = [user for user in users if user.get("subject") == subject]
    if len(owners) != 1:
        raise PermissionError("authenticated approving principal not authorized")
    if device_id in owners[0]["devices"]:
        raise PermissionError("candidate permission already exists")

    # Keep identity_file and ssh_user fixed; do not accept these from HTTP.
    record = {
        "id": device_id, "name": name, "ssh_user": "ai-gateway",
        "tunnel_host": "127.0.0.1", "tunnel_port": PILOT_PORT,
        "identity_file": PILOT_KEY, "enabled": True,
    }
    Device.from_dict(record)

    updated_registry = copy.deepcopy(protected_registry)
    updated_policy = copy.deepcopy(protected_policy)
    updated_registry["devices"].append(record)
    for user in updated_policy["users"]:
        if user["subject"] == subject:
            user["devices"][device_id] = list(PERMITTED_ACTIONS)
    return updated_registry, updated_policy
