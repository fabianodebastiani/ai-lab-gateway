"""Generic Linux pairing final-mile plan: pure calculations, no privileged IO.

Inputs marked trusted MUST originate from the root-controlled Gateway
configuration and peer-verified, unexpired Auth0 pairing handoff. This module
never writes SSH keys, registry/policy, sudoers or services, and is not an
authorization boundary by itself.

Device-initiated code pairing is independent of hostname, distribution or
location. A dedicated, non-sudo 'ai-gateway' account is established by a
separately authorized target-local installer before SSH activation.
"""
from __future__ import annotations

import copy
import re

from .device_code_offer import OFFER_VERSION, fingerprint, validate_offer
from .enrollment import _validate_public_key
from .registry import Device

DEVICE_ID = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")
# Outside legacy 10001/10002 and WSL trial 10003; only internal loopback.
PORT_START = 11000
PORT_END = 11999
SSH_USER = "ai-gateway"
KEY_ROOT = "/etc/ai-lab-gateway/device-code-keys"
SSH_ACTIONS = ("status", "exec", "read_file", "write_file")


def _candidate_identity(candidate: dict) -> dict:
    fields = {
        "request_id", "device_id", "device_name", "operator_subject",
        "tunnel_public_key", "host_public_key", "persistent", "expires_at",
    }
    if not isinstance(candidate, dict) or set(candidate) != fields:
        raise PermissionError("unexpected approved Linux pairing record")
    c = candidate
    if (not isinstance(c["device_id"], str)
            or not DEVICE_ID.fullmatch(c["device_id"])
            or not isinstance(c["request_id"], str)
            or not REQUEST_ID.fullmatch(c["request_id"])
            or not isinstance(c["device_name"], str)
            or not 1 <= len(c["device_name"]) <= 80
            or not isinstance(c["operator_subject"], str)
            or not 1 <= len(c["operator_subject"]) <= 256
            or type(c["persistent"]) is not bool
            or type(c["expires_at"]) is not int or c["expires_at"] <= 0):
        raise PermissionError("invalid approved Linux pairing identity")
    tunnel = _validate_public_key(c["tunnel_public_key"])
    host = _validate_public_key(c["host_public_key"])
    if tunnel == host:
        raise PermissionError("tunnel and SSH host must have different keys")
    return {**c, "tunnel_public_key": tunnel, "host_public_key": host}


def _trusted_registry(registry: dict) -> list[dict]:
    if (not isinstance(registry, dict) or set(registry) != {"devices"}
            or not isinstance(registry["devices"], list)):
        raise PermissionError("unexpected root-controlled registry format")
    devices = registry["devices"]
    for item in devices:
        if not isinstance(item, dict):
            raise PermissionError("bad existing registered device")
        Device.from_dict(item)
    if len({d["id"] for d in devices}) != len(devices):
        raise PermissionError("duplicate existing registered device")
    if len({int(d["tunnel_port"]) for d in devices}) != len(devices):
        raise PermissionError("duplicate existing port")
    return devices


def choose_loopback_port(*, registry: dict, reserved_ports=()) -> int:
    """Pick a free PORT IN A FIXED RANGE; root later reserves and checks it.

    reserved_ports represents root-observed listeners and existing host pins,
    never client-declared availability. No socket is opened by this function.
    """
    devices = _trusted_registry(registry)
    if not isinstance(reserved_ports, (tuple, list, set, frozenset)):
        raise PermissionError("untrusted root port inventory")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in reserved_ports):
        raise PermissionError("invalid reserved port")
    allocated = {int(item["tunnel_port"]) for item in devices}
    occupied = allocated | set(reserved_ports)
    for port in range(PORT_START, PORT_END + 1):
        if port not in occupied:
            return port
    raise PermissionError("no unallocated loopback onboarding port")


def plan_generic_linux_enrollment(
    *, approved_candidate: dict, registry: dict, policy: dict,
    reserved_ports: tuple[int, ...],
    gateway_ssh_host_key: str, gateway_management_public_key: str
) -> tuple[dict, dict, dict]:
    """Plan one constrained SSH offer plus registry and per-owner ACL.

    Caller must still obtain real consent, install keys by approved local
    root operations, confirm SSH reachability/host pin/identity, then commit
    registry/policy. DO NOT commit these dictionaries before verification.
    """
    c = _candidate_identity(approved_candidate)
    devices = _trusted_registry(registry)
    if (not isinstance(policy, dict) or set(policy) != {"users"}
            or not isinstance(policy["users"], list)
            or any(not isinstance(x, dict) or not isinstance(x.get("devices"), dict)
                   for x in policy["users"])):
        raise PermissionError("invalid root-controlled Auth0 policy")
    owners = [u for u in policy["users"]
              if u.get("subject") == c["operator_subject"]]
    if len(owners) != 1:
        raise PermissionError("approving Auth0 principal missing or duplicated")
    device_id = c["device_id"]
    if (any(x["id"] == device_id for x in devices)
            or any(device_id in x["devices"] for x in policy["users"])):
        raise PermissionError("device identity already registered or granted")
    port = choose_loopback_port(registry=registry, reserved_ports=reserved_ports)
    gateway_host = _validate_public_key(gateway_ssh_host_key)
    management = _validate_public_key(gateway_management_public_key)
    if len({c["tunnel_public_key"], c["host_public_key"],
            gateway_host, management}) != 4:
        raise PermissionError("independent SSH keypairs required")
    offer = {
        "version": OFFER_VERSION,
        "request_id": c["request_id"],
        "device_id": device_id,
        "access_mode": "restricted",
        "persistent": c["persistent"],
        "gateway_host": "gateway.debasti.com",
        "gateway_ssh_port": 22,
        "gateway_tunnel_user": "tunnel",
        "gateway_ssh_host_key": gateway_host,
        "gateway_management_public_key": management,
        "reverse_listen_host": "127.0.0.1",
        "reverse_listen_port": port,
        "management_user": SSH_USER,
        "device_tunnel_fingerprint": fingerprint(c["tunnel_public_key"]),
        "device_host_fingerprint": fingerprint(c["host_public_key"]),
    }
    offer = validate_offer(
        offer, request_id=c["request_id"], device_id=device_id,
        persistent=c["persistent"], tunnel_key=c["tunnel_public_key"],
        host_key=c["host_public_key"])
    record = {
        "id": device_id, "name": c["device_name"],
        "ssh_user": SSH_USER, "tunnel_host": "127.0.0.1",
        "tunnel_port": port,
        "identity_file": f"{KEY_ROOT}/{device_id}/identity",
        "enabled": True,
    }
    Device.from_dict(record)
    next_registry = copy.deepcopy(registry)
    next_policy = copy.deepcopy(policy)
    next_registry["devices"].append(record)
    for entry in next_policy["users"]:
        if entry["subject"] == c["operator_subject"]:
            entry["devices"][device_id] = list(SSH_ACTIONS)
    return offer, next_registry, next_policy


def plan_generic_linux_activation(*, staged_candidate: dict,
                                  registry: dict, policy: dict
                                  ) -> tuple[dict, dict]:
    """Plan registry/ACL *after* an external pinned-SSH proof succeeded.

    Staged offer is immutable and signed by the validated device proof in the
    trusted pairing store; this routine deliberately CANNOT claim SSH is
    online or authorize its own root caller.
    """
    if not isinstance(staged_candidate, dict) or set(staged_candidate) != {
        "request_id", "device_id", "device_name", "operator_subject",
        "tunnel_public_key", "host_public_key", "persistent", "expires_at",
        "offer"}:
        raise PermissionError("invalid staged candidate snapshot")
    candidate = {k: value for k, value in staged_candidate.items() if k != "offer"}
    c = _candidate_identity(candidate)
    offer = validate_offer(
        staged_candidate["offer"], request_id=c["request_id"],
        device_id=c["device_id"], persistent=c["persistent"],
        tunnel_key=c["tunnel_public_key"], host_key=c["host_public_key"])
    port = offer["reverse_listen_port"]
    if not PORT_START <= port <= PORT_END:
        raise PermissionError("staged reverse SSH port outside provisioner range")
    devices = _trusted_registry(registry)
    if (any(d["id"] == c["device_id"] or int(d["tunnel_port"]) == port for d in devices)):
        raise PermissionError("duplicate device identity or assigned listener")
    if (not isinstance(policy, dict) or set(policy) != {"users"}
            or not isinstance(policy["users"], list)
            or any(not isinstance(u, dict) or not isinstance(u.get("devices"), dict)
                   for u in policy["users"])):
        raise PermissionError("invalid authorization policy")
    owners = [u for u in policy["users"]
              if u.get("subject") == c["operator_subject"]]
    if len(owners) != 1 or any(c["device_id"] in u["devices"]
                                for u in policy["users"]):
        raise PermissionError("unknown principal or pre-existing device grant")
    record = {
        "id": c["device_id"], "name": c["device_name"],
        "ssh_user": SSH_USER, "tunnel_host": "127.0.0.1",
        "tunnel_port": port,
        "identity_file": f"{KEY_ROOT}/{c['device_id']}/identity",
        "enabled": True,
    }
    Device.from_dict(record)
    next_registry = copy.deepcopy(registry)
    next_policy = copy.deepcopy(policy)
    next_registry["devices"].append(record)
    for user in next_policy["users"]:
        if user["subject"] == c["operator_subject"]:
            user["devices"][c["device_id"]] = list(SSH_ACTIONS)
    return next_registry, next_policy
