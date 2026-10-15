"""Atomic SSH fragment rehearsal against mock files ONLY (never production).

The privileged Oracle installer is not here. This exercise takes an approved,
immutable, already staged WSL device-code offer, checks exact fingerprints,
ports and root-style append fragments, and rehearses a two-file transaction
under sandbox_root/mock-gateway. No real SSH configuration can be passed in.
The lab runs as nonroot, refuses symlinks, rejects duplicated fragments and
rolls back if an injected second-stage failure occurs.

Before production: independent root-owned IPC/auth, protected source paths,
durable cross-file journal/rollback after crash, service UID enforcement,
audit, port reservation, backup and SSH negative acceptance are mandatory.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
import stat

from .device_code_candidate import PILOT_DEVICE, PILOT_PORT
from .device_code_offer import validate_offer
from .enrollment import _validate_public_key
from .device_code_candidate_journal import apply_mock_gateway_transaction


def _private_dir(folder: Path) -> None:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError("mock gateway directory must be private 0700")


def _protected_file(path: Path) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1):
        raise PermissionError("mock gateway file must be regular 0600 and unlinked")
    data = path.read_bytes()
    if len(data) > 128 * 1024:
        raise ValueError("mock SSH file is oversized")
    return data


def rehearse_mock_gateway_install(store, request_id: str, *,
                                  sandbox_root: Path,
                                  independent_gateway_host_key: str,
                                  inject_failure_after_first: bool = False) -> dict:
    """Never edits real authorized_keys, known_hosts or an SSH service.

    Only two *fixed* files inside an owned sandbox's mock-gateway directory
    are writable. This function takes no caller-controlled destination paths.
    """
    if os.geteuid() == 0:
        raise PermissionError("cannot rehearse as root")
    if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", request_id):
        raise PermissionError("invalid approved request id")
    sandbox_root = Path(sandbox_root)
    _private_dir(sandbox_root)
    mock = sandbox_root / "mock-gateway"
    _private_dir(mock)
    # Reject unapproved or expired sessions *before* looking at candidate
    # filesystem paths, so rejected requests never reveal staging layout.
    approved = store.staged_candidate_snapshot(request_id=request_id)
    candidate = sandbox_root / ("candidate-" + request_id)
    _private_dir(candidate)
    if approved["device_id"] != PILOT_DEVICE or approved["persistent"] is not False:
        raise PermissionError("WSL Restricted/on-demand pilot only")
    disk_offer = json.loads(_protected_file(candidate / "offer.json"))
    if disk_offer != approved["offer"]:
        raise PermissionError("candidate differs from approved immutable offer")
    tunnel_pub = _validate_public_key(approved["tunnel_public_key"])
    host_pub = _validate_public_key(approved["host_public_key"])
    gateway_pub = _validate_public_key(independent_gateway_host_key)
    offer = validate_offer(
        disk_offer, request_id=request_id, device_id=PILOT_DEVICE,
        persistent=False, tunnel_key=tunnel_pub, host_key=host_pub)
    if offer["gateway_ssh_host_key"] != gateway_pub:
        raise PermissionError("candidate host key does not match independent pin")
    management_pub = _validate_public_key(
        _protected_file(candidate / "gateway-management-ed25519.pub")
        .decode("ascii").strip())
    if offer["gateway_management_public_key"] != management_pub:
        raise PermissionError("candidate management key differs from offer")
    expected_tunnel = (
        'permitlisten="127.0.0.1:10003",no-agent-forwarding,'
        'no-X11-forwarding,no-pty,no-user-rc ' + tunnel_pub
        + ' ai-lab-wsl-v2\n'
    ).encode("ascii")
    expected_host = ("[127.0.0.1]:10003 " + host_pub + "\n").encode("ascii")
    if (_protected_file(candidate / "tunnel-authorized_keys.append")
            != expected_tunnel
            or _protected_file(candidate / "gateway-known_hosts.append")
            != expected_host):
        raise PermissionError("candidate fragments fail exact policy")
    if offer["reverse_listen_port"] != PILOT_PORT:
        raise PermissionError("wrong port")

    committed = apply_mock_gateway_transaction(
        sandbox_root, auth_fragment=expected_tunnel,
        host_fragment=expected_host,
        test_failure_after_first=inject_failure_after_first)
    return {
        "status": "mock_gateway_fragments_applied",
        "port": committed["port"],
        "live_ssh_changed": committed["live_ssh_changed"],
        "registry_changed": committed["registry_changed"],
    }
