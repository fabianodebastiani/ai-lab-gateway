"""Root-only, fixed WSL one-code SSH offer staging.

NOT ENABLED UNTIL INDEPENDENT ADMIN INSTALL. This is a bounded pilot:
10003, existing WSL sshd identity, no persistent mode, no sudo,
no registry switch, no arbitrary RPC-supplied path or command.

Called by the *separate* Oracle root provisioning service only after
the nonroot device-code service validated Auth0-bound human approval.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import socket
import subprocess

from .device_code_root_environment import (
    PROD_AUTHORIZED_KEYS, PROD_KNOWN_HOSTS, PROD_REGISTRY,
    PROD_GATEWAY_HOST_KEY, protected_file, check_tunnel_sshd_policy,
)
from .device_code_root_identity import (
    BASE, PILOT, prepare_wsl_management_identity,
    verify_wsl_management_identity,
)
from .device_code_root_transaction import (
    apply_candidate_root_transaction, production_paths,
)
from .device_code_root_handoff import SOCKET, root_handoff_call
from .device_code_wsl_root_plan import build_wsl_one_code_offer, PILOT_ID

SSHD_PROBE = ("/usr/sbin/sshd", "-T", "-C",
              "user=tunnel,host=gateway.debasti.com,addr=127.0.0.1")


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError("separate UID-0 provisioning service required")


def _trusted_root_state(group_gid: int) -> None:
    """One-time root-owned directory setup with no client-controlled path."""
    parent = BASE.parent
    st = parent.lstat()
    if (st.st_uid != 0 or st.st_gid != group_gid
            or (st.st_mode & 0o777) != 0o750 or not parent.is_dir()):
        raise PermissionError("trusted Gateway parent directory unavailable")
    if not BASE.exists() and not BASE.is_symlink():
        BASE.mkdir(mode=0o750)
        os.chown(BASE, 0, group_gid)
    st = BASE.lstat()
    if (not BASE.is_dir() or BASE.is_symlink() or st.st_uid != 0
            or st.st_gid != group_gid or (st.st_mode & 0o777) != 0o750):
        raise PermissionError("untrusted root-managed SSH identity directory")


def _trusted_files(gateway_gid: int, tunnel_uid: int,
                   gateway_uid: int) -> tuple[dict, bytes, str]:
    """Read only exact fixed trusted paths, preserve their owner controls."""
    tunnel_auth = protected_file(
        PROD_AUTHORIZED_KEYS, owner_uid=tunnel_uid,
        modes=frozenset({0o600}))
    known = protected_file(
        PROD_KNOWN_HOSTS, owner_uid=gateway_uid,
        modes=frozenset({0o600}))
    registry = json.loads(protected_file(
        PROD_REGISTRY, owner_uid=0, modes=frozenset({0o640, 0o600})))
    gateway_host_key = protected_file(
        PROD_GATEWAY_HOST_KEY, owner_uid=0,
        modes=frozenset({0o644, 0o600})).decode("ascii").strip()
    if b'permitlisten="127.0.0.1:10003"' in tunnel_auth:
        raise PermissionError("candidate tunnel credential already installed")
    config = subprocess.run(SSHD_PROBE, check=True, capture_output=True,
                            text=True, timeout=8)
    check_tunnel_sshd_policy(config.stdout)
    return registry, known, gateway_host_key


def stage_one_approved_candidate() -> dict:
    """Process exactly one verified WSL approval. No reusable sudo access."""
    _require_root()
    gateway = pwd.getpwnam("ai-lab-gateway")
    tunnel = pwd.getpwnam("tunnel")
    pending = root_handoff_call(SOCKET, {"action": "list_approved"})["requests"]
    if not isinstance(pending, list) or len(pending) > 20:
        raise PermissionError("untrusted root handoff list")
    # Only the intended WSL pilot is eligible; all other devices are ignored,
    # not magically granted SSH without their own separately reviewed policy.
    for rid in pending:
        candidate = root_handoff_call(SOCKET, {
            "action": "inspect_approved", "request_id": rid})["candidate"]
        if not isinstance(candidate, dict) or not PILOT_ID.fullmatch(
                str(candidate.get("device_id", ""))):
            continue
        if candidate.get("persistent") is not False:
            continue

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
            reservation.bind(("127.0.0.1", 10003))
            registry, known, gateway_host = _trusted_files(
                gateway.pw_gid, tunnel.pw_uid, gateway.pw_uid)
            _trusted_root_state(gateway.pw_gid)
            if not (BASE / PILOT).exists():
                prepared = prepare_wsl_management_identity(
                    group_gid=gateway.pw_gid, gateway_uid=gateway.pw_uid)
                if prepared["status"] != "root_candidate_identity_prepared":
                    raise PermissionError("new root identity unavailable")
            management = verify_wsl_management_identity(
                group_gid=gateway.pw_gid, gateway_uid=gateway.pw_uid)
            offer = build_wsl_one_code_offer(
                candidate, trusted_registry=registry,
                trusted_known_hosts=known,
                gateway_ssh_host_key=gateway_host,
                gateway_management_key=management)
            def approved_again() -> bool:
                same = root_handoff_call(SOCKET, {
                    "action": "inspect_approved", "request_id": rid})["candidate"]
                return same == candidate

            applied = apply_candidate_root_transaction(
                production_paths(
                    tunnel_uid=tunnel.pw_uid, tunnel_gid=tunnel.pw_gid,
                    gateway_uid=gateway.pw_uid, gateway_gid=gateway.pw_gid),
                request_id=rid,
                tunnel_key=candidate["tunnel_public_key"],
                host_key=candidate["host_public_key"],
                approval_check=approved_again,
                verified_existing_host_pin=True,
                device_id=candidate["device_id"])
            if applied.get("status") != "candidate_ssh_staged":
                raise PermissionError("candidate root transaction failed")
            # No offer is visible to the Linux until SSH authorization has
            # been durably written. A failure at this point requires manual
            # root recovery; never silently grant root or rotate old keys.
            result = root_handoff_call(SOCKET, {
                "action": "publish_offer", "request_id": rid,
                "offer": offer, "gateway_ssh_host_key": gateway_host})
            if result["result"]["status"] != "candidate_staged":
                raise PermissionError("root provisioning offer not published")
            return {"status": "offer_staged", "port": 10003,
                    "device_id": candidate["device_id"],
                    "sudo_granted": False,
                    "old_connections_changed": False}
    return {"status": "no_matching_approved_candidate"}
