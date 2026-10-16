"""Restricted Linux SSH offer provisioning. Root-only; never exposed to MCP.

Every operation is fixed and derived from one still-valid, Auth0-approved
device proof. No RPC parameter supplies a command, path, port or privilege.
A Gateway management private key NEVER leaves this machine; a device
tunnel private key NEVER enters this machine.

Root transaction journal and per-device SSH identities are isolated so a
failed candidate cannot corrupt existing devices. If interrupted, fail
closed and require supervised recovery rather than rotating existing keys.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import tempfile

from .device_code_root_environment import (
    PROD_AUTHORIZED_KEYS, PROD_KNOWN_HOSTS, PROD_REGISTRY,
    PROD_GATEWAY_HOST_KEY, protected_file, check_tunnel_sshd_policy,
)
from .device_code_root_handoff import SOCKET, root_handoff_call
from .device_code_root_transaction import (
    RootSSHPaths, apply_candidate_root_transaction,
)
from .device_code_linux_plan import (
    choose_loopback_port, plan_generic_linux_enrollment, DEVICE_ID,
)

KEY_ROOT = Path("/etc/ai-lab-gateway/device-code-keys")
ROOT_STATE = Path("/var/lib/ai-lab-root-provision")
ROOT_LOCK = ROOT_STATE / "generic-enrollment.lock"


def _require_root():
    if os.geteuid() != 0:
        raise PermissionError("root-only SSH staging")


def _root_directory(path: Path, *, group: int = 0, mode: int = 0o700):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
        os.chown(path, 0, group)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_gid != group or stat.S_IMODE(info.st_mode) != mode):
        raise PermissionError("untrusted root provisioning directory")


def _known_reserved(raw: bytes) -> set[int]:
    occupied = set()
    for line in raw.decode("ascii").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        items = line.split()
        if not items:
            continue
        m = re.fullmatch(r"\[127\.0\.0\.1\]:(\d+)", items[0])
        if m:
            occupied.add(int(m.group(1)))
        elif "[127.0.0.1]:" in line:
            # Mixed/marked entries are not safe to allocate against.
            for value in re.findall(r"\[127\.0\.0\.1\]:(\d+)", line):
                occupied.add(int(value))
    return occupied


def _authorized_reserved(raw: bytes) -> set[int]:
    occupied = set()
    for m in re.finditer(rb'permitlisten="127\.0\.0\.1:(\d+)"', raw):
        occupied.add(int(m.group(1)))
    return occupied


def _trusted_state(tunnel_uid: int, gateway_uid: int) -> tuple[dict, bytes, str, set[int]]:
    auth = protected_file(PROD_AUTHORIZED_KEYS, owner_uid=tunnel_uid,
                          modes=frozenset({0o600}))
    known = protected_file(PROD_KNOWN_HOSTS, owner_uid=gateway_uid,
                           modes=frozenset({0o600}))
    registry = json.loads(protected_file(
        PROD_REGISTRY, owner_uid=0, modes=frozenset({0o640, 0o600})))
    gateway_key = protected_file(
        PROD_GATEWAY_HOST_KEY, owner_uid=0,
        modes=frozenset({0o644, 0o600})).decode("ascii").strip()
    # Fail-closed if sshd account restrictions were accidentally relaxed.
    config = subprocess.run(
        ["/usr/sbin/sshd", "-T", "-C",
         "user=tunnel,host=gateway.debasti.com,addr=127.0.0.1"],
        capture_output=True, text=True, check=True, timeout=8)
    check_tunnel_sshd_policy(config.stdout)
    return registry, known, gateway_key, (
        _known_reserved(known) | _authorized_reserved(auth))


def _create_management_identity(device_id: str, gateway_uid: int, gateway_gid: int) -> str:
    if not DEVICE_ID.fullmatch(device_id):
        raise PermissionError("invalid approved device ID")
    _root_directory(KEY_ROOT, group=gateway_gid, mode=0o750)
    dest = KEY_ROOT / device_id
    if dest.exists() or dest.is_symlink():
        raise PermissionError("management key already staged; no silent rotation")
    dest.mkdir(mode=0o750)
    os.chown(dest, 0, gateway_gid)
    private = dest / "identity"
    subprocess.run(
        ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
         "-N", "", "-f", str(private),
         "-C", "ai-lab-device-code-" + device_id],
        check=True, capture_output=True, timeout=15)
    public = private.with_suffix(".pub")
    for file in (private, public):
        os.chown(file, 0, gateway_gid)
        os.chmod(file, 0o640)
    verified = subprocess.run(
        ["/usr/bin/setpriv", "--reuid", str(gateway_uid),
         "--regid", str(gateway_gid), "--clear-groups",
         "/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(private)],
        check=True, capture_output=True, text=True, timeout=8).stdout.strip()
    from .enrollment import _validate_public_key
    actual = _validate_public_key(public.read_text().strip())
    if _validate_public_key(verified) != actual:
        raise PermissionError("management keypair inaccessible or changed")
    return actual


def _choose_free_port(registry: dict, occupied: set[int]) -> tuple[int, socket.socket]:
    # Keep the selected port reserved until SSH authorized_keys is committed.
    for _ in range(1000):
        port = choose_loopback_port(registry=registry, reserved_ports=occupied)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            sock.close()
            occupied.add(port)
            continue
        return port, sock
    raise PermissionError("cannot reserve an SSH loopback port")


def stage_one_approved_generic_linux() -> dict:
    """One independently approved identity, one reserved loopback port."""
    _require_root()
    gw = pwd.getpwnam("ai-lab-gateway")
    tunnel = pwd.getpwnam("tunnel")
    _root_directory(ROOT_STATE)
    lock_fd = os.open(ROOT_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        approved = root_handoff_call(SOCKET, {"action": "list_approved"})["requests"]
        if not isinstance(approved, list) or len(approved) > 20:
            raise PermissionError("untrusted approved request inventory")
        for rid in approved:
            candidate = root_handoff_call(
                SOCKET, {"action": "inspect_approved", "request_id": rid})["candidate"]
            if not isinstance(candidate, dict):
                raise PermissionError("untrusted candidate")
            device_id = candidate.get("device_id")
            if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
                raise PermissionError("untrusted approved identity")
            registry, known, gateway_key, occupied = _trusted_state(
                tunnel.pw_uid, gw.pw_uid)
            port, sock = _choose_free_port(registry, occupied)
            try:
                # Root-controlled, root-owned per-port crash recovery.
                journal_dir = ROOT_STATE / ("ssh-" + str(port))
                _root_directory(journal_dir)
                # This only stages a per-device keypair in a root-owned
                # directory. No existing device identity is ever rotated.
                management_pub = _create_management_identity(
                    device_id, gw.pw_uid, gw.pw_gid)
                offer, _, _ = plan_generic_linux_enrollment(
                    approved_candidate=candidate,
                    registry=registry,
                    policy=_read_owner_policy(),
                    reserved_ports=tuple(sorted(occupied | set(range(11000, port)))),
                    gateway_ssh_host_key=gateway_key,
                    gateway_management_public_key=management_pub)
                if offer["reverse_listen_port"] != port:
                    raise PermissionError("reserved port and validated offer differ")
                def still_approved() -> bool:
                    updated = root_handoff_call(
                        SOCKET, {"action": "inspect_approved",
                                 "request_id": rid})["candidate"]
                    return updated == candidate
                paths = RootSSHPaths(
                    authorized_keys=PROD_AUTHORIZED_KEYS,
                    known_hosts=PROD_KNOWN_HOSTS,
                    journal_dir=journal_dir,
                    tunnel_uid=tunnel.pw_uid,
                    tunnel_gid=tunnel.pw_gid,
                    gateway_uid=gw.pw_uid,
                    gateway_gid=gw.pw_gid)
                outcome = apply_candidate_root_transaction(
                    paths, request_id=rid,
                    tunnel_key=candidate["tunnel_public_key"],
                    host_key=candidate["host_public_key"],
                    approval_check=still_approved, device_id=device_id,
                    port=port)
                if outcome["status"] != "candidate_ssh_staged":
                    raise PermissionError("SSH staging transaction incomplete")
            finally:
                sock.close()
            published = root_handoff_call(SOCKET, {
                "action": "publish_offer", "request_id": rid,
                "offer": offer, "gateway_ssh_host_key": gateway_key,
            })
            if published["result"]["status"] != "candidate_staged":
                raise PermissionError("provisioned offer not published")
            return {"status": "offer_staged", "device_id": device_id,
                    "port": port, "access_mode": "restricted"}
        return {"status": "no_approved_candidate"}
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _read_owner_policy() -> dict:
    file = Path("/etc/ai-lab-gateway/authorization.json")
    return json.loads(protected_file(
        file, owner_uid=0, modes=frozenset({0o640, 0o600})))
