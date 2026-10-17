"""Root-only SSH acceptance and restricted MCP registration for any Linux.

A new device is never registered until the existing Gateway SSH service has
authenticated to the exact pinned target, using a unique private key, and
confirmed the no-sudo Linux management account. The candidate's Auth0 owner
comes only from the independently authenticated device-code store.

Changes to the two root-owned JSON configuration files use a root-only,
fsync-backed journal. A crashed transaction blocks subsequent enrollment;
recovery requires human review. No privileged shell or caller-supplied path
is exposed to MCP or to any pairing HTTP request.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import tempfile
import time

from .device_code_root_handoff import SOCKET, root_handoff_call
from .device_code_root_environment import (
    PROD_KNOWN_HOSTS, PROD_REGISTRY, protected_file)
from .device_code_root_generic_stage import KEY_ROOT, ROOT_STATE, _root_directory
from .device_code_linux_plan import (
    DEVICE_ID, PORT_START, PORT_END, plan_generic_linux_activation,
)
from .enrollment import _validate_public_key

POLICY_PATH = Path("/etc/ai-lab-gateway/authorization.json")
LOCK = ROOT_STATE / "generic-activation.lock"
JOURNAL = ROOT_STATE / "generic-activation-pending.json"
MAX_JSON = 256 * 1024


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _trusted_json(path: Path, gateway_gid: int) -> tuple[bytes, dict]:
    parent = path.parent.lstat()
    info = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or stat.S_IMODE(parent.st_mode) & 0o022
            or not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != gateway_gid
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o640)
            or info.st_nlink != 1):
        raise PermissionError("protected Gateway registry/policy metadata changed")
    content = protected_file(
        path, owner_uid=0, modes=frozenset({0o600, 0o640}),
        limit=MAX_JSON)
    value = json.loads(content)
    if not isinstance(value, dict):
        raise PermissionError("expected protected JSON object")
    return content, value


def _read_exact_host_pin(raw: bytes, port: int) -> str:
    endpoint = "[127.0.0.1]:" + str(port)
    matches = []
    for line in raw.decode("ascii").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] == endpoint:
            if len(fields) != 3 or fields[1] != "ssh-ed25519":
                raise PermissionError("invalid candidate SSH pin")
            matches.append(_validate_public_key(" ".join(fields[1:])))
        elif endpoint in fields[0].split(",") or (
                fields[0].startswith("@") and endpoint in line):
            raise PermissionError("unexpected marked/merged SSH host pin")
    if len(matches) != 1:
        raise PermissionError("candidate SSH host pin must be unique")
    return matches[0]


def _run_ssh(gateway_uid: int, gateway_gid: int, port: int,
             key_path: Path, remote_command: str) -> subprocess.CompletedProcess:
    argv = [
        "/usr/bin/setpriv", "--reuid", str(gateway_uid),
        "--regid", str(gateway_gid), "--clear-groups",
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UserKnownHostsFile=" + str(PROD_KNOWN_HOSTS),
        "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1",
        "-o", "ControlMaster=no", "-o", "ClearAllForwardings=yes",
        "-o", "LogLevel=ERROR",
        "-i", str(key_path), "-p", str(port),
        "ai-gateway@127.0.0.1", "--", remote_command,
    ]
    return subprocess.run(argv, check=False, capture_output=True,
                          text=True, timeout=8)


def _verified_target(candidate: dict, *, gateway_uid: int,
                     gateway_gid: int) -> bool:
    offer = candidate["offer"]
    port = offer["reverse_listen_port"]
    if (type(port) is not int or not PORT_START <= port <= PORT_END
            or offer["management_user"] != "ai-gateway"
            or offer["access_mode"] != "restricted"):
        raise PermissionError("candidate SSH offer is not a restricted Linux")
    if int(candidate["expires_at"]) <= int(time.time()):
        raise PermissionError("pairing expired before activation")
    known = protected_file(
        PROD_KNOWN_HOSTS, owner_uid=gateway_uid,
        modes=frozenset({0o600}))
    if _read_exact_host_pin(known, port) != _validate_public_key(
            candidate["host_public_key"]):
        raise PermissionError("approved target SSH host identity mismatch")
    device_id = candidate["device_id"]
    if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
        raise PermissionError("invalid device identity")
    key_dir = KEY_ROOT / device_id
    if key_dir.is_symlink():
        raise PermissionError("management identity directory is symlinked")
    dir_stat = key_dir.lstat()
    if not stat.S_ISDIR(dir_stat.st_mode) or dir_stat.st_uid != 0:
        raise PermissionError("management private key directory not root-owned")
    key = key_dir / "identity"
    info = key.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_gid != gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o640
            or info.st_nlink != 1):
        raise PermissionError("untrusted Gateway management private key")
    key_public = key.with_suffix(".pub")
    expected = _validate_public_key(key_public.read_text().strip())
    if expected != offer["gateway_management_public_key"]:
        raise PermissionError("management public key differs from offer")

    try:
        who = _run_ssh(gateway_uid, gateway_gid, port, key, "id -un")
        host = _run_ssh(gateway_uid, gateway_gid, port, key, "hostname")
        uname = _run_ssh(gateway_uid, gateway_gid, port, key, "uname -s")
        sudo = _run_ssh(gateway_uid, gateway_gid, port, key, "sudo -n id -u")
    except (OSError, subprocess.TimeoutExpired):
        return False
    if (who.returncode != 0 or who.stdout.strip() != "ai-gateway"
            or host.returncode != 0
            or host.stdout.strip().lower() != candidate["device_name"].lower()
            or uname.returncode != 0 or uname.stdout.strip() != "Linux"):
        return False
    # No unrestricted sudo by default; a missing sudo command also fails.
    if sudo.returncode == 0:
        raise PermissionError("new management user unexpectedly has sudo")
    return True


def _sync_parent(path: Path) -> None:
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace_json(path: Path, before: bytes, after: bytes, gid: int):
    if len(after) > MAX_JSON:
        raise PermissionError("new protected configuration too large")
    current, _ = _trusted_json(path, gid)
    if current != before:
        raise PermissionError("protected configuration changed concurrently")
    fd, temp = tempfile.mkstemp(prefix=".device-onboard-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), 0, gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(after)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        _sync_parent(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _new_json(data: dict) -> bytes:
    return (json.dumps(data, sort_keys=True, indent=2) + "\n").encode("utf8")


def _journal(before: tuple[bytes, bytes], after: tuple[bytes, bytes]):
    if JOURNAL.exists() or JOURNAL.is_symlink():
        raise PermissionError("root registry/policy recovery required")
    record = {
        "version": 1,
        "before": [base64.b64encode(x).decode("ascii") for x in before],
        "after_sha256": [_hash(x) for x in after],
        "before_sha256": [_hash(x) for x in before],
    }
    encoded = _new_json(record)
    fd = os.open(JOURNAL, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(encoded)
        out.flush()
        os.fsync(out.fileno())
    _sync_parent(ROOT_STATE)


def _commit_active(candidate: dict, *, gateway_gid: int) -> dict:
    fd = os.open(LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if JOURNAL.exists() or JOURNAL.is_symlink():
            raise PermissionError("previous candidate requires root recovery")
        old_registry, registry = _trusted_json(PROD_REGISTRY, gateway_gid)
        old_policy, policy = _trusted_json(POLICY_PATH, gateway_gid)
        updated_registry, updated_policy = plan_generic_linux_activation(
            staged_candidate=candidate, registry=registry, policy=policy)
        next_registry, next_policy = (
            _new_json(updated_registry), _new_json(updated_policy))
        _journal((old_registry, old_policy), (next_registry, next_policy))
        try:
            _replace_json(PROD_REGISTRY, old_registry, next_registry, gateway_gid)
            _replace_json(POLICY_PATH, old_policy, next_policy, gateway_gid)
            refreshed = root_handoff_call(SOCKET, {
                "action": "inspect_staged", "request_id": candidate["request_id"],
            })["candidate"]
            if refreshed != candidate:
                raise PermissionError("candidate approval changed before activation")
            result = root_handoff_call(SOCKET, {
                "action": "mark_active", "request_id": candidate["request_id"]})
            if result["result"]["status"] != "active":
                raise PermissionError("device-code state not marked active")
        except Exception:
            safe = True
            for path, previous, expected in (
                (POLICY_PATH, old_policy, next_policy),
                (PROD_REGISTRY, old_registry, next_registry)):
                current, _ = _trusted_json(path, gateway_gid)
                if current == expected:
                    _replace_json(path, current, previous, gateway_gid)
                elif current != previous:
                    safe = False
            if safe:
                JOURNAL.unlink()
            raise
        JOURNAL.unlink()
        _sync_parent(ROOT_STATE)
        return {"status": "active", "device_id": candidate["device_id"],
                "port": candidate["offer"]["reverse_listen_port"],
                "access_mode": "restricted"}
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def finalize_one_staged_generic_linux() -> dict:
    if os.geteuid() != 0:
        raise PermissionError("root-only SSH verification and activation")
    gateway = pwd.getpwnam("ai-lab-gateway")
    _root_directory(ROOT_STATE)
    staged = root_handoff_call(SOCKET, {"action": "list_staged"})["requests"]
    if not isinstance(staged, list) or len(staged) > 20:
        raise PermissionError("untrusted staged candidate inventory")
    for rid in staged:
        candidate = root_handoff_call(
            SOCKET, {"action": "inspect_staged", "request_id": rid})["candidate"]
        if not isinstance(candidate, dict):
            raise PermissionError("untrusted candidate")
        if not _verified_target(candidate, gateway_uid=gateway.pw_uid,
                                gateway_gid=gateway.pw_gid):
            continue
        return _commit_active(candidate, gateway_gid=gateway.pw_gid)
    return {"status": "no_ssh_verified_candidate"}
