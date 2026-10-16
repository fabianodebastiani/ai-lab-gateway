"""Root-owned, two-file WSL candidate transaction core — NOT DEPLOYED.

Unlike the earlier nonroot mock, this core uses real kernel UID and file
ownership, preserves the *different* owners of tunnel authorized_keys and
Gateway known_hosts, fsyncs a root-only undo journal before the first write,
and requires explicit recovery after an interrupted operation.

Production paths MUST be built solely by production_paths(), not by HTTP,
MCP, the remote Linux or a client-supplied JSON value. A root-only test
constructs a synthetic fixture in a disposable CI directory; NO production
SSH file is modified by the tests. This core has no network listener,
sudo operation, activation or registry cutover.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from dataclasses import dataclass

from .device_code_root_environment import PROD_AUTHORIZED_KEYS, PROD_KNOWN_HOSTS
from .enrollment import _validate_public_key

MAX_FILE = 128 * 1024
ROOT_UID = 0
JOURNAL = "pending-ssh-10003.json"
LOCK = "ssh-10003.lock"
AUDIT = "ssh-10003-audit.jsonl"
RID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")


class InterruptedRootTransaction(BaseException):
    """Only used by root-CI tests to model sudden process death."""


@dataclass(frozen=True)
class RootSSHPaths:
    authorized_keys: Path
    known_hosts: Path
    journal_dir: Path
    tunnel_uid: int
    tunnel_gid: int
    gateway_uid: int
    gateway_gid: int


def production_paths(*, tunnel_uid: int, tunnel_gid: int,
                     gateway_uid: int, gateway_gid: int) -> RootSSHPaths:
    """Fixed root-controlled destinations. Never build these from RPC input."""
    return RootSSHPaths(
        authorized_keys=PROD_AUTHORIZED_KEYS,
        known_hosts=PROD_KNOWN_HOSTS,
        journal_dir=Path("/var/lib/ai-lab-gateway/root-provision-10003"),
        tunnel_uid=tunnel_uid, tunnel_gid=tunnel_gid,
        gateway_uid=gateway_uid, gateway_gid=gateway_gid,
    )


def _require_root() -> None:
    if os.geteuid() != ROOT_UID:
        raise PermissionError("real root UID required for SSH transaction")


def _root_journal_dir(paths: RootSSHPaths) -> Path:
    _require_root()
    root = paths.journal_dir
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != ROOT_UID
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError("root-only journal directory required")
    return root


def _check_parent(path: Path, uid: int) -> None:
    info = path.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise PermissionError("untrusted SSH parent directory")


def _read_exact(path: Path, uid: int, gid: int) -> bytes:
    _check_parent(path, uid)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1):
            raise PermissionError("unsafe SSH file owner, group, mode or link count")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_FILE + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_FILE:
        raise ValueError("SSH file exceeds allowed size")
    return data


def _sync_dir(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace(path: Path, payload: bytes, uid: int, gid: int,
             *, expected: bytes) -> None:
    if len(payload) > MAX_FILE:
        raise ValueError("SSH replacement too large")
    if _read_exact(path, uid, gid) != expected:
        raise PermissionError("SSH file changed after the approved snapshot")
    fd, name = tempfile.mkstemp(prefix=".candidate10003-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        _sync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _journal_bytes(before: tuple[bytes, bytes],
                   after: tuple[bytes, bytes], request_id: str) -> bytes:
    record = {
        "version": 1, "request_id": request_id, "port": 10003,
        "files": [
            {"name": name, "original": base64.b64encode(old).decode("ascii"),
             "old_sha256": _hash(old), "new_sha256": _hash(new)}
            for name, old, new in zip(("authorized_keys", "known_hosts"), before, after)
        ],
    }
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _load_journal(path: Path) -> tuple[str, list[tuple[bytes, str]]]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise PermissionError("root transaction journal is untrusted")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE * 4:
        raise PermissionError("root transaction journal too large")
    try:
        j = json.loads(raw)
        if (set(j) != {"version", "request_id", "port", "files"}
                or type(j["version"]) is not int or j["version"] != 1
                or type(j["port"]) is not int or j["port"] != 10003
                or not isinstance(j["request_id"], str)
                or not RID.fullmatch(j["request_id"])
                or not isinstance(j["files"], list) or len(j["files"]) != 2):
            raise ValueError("invalid root journal format")
        entries = []
        for item, name in zip(j["files"], ("authorized_keys", "known_hosts")):
            if not isinstance(item, dict) or set(item) != {
                    "name", "original", "old_sha256", "new_sha256"
            } or item["name"] != name:
                raise ValueError("unknown journal destination")
            original = base64.b64decode(item["original"], validate=True)
            if (len(original) > MAX_FILE or _hash(original) != item["old_sha256"]
                    or not isinstance(item["new_sha256"], str)
                    or not re.fullmatch("[a-f0-9]{64}", item["new_sha256"])):
                raise ValueError("untrusted undo record")
            entries.append((original, item["new_sha256"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise PermissionError("invalid root transaction journal") from exc
    return j["request_id"], entries


def _record(root: Path, request_id: str, status: str) -> None:
    """Best-effort audit durability is NOT sufficient for external compliance."""
    if status not in ("prepared", "applied", "restored"):
        raise ValueError("unknown audit event")
    path = root / AUDIT
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (info.st_uid != ROOT_UID or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode)):
            raise PermissionError("unsafe root SSH audit file")
        value = (json.dumps({"request_id": request_id, "status": status},
                            separators=(",", ":")) + "\n").encode()
        os.write(fd, value)
        os.fsync(fd)
    finally:
        os.close(fd)


def _lock(root: Path) -> int:
    fd = os.open(root / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != ROOT_UID
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise PermissionError("unsafe root transaction lock")
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _end_lock(fd: int) -> None:
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)


def _destinations(paths: RootSSHPaths):
    return (
        (paths.authorized_keys, paths.tunnel_uid, paths.tunnel_gid),
        (paths.known_hosts, paths.gateway_uid, paths.gateway_gid),
    )


def _recover_locked(paths: RootSSHPaths, root: Path) -> bool:
    jpath = root / JOURNAL
    if not jpath.exists() and not jpath.is_symlink():
        return False
    rid, entries = _load_journal(jpath)
    destinations = _destinations(paths)
    existing = [_read_exact(p, uid, gid) for p, uid, gid in destinations]
    for raw, (old, planned_hash) in zip(existing, entries):
        if _hash(raw) not in (_hash(old), planned_hash):
            raise PermissionError("another administrator modified SSH after crash")
    for (path, uid, gid), current, (original, _) in zip(destinations, existing, entries):
        if current != original:
            _replace(path, original, uid, gid, expected=current)
    _record(root, rid, "restored")
    jpath.unlink()
    _sync_dir(root)
    return True


def recover_candidate_root_transaction(paths: RootSSHPaths) -> bool:
    """Explicit supervised recovery, never an MCP callback."""
    root = _root_journal_dir(paths)
    lock = _lock(root)
    try:
        return _recover_locked(paths, root)
    finally:
        _end_lock(lock)


def _validated_fragments(tunnel_key: str, host_key: str) -> tuple[bytes, bytes]:
    tunnel = _validate_public_key(tunnel_key)
    host = _validate_public_key(host_key)
    if tunnel == host:
        raise PermissionError("host and tunnel SSH key cannot be equal")
    auth = (
        'permitlisten="127.0.0.1:10003",no-agent-forwarding,'
        'no-X11-forwarding,no-pty,no-user-rc ' + tunnel +
        " ai-lab-wsl-v2\n").encode("ascii")
    known = ("[127.0.0.1]:10003 " + host + "\n").encode("ascii")
    return auth, known


def apply_candidate_root_transaction(paths: RootSSHPaths, *,
                                     request_id: str, tunnel_key: str,
                                     host_key: str, approval_check,
                                     test_interrupt_after: int = 0,
                                     verified_existing_host_pin: bool = False,
                                     device_id: str = "windows-wsl") -> dict:
    """Apply only one verified WSL candidate; no registry or service changes.

    The caller MUST obtain keys from the authenticated approval handoff and
    perform root environment preflight. approval_check rechecks that same
    approval under the transaction lock immediately before writing.
    test_interrupt_after is private to unit tests: the root production
    adapter MUST NOT expose it as a parameter.
    """
    if not isinstance(request_id, str) or not RID.fullmatch(request_id):
        raise PermissionError("invalid candidate transaction identity")
    if not isinstance(device_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,47}", device_id):
        raise PermissionError("untrusted candidate device identifier")
    if type(verified_existing_host_pin) is not bool:
        raise PermissionError("invalid existing host pin mode")
    if type(test_interrupt_after) is not int or test_interrupt_after not in (0, 1, 2):
        raise ValueError("invalid test mode")
    fragments = _validated_fragments(tunnel_key, host_key)
    root = _root_journal_dir(paths)
    fd = _lock(root)
    try:
        journal = root / JOURNAL
        if journal.exists() or journal.is_symlink():
            raise PermissionError("root SSH recovery is required before new apply")
        # Never authorize from the presence of a previous successful preflight
        # or from a model-provided provisioner_verified flag.
        if approval_check() is not True:
            raise PermissionError("fresh independent human approval unavailable")
        destinations = _destinations(paths)
        before = tuple(_read_exact(p, uid, gid) for p, uid, gid in destinations)
        if b'permitlisten="127.0.0.1:10003"' in before[0]:
            raise PermissionError("candidate tunnel credential already authorized")
        pinned = []
        for line in before[1].splitlines():
            parts = line.split()
            if parts and parts[0] == b"[127.0.0.1]:10003":
                pinned.append(line.strip())
            elif parts and (b"[127.0.0.1]:10003" in parts[0].split(b",")
                             or (parts[0].startswith(b"@") and
                                 b"[127.0.0.1]:10003" in line)):
                raise PermissionError("ambiguous candidate host pin")
        if pinned:
            if (not verified_existing_host_pin or len(pinned) != 1
                    or pinned[0] != fragments[1].strip()):
                raise PermissionError("candidate host pin mismatch or duplicate")
            known_after = before[1]
        else:
            known_after = before[1].rstrip(b"\n") + b"\n" + fragments[1]
        after = (
            before[0].rstrip(b"\n") + b"\n" + fragments[0],
            known_after,
        )
        if any(len(chunk) > MAX_FILE for chunk in after):
            raise ValueError("candidate SSH file too large")
        payload = _journal_bytes(before, after, request_id)
        jf = os.open(journal, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(jf, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            _sync_dir(root)
        except BaseException:
            # A journal may already exist. Do NOT unlink: it is a
            # recovery marker even if initial fsync failed.
            raise
        _record(root, request_id, "prepared")
        try:
            _replace(destinations[0][0], after[0], *destinations[0][1:], expected=before[0])
            if test_interrupt_after == 1:
                raise InterruptedRootTransaction()
            _replace(destinations[1][0], after[1], *destinations[1][1:], expected=before[1])
            if test_interrupt_after == 2:
                raise InterruptedRootTransaction()
        except Exception:
            _recover_locked(paths, root)
            raise
        _record(root, request_id, "applied")
        journal.unlink()
        _sync_dir(root)
        return {"status": "candidate_ssh_staged", "port": 10003,
                "device_id": device_id, "registry_changed": False,
                "sudo_granted": False}
    finally:
        _end_lock(fd)
