"""Crash-recoverable two-file transaction, *sandbox mock SSH only*.

NOT A ROOT INSTALLER. Root execution is rejected and the only recognized
destinations are mock-gateway/authorized_keys and mock-gateway/known_hosts
under a pre-existing, caller-owned 0700 laboratory directory. The durable
journal is written before any file replacement and holds only SSH public
fragments. Recovery is a distinct explicit operation. It refuses to overwrite
unexpected external changes.

This is a rehearsal of durability mechanics, NOT evidence that production SSH
file ownership, root-owned IPC, consent or actual sshd acceptance work.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

JOURNAL = "transaction-journal.json"
LOCK = "transaction.lock"
FILES = ("authorized_keys", "known_hosts")
MAX_BYTES = 128 * 1024
PORT = b"10003"


class SimulatedProcessCrash(BaseException):
    """Test-only stand-in for process death; intentionally skips rollback."""


def _private_folder(folder: Path) -> None:
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError("expected privately owned 0700 lab directory")


def _read_file(path: Path) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise PermissionError("mock SSH file not private, regular and singly linked")
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("mock SSH file too large")
    return data


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_replace(path: Path, contents: bytes) -> None:
    if len(contents) > MAX_BYTES:
        raise ValueError("oversized test SSH file")
    fd, tmp = tempfile.mkstemp(prefix=".transaction-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(contents)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _encoded(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decoded(data: str) -> bytes:
    if not isinstance(data, str) or len(data) > (MAX_BYTES * 2):
        raise PermissionError("invalid transaction bytes")
    raw = base64.b64decode(data, validate=True)
    if len(raw) > MAX_BYTES:
        raise PermissionError("oversized transaction bytes")
    return raw


def _strict_mock_root(root: Path) -> Path:
    if os.geteuid() == 0:
        raise PermissionError("nonroot mock only; no production root installer")
    root = Path(root)
    _private_folder(root)
    mock = root / "mock-gateway"
    _private_folder(mock)
    return mock


def _lock(mock: Path) -> int:
    path = mock / LOCK
    fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise PermissionError("unsafe transaction lock file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _journal_payload(originals: tuple[bytes, bytes],
                     replacements: tuple[bytes, bytes]) -> bytes:
    payload = {
        "version": 1,
        "files": {
            label: {
                "original": _encoded(old),
                "new_hash": _sha(new),
                "old_hash": _sha(old),
            }
            for label, old, new in zip(FILES, originals, replacements)
        },
    }
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _persist_journal(mock: Path, originals: tuple[bytes, bytes],
                     replacements: tuple[bytes, bytes]) -> None:
    path = mock / JOURNAL
    payload = _journal_payload(originals, replacements)
    # O_EXCL: a concurrent or crashed prior transaction must be resolved.
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(mock)
    except BaseException:
        # Even after a failed fsync the file is a recovery marker.
        raise


def _parse_journal(raw: bytes):
    try:
        item = json.loads(raw)
        if (not isinstance(item, dict) or set(item) != {"version", "files"}
                or type(item["version"]) is not int or item["version"] != 1
                or not isinstance(item["files"], dict)
                or set(item["files"]) != set(FILES)):
            raise ValueError("invalid transaction record")
        entries = []
        for name in FILES:
            value = item["files"][name]
            if not isinstance(value, dict) or set(value) != {
                    "original", "old_hash", "new_hash"}:
                raise ValueError("invalid transaction file record")
            old = _decoded(value["original"])
            if (_sha(old) != value["old_hash"]
                    or not isinstance(value["new_hash"], str)
                    or len(value["new_hash"]) != 64):
                raise ValueError("transaction integrity mismatch")
            entries.append((old, value["new_hash"]))
        return entries
    except (ValueError, TypeError, KeyError) as exc:
        raise PermissionError("invalid durable transaction journal") from exc


def _recover_locked(mock: Path) -> bool:
    journal = mock / JOURNAL
    if not journal.exists() and not journal.is_symlink():
        return False
    entries = _parse_journal(_read_file(journal))
    paths = [mock / name for name in FILES]
    current = [_read_file(path) for path in paths]
    # Do not overwrite unrelated updates after a crash. Files must exactly
    # match either their original hash or the planned new hash.
    for existing, (old, newhash) in zip(current, entries):
        if _sha(existing) not in (_sha(old), newhash):
            raise PermissionError("SSH file changed outside pending transaction")
    for path, (_, record) in zip(paths, entries):
        pass
    for path, (old, _) in zip(paths, entries):
        if _read_file(path) != old:
            _atomic_replace(path, old)
    journal.unlink()
    _fsync_dir(mock)
    return True


def recover_mock_gateway_transaction(sandbox_root: Path) -> bool:
    """Explicit crash recovery, never silently continue a new installation."""
    mock = _strict_mock_root(sandbox_root)
    fd = _lock(mock)
    try:
        return _recover_locked(mock)
    finally:
        os.close(fd)


def apply_mock_gateway_transaction(sandbox_root: Path, *, auth_fragment: bytes,
                                   host_fragment: bytes,
                                   test_crash_after: str | None = None,
                                   test_failure_after_first: bool = False) -> dict:
    """Durable simulated append after separate candidate validation.

    Callers must validate immutable candidate identities *before* invocation.
    The fragments are not public RPC fields; this module has no RPC handler.
    """
    mock = _strict_mock_root(sandbox_root)
    if (not isinstance(auth_fragment, bytes) or not isinstance(host_fragment, bytes)
            or not auth_fragment.endswith(b"\n") or not host_fragment.endswith(b"\n")
            or b"\n" in auth_fragment.strip(b"\n")
            or b"\n" in host_fragment.strip(b"\n")
            or b'permitlisten="127.0.0.1:10003"' not in auth_fragment
            or not host_fragment.startswith(b"[127.0.0.1]:10003 ssh-ed25519 ")
            or len(auth_fragment) > 2048 or len(host_fragment) > 2048):
        raise PermissionError("only single-line WSL candidate SSH fragments accepted")
    if test_crash_after not in (None, "first", "second"):
        raise ValueError("invalid test crash point")
    fd = _lock(mock)
    try:
        journal = mock / JOURNAL
        if journal.exists() or journal.is_symlink():
            raise PermissionError("pending crash recovery must be completed first")
        paths = [mock / name for name in FILES]
        originals = tuple(_read_file(p) for p in paths)
        auth, known = originals
        if (auth_fragment.strip() in auth or host_fragment.strip() in known
                or b'permitlisten="127.0.0.1:10003"' in auth
                or b"[127.0.0.1]:10003 " in known):
            raise FileExistsError("WSL candidate already present")
        replacements = (auth.rstrip(b"\n") + b"\n" + auth_fragment,
                        known.rstrip(b"\n") + b"\n" + host_fragment)
        if any(len(s) > MAX_BYTES for s in replacements):
            raise ValueError("oversized candidate SSH contents")
        _persist_journal(mock, originals, replacements)
        try:
            _atomic_replace(paths[0], replacements[0])
            if test_crash_after == "first":
                raise SimulatedProcessCrash()
            if test_failure_after_first:
                raise RuntimeError("injected after-first failure")
            _atomic_replace(paths[1], replacements[1])
            if test_crash_after == "second":
                raise SimulatedProcessCrash()
        except Exception:
            _recover_locked(mock)
            raise
        journal.unlink()
        _fsync_dir(mock)
        return {"status": "mock_candidate_applied", "port": 10003,
                "live_ssh_changed": False, "registry_changed": False}
    finally:
        os.close(fd)
