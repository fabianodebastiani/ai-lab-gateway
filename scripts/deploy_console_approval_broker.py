#!/usr/bin/python3 -I
"""Original-admin-only broker hotfix for independent LOCAL console approval.

Only the already-running root broker executable is replaced; OAuth and target
authorizations are not changed. This helper never approves any request.
It refuses unexpected source and installed hashes; stores a root-only backup
and reverts on service failure. Run solely from the original ubuntu/OCI session.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

BROKER = Path("/usr/local/libexec/ai-lab-privilege-brokerd")
BACKUP = Path("/var/backups/ai-lab-console-approval-broker-v1")
SERVICE = "ai-lab-privilege-broker"
OLD_SHA = "f75d339600c30a063cb5f556434523e658de048f708429dc1f1dc3ad441b8199"
NEW_SHA = "479034afb80594138cd3c6e4a1d5f7dfad1835e3a62888cc83353727ba64d902"


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def protected(path: Path, expected_uid: int = 0) -> bytes:
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != expected_uid
            or bool(st.st_mode & 0o022) or st.st_size > 125000):
        raise PermissionError("untrusted broker / backup file")
    return path.read_bytes()


def check(source: Path) -> bytes:
    old = protected(BROKER)
    if checksum(old) != OLD_SHA:
        raise PermissionError("live broker does not match pinned baseline")
    if BACKUP.exists() or BACKUP.is_symlink():
        raise PermissionError("existing broker backup; no second deployment")
    src = source.lstat()
    if not stat.S_ISREG(src.st_mode) or src.st_size > 125000:
        raise PermissionError("source must be a regular file")
    new = source.read_bytes()
    if checksum(new) != NEW_SHA:
        raise PermissionError("new broker source hash mismatch")
    if not new.startswith(b"#!/usr/bin/env python3\n"):
        raise PermissionError("unexpected broker Python interpreter")
    return new


def replace_broker(data: bytes) -> None:
    st = BROKER.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0:
        raise PermissionError("broker executable ownership invalid")
    fd, name = tempfile.mkstemp(prefix=".ai-lab-broker-", dir=BROKER.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchown(f.fileno(), 0, 0)
            os.fchmod(f.fileno(), stat.S_IMODE(st.st_mode))
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, BROKER)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def restart() -> None:
    result = subprocess.run(
        ["/usr/bin/systemctl", "restart", SERVICE], capture_output=True,
        text=True, stdin=subprocess.DEVNULL, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("broker restart failed: " + result.stderr[:300])
    result = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "--quiet", SERVICE],
        capture_output=True, timeout=10, check=False)
    if result.returncode:
        raise RuntimeError("broker did not become active")


def rollback() -> None:
    st = BACKUP.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise PermissionError("untrusted root-only backup directory")
    old = protected(BACKUP / "previous-broker")
    if checksum(old) != OLD_SHA:
        raise PermissionError("original broker backup failed verification")
    replace_broker(old)
    restart()


def apply(new: bytes) -> None:
    if os.geteuid() != 0:
        raise PermissionError("root required from original ubuntu console")
    os.umask(0o077)
    old = protected(BROKER)
    BACKUP.mkdir(mode=0o700)
    os.chown(BACKUP, 0, 0)
    os.chmod(BACKUP, 0o700)
    path = BACKUP / "previous-broker"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        os.fchown(f.fileno(), 0, 0)
        os.fchmod(f.fileno(), 0o600)
        f.write(old)
        f.flush()
        os.fsync(f.fileno())
    try:
        replace_broker(new)
        restart()
    except BaseException:
        try:
            rollback()
        except BaseException:
            print("URGENT: broker rollback requires original local root console",
                  file=sys.stderr)
        raise


def main() -> int:
    cli = argparse.ArgumentParser()
    modes = cli.add_mutually_exclusive_group(required=True)
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--apply", action="store_true")
    modes.add_argument("--rollback", action="store_true")
    cli.add_argument("--source", type=Path)
    args = cli.parse_args()
    try:
        if os.geteuid() != 0:
            raise PermissionError("original administrator sudo required")
        if args.rollback:
            if args.source:
                raise ValueError("rollback does not accept --source")
            rollback()
            print("BROKER_CONSOLE_APPROVAL_ROLLBACK_OK")
            return 0
        if not args.source:
            raise ValueError("--source required")
        code = check(args.source)
        print("BROKER_CONSOLE_APPROVAL_CHECK_OK")
        if args.check:
            return 0
        apply(code)
        print("BROKER_CONSOLE_APPROVAL_DEPLOYED: no request approved")
        return 0
    except (OSError, ValueError, PermissionError, RuntimeError,
            subprocess.SubprocessError) as e:
        print("BROKER_CONSOLE_APPROVAL_FAILED:", type(e).__name__, str(e)[:250],
              file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
