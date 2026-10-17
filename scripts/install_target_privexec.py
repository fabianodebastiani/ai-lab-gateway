#!/usr/bin/python3 -I
"""Local human-admin-only initial installation of the narrow target executor.

No remote privileged action, no enrollment, no network, and no auto-approval.
Run on the TARGET Linux with the original administrator's own sudo.
An independently verified public issuer key is REQUIRED.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys

EXECUTOR_SHA256 = "d94660a4e1a925d50fd3bd2fda02408cf5300458ad0ddd85498ba4203bdea632"
EXECUTOR_PATH = Path("/usr/local/libexec/ai-lab-target-privexec")
CONFIG = Path("/etc/ai-lab-target-privexec")
STATE = Path("/var/lib/ai-lab-target-privexec")
SUDOERS = Path("/etc/sudoers.d/90-ai-lab-target-privexec")
LOCAL_ID = Path("/home/ai-gateway/.ssh/ai-lab-device-code/device-id")
SIGNER = "ai-lab-privilege-approver-v1"
DEVICE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")


def regular_nonlink(path: Path) -> None:
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode):
        raise PermissionError("refusing non-regular or symlink file")


def parent_secure(path: Path) -> None:
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
            or st.st_mode & 0o022):
        raise PermissionError("destination parent not protected by root")


def public_key_data(path: Path, expected_fp: str) -> bytes:
    regular_nonlink(path)
    raw = path.read_bytes()
    if len(raw) > 2048 or b"\r" in raw:
        raise PermissionError("untrusted approver public key format")
    parts = raw.decode("ascii").strip().split()
    if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519":
        raise PermissionError("approver must use Ed25519")
    key = base64.b64decode(parts[1], validate=True)
    if len(key) != 51 or key[:4] != b"\x00\x00\x00\x0b":
        raise PermissionError("invalid Ed25519 public key encoding")
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode().rstrip("=")
    if not isinstance(expected_fp, str) or fp != expected_fp:
        raise PermissionError("approver public key fingerprint mismatch")
    return (SIGNER + " ssh-ed25519 " + parts[1] + "\n").encode("ascii")


def validate(device_id: str, issuer: Path, fingerprint: str, source: Path) -> tuple[bytes, bytes]:
    if not isinstance(device_id, str) or not DEVICE.fullmatch(device_id):
        raise ValueError("invalid device id")
    regular_nonlink(LOCAL_ID)
    device = LOCAL_ID.read_text(encoding="ascii").strip()
    if device != device_id:
        raise PermissionError("local paired device ID differs from human-approved ID")
    pw = pwd.getpwnam("ai-gateway")
    if pw.pw_uid in (0,) or pw.pw_dir != "/home/ai-gateway":
        raise PermissionError("management identity must be ordinary ai-gateway")
    public = public_key_data(issuer, fingerprint)
    regular_nonlink(source)
    blob = source.read_bytes()
    if len(blob) > 120_000 or hashlib.sha256(blob).hexdigest() != EXECUTOR_SHA256:
        raise PermissionError("root executor release SHA256 mismatch")
    if not blob.startswith(b"#!/usr/bin/python3 -I\n"):
        raise PermissionError("wrong executable interpreter")
    return public, blob


def mkdir_root(path: Path, created: list[Path]) -> None:
    if path.exists() or path.is_symlink():
        st = path.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                or stat.S_IMODE(st.st_mode) != 0o700):
            raise PermissionError("existing root state directory is untrusted")
        return
    parent_secure(path.parent)
    path.mkdir(mode=0o700)
    os.chown(path, 0, 0)
    os.chmod(path, 0o700)
    created.append(path)


def write_exclusive(path: Path, data: bytes, mode: int, created: list[Path]) -> None:
    parent_secure(path.parent)
    if path.exists() or path.is_symlink():
        raise FileExistsError("will not overwrite existing installation")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    created.append(path)
    with os.fdopen(fd, "wb") as f:
        os.fchown(f.fileno(), 0, 0)
        os.fchmod(f.fileno(), mode)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def sudoers_text() -> bytes:
    return (b"# AI Lab target one-use executor only; no arguments permitted.\n"
            b"ai-gateway ALL=(root) NOPASSWD: "
            b"/usr/local/libexec/ai-lab-target-privexec \"\"\n")


def apply(device_id: str, issuer: Path, fingerprint: str, source: Path,
          *, check_only: bool) -> str:
    public, blob = validate(device_id, issuer, fingerprint, source)
    if check_only:
        return "DRY_RUN_OK (no files or privileges changed)"
    if os.geteuid() != 0:
        raise PermissionError("apply requires original local administrator sudo")
    parent_secure(EXECUTOR_PATH.parent)
    parent_secure(SUDOERS.parent)
    created_files: list[Path] = []
    created_dirs: list[Path] = []
    try:
        mkdir_root(CONFIG, created_dirs)
        mkdir_root(STATE, created_dirs)
        mkdir_root(STATE / "used", created_dirs)
        mkdir_root(STATE / "revoked", created_dirs)
        write_exclusive(CONFIG / "device-id", (device_id + "\n").encode("ascii"),
                        0o600, created_files)
        write_exclusive(CONFIG / "allowed_signers", public, 0o600, created_files)
        write_exclusive(STATE / "lock", b"", 0o600, created_files)
        write_exclusive(EXECUTOR_PATH, blob, 0o755, created_files)
        # Preflight the complete isolated rule BEFORE installing sudoers.
        candidate = SUDOERS.parent / ".ai-lab-target-privexec.preflight"
        write_exclusive(candidate, sudoers_text(), 0o440, created_files)
        checked = subprocess.run(["/usr/sbin/visudo", "-cf", str(candidate)],
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 timeout=8, check=False)
        if checked.returncode:
            raise PermissionError("visudo rejected narrowly scoped policy")
        if SUDOERS.exists() or SUDOERS.is_symlink():
            raise FileExistsError("sudoers rule already exists")
        os.replace(candidate, SUDOERS)
        created_files.remove(candidate)
        created_files.append(SUDOERS)
        return "INSTALLED: limited root executor only; no voucher approved"
    except BaseException:
        for path in reversed(created_files):
            if path.exists() and not path.is_symlink():
                path.unlink()
        for path in reversed(created_dirs):
            try:
                path.rmdir()
            except OSError:
                pass
        raise


def revoke() -> str:
    if os.geteuid() != 0:
        raise PermissionError("revoke requires local administrator sudo")
    regular_nonlink(SUDOERS)
    if SUDOERS.read_bytes() != sudoers_text():
        raise PermissionError("refusing to remove modified sudoers")
    SUDOERS.unlink()
    return "REVOKED: executor can no longer be called via sudo by ai-gateway"


def main() -> int:
    p = argparse.ArgumentParser()
    action = p.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--apply", action="store_true")
    action.add_argument("--revoke", action="store_true")
    p.add_argument("--device-id")
    p.add_argument("--issuer-public-key", type=Path)
    p.add_argument("--issuer-fingerprint")
    p.add_argument("--executor-source", type=Path)
    args = p.parse_args()
    try:
        if args.revoke:
            if any((args.device_id, args.issuer_public_key, args.issuer_fingerprint,
                    args.executor_source)):
                raise ValueError("revoke does not accept install parameters")
            output = revoke()
        else:
            if not all((args.device_id, args.issuer_public_key,
                        args.issuer_fingerprint, args.executor_source)):
                raise ValueError("all installation parameters are required")
            output = apply(args.device_id, args.issuer_public_key,
                           args.issuer_fingerprint, args.executor_source,
                           check_only=args.check)
        print(output)
        return 0
    except (OSError, ValueError, PermissionError, subprocess.SubprocessError) as e:
        print("TARGET_PRIVEXEC_NOT_INSTALLED: " + type(e).__name__, file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
