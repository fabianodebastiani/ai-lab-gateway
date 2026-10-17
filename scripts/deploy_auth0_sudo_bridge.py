#!/usr/bin/python3 -I
"""Root-admin-only rollout of the AUTH0-owned root-request eligibility bridge.

Read-only --check; --apply uses original local sudo + version/digest checking.
Does NOT enable v2 issuer allowlist, approve root or change Auth0 login.
"""
from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import urllib.request
from urllib.parse import urlsplit

BASE = "https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway"
SOURCES = (
    ("scripts/privilege_broker_daemon.py",
     "b6a717083d3cbb3844fe2766d2b7134b5312a411",
     "dfaa854cf26f9a642ce8fe068d1c4f0f470ace062d08412bf223412a9f50441d",
     Path("/usr/local/libexec/ai-lab-privilege-brokerd"),
     "479034afb80594138cd3c6e4a1d5f7dfad1835e3a62888cc83353727ba64d902"),
    ("src/ai_lab_gateway/device_code_linux_plan.py",
     "532c83d54737f435d584f043763b7bb84e7689ae",
     "000d9877ac906c32590d6a159b34c8a8c6875df15ec8babbe7317a3496a83c4e",
     Path("/opt/ai-lab-gateway/src/ai_lab_gateway/device_code_linux_plan.py"),
     "91c8932fe8b47204e3b1cceea846f6e892bdc4cddcab98966119cb5863db066e"),
)
BACKUP = Path("/var/backups/ai-lab-auth0-sudo-code-v1")
SYSTEMCTL = "/usr/bin/systemctl"


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def root_file(path: Path):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
            or st.st_mode & 0o022 or st.st_nlink != 1):
        raise PermissionError("unexpected ownership/mode of production executable")
    return st


def get_pinned(path: str, commit: str, checksum: str) -> bytes:
    url = f"{BASE}/{commit}/{path}"
    with urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "ai-lab-safe-auth0-sudo-bridge"}),
        timeout=15) as r:
        final = urlsplit(r.geturl())
        if final.scheme != "https" or final.netloc != "raw.githubusercontent.com":
            raise PermissionError("bootstrap download redirected to untrusted server")
        blob = r.read(160001)
    if len(blob) > 160000 or sha(blob) != checksum:
        raise PermissionError("source SHA-256 mismatch")
    compile(blob, path, "exec")
    return blob


def preflight():
    if len(SOURCES) != 2:
        raise PermissionError("fixed deployment manifest expected")
    verified = []
    for path, commit, new_digest, destination, current_digest in SOURCES:
        original_st = root_file(destination)
        current = destination.read_bytes()
        if sha(current) != current_digest:
            raise PermissionError("live Gateway code differs from reviewed baseline")
        new = get_pinned(path, commit, new_digest)
        verified.append((destination, original_st, current, new))
    if BACKUP.exists() or BACKUP.is_symlink():
        raise PermissionError("prior rollout backup present: inspect manually")
    return verified


def sync_parent(parent):
    fd = os.open(parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path: Path, data: bytes, info):
    fd, temporary = tempfile.mkstemp(prefix=".ai-lab-auth0-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            os.fchown(file.fileno(), 0, 0)
            os.fchmod(file.fileno(), stat.S_IMODE(info.st_mode))
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        sync_parent(path.parent)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def apply():
    if os.geteuid() != 0:
        raise PermissionError("requires human original Oracle sudo; not MCP sudo")
    sources = preflight()
    parent = BACKUP.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
            stat.S_IMODE(parent.st_mode) != 0o755):
        raise PermissionError("untrusted backup parent")
    BACKUP.mkdir(mode=0o700)
    os.chown(BACKUP, 0, 0)
    os.chmod(BACKUP, 0o700)
    for i, (path, info, old, new) in enumerate(sources):
        fd = os.open(BACKUP / f"source-{i}.before", os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(old)
            output.flush()
            os.fsync(output.fileno())
    sync_parent(BACKUP)
    updated = []
    try:
        # Update pure enrollment plan first; v1 signer continues to deny new
        # devices until independent root operator opts into v2.
        for i in (1, 0):
            dest, info, old, new = sources[i]
            atomic(dest, new, info)
            updated.append(i)
        result = subprocess.run([SYSTEMCTL, "restart", "ai-lab-privilege-broker"],
                                check=True, timeout=25, capture_output=True)
        if subprocess.run([SYSTEMCTL, "is-active", "--quiet", "ai-lab-privilege-broker"],
                          timeout=8, check=False).returncode:
            raise RuntimeError("broker not active after restart")
    except BaseException:
        for i in reversed(updated):
            dest, info, old, new = sources[i]
            if sha(dest.read_bytes()) != sha(new):
                raise RuntimeError("unexpected concurrent modification: manual restore")
            atomic(dest, old, info)
        try:
            subprocess.run([SYSTEMCTL, "restart", "ai-lab-privilege-broker"],
                           timeout=25, check=True)
        except Exception:
            raise RuntimeError("original code restored but service restart failed")
        raise
    print("AUTH0_SUDO_BRIDGE_DEPLOYED: no root request approved or issuer v2 enabled")
    print("backup:", BACKUP)


def main():
    parser = argparse.ArgumentParser()
    x = parser.add_mutually_exclusive_group(required=True)
    x.add_argument("--check", action="store_true")
    x.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        if args.check:
            preflight()
            print("AUTH0_SUDO_BRIDGE_CHECK_OK: SHA-256 verified, nothing modified")
        else:
            apply()
        return 0
    except (OSError, PermissionError, RuntimeError, ValueError,
            subprocess.SubprocessError) as exc:
        print("AUTH0_SUDO_BRIDGE_DENIED:", type(exc).__name__)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
