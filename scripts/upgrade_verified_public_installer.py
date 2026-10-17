#!/usr/bin/python3 -I
"""Human-root-only upgrade of the fixed public /install.sh after sudo rollout.

Only replaces the static root-owned script, not Caddy routes or Auth0 services.
Requires issuer v2 opt-in and approved Gateway bridge before publication.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import urllib.request
from urllib.parse import urlsplit

PUBLIC = Path("/usr/local/share/ai-lab-gateway-public/install.sh")
BACKUP = Path("/var/backups/ai-lab-one-line-sudo-v2")
PUBLIC_URL = "https://gateway.debasti.com/install.sh"
COMMIT = "468081b396ae61e5e5ad22aae50d29ff4b6128f6"
URL = ("https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/" +
       COMMIT + "/scripts/install_ai_lab_device.sh")
OLD = "367fb8d46b0efcac3c319c92174af29e96e943ae18cdbeb7a8e62576c0857127"
NEW = "c65e46e483758ded11fe5c35dfbbccc128c339aef0c23fd5dca765207a5f9218"
BROKER = Path("/usr/local/libexec/ai-lab-privilege-brokerd")
BROKER_SHA = "dfaa854cf26f9a642ce8fe068d1c4f0f470ace062d08412bf223412a9f50441d"
PLAN = Path("/opt/ai-lab-gateway/src/ai_lab_gateway/device_code_linux_plan.py")
PLAN_SHA = "000d9877ac906c32590d6a159b34c8a8c6875df15ec8babbe7317a3496a83c4e"
ISSUER_CONFIG = Path("/etc/ai-lab-target-issuer/targets.json")


def sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def trusted_file(path: Path, mode: int):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
            or stat.S_IMODE(st.st_mode) != mode or st.st_nlink != 1):
        raise PermissionError("untrusted file or permissions")
    return path.read_bytes()


def pinned_download() -> bytes:
    with urllib.request.urlopen(
        urllib.request.Request(URL, headers={"User-Agent": "ai-lab-verified-installer-v2"}),
        timeout=15) as r:
        uri = urlsplit(r.geturl())
        if uri.scheme != "https" or uri.netloc != "raw.githubusercontent.com":
            raise PermissionError("untrusted redirect")
        data = r.read(150001)
    if not 0 < len(data) <= 150000 or sha(data) != NEW or not data.startswith(b"#!/bin/sh\n"):
        raise PermissionError("candidate installer checksum/shebang mismatch")
    return data


def preflight() -> bytes:
    prior = trusted_file(PUBLIC, 0o644)
    if sha(prior) != OLD:
        raise PermissionError("installed v1 file differs from reviewed baseline")
    if BACKUP.exists() or BACKUP.is_symlink():
        raise PermissionError("previous upgrade backup exists")
    return pinned_download()


def ensure_gateway_ready():
    if os.geteuid() != 0:
        raise PermissionError("root preflight required for issuer policy")
    if sha(trusted_file(BROKER, 0o755)) != BROKER_SHA:
        raise PermissionError("Auth0 sudo bridge not installed")
    if sha(trusted_file(PLAN, 0o644)) != PLAN_SHA:
        raise PermissionError("Gateway enrollment root policy not installed")
    targets = json.loads(trusted_file(ISSUER_CONFIG, 0o600))
    if (type(targets) is not dict or targets.get("version") != 2
            or targets.get("allow_verified_restricted_onboarding") is not True):
        raise PermissionError("independent human root opt-in not completed")


def atomically_replace(destination: Path, payload: bytes):
    fd, temp = tempfile.mkstemp(prefix=".ai-lab-installer-v2-", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchown(out.fileno(), 0, 0)
            os.fchmod(out.fileno(), 0o644)
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, destination)
        dfd = os.open(destination.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.lexists(temp):
            os.unlink(temp)


def verify_online():
    with urllib.request.urlopen(
        urllib.request.Request(PUBLIC_URL, headers={"User-Agent": "ai-lab-public-verify-v2"}),
        timeout=10) as r:
        value = r.read(150001)
        if r.geturl() != PUBLIC_URL or r.status != 200:
            raise PermissionError("HTTPS installer public verification failed")
    if sha(value) != NEW:
        raise PermissionError("wrong public installer SHA-256 after upgrade")


def apply():
    if os.geteuid() != 0:
        raise PermissionError("only independent original Gateway administrator can publish")
    candidate = preflight()
    ensure_gateway_ready()
    base = BACKUP.parent.lstat()
    if (not stat.S_ISDIR(base.st_mode) or base.st_uid != 0
            or stat.S_IMODE(base.st_mode) != 0o755):
        raise PermissionError("untrusted backup parent")
    BACKUP.mkdir(mode=0o700)
    os.chown(BACKUP, 0, 0)
    os.chmod(BACKUP, 0o700)
    fd = os.open(BACKUP / "install-v1.sh", os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(PUBLIC.read_bytes())
        out.flush()
        os.fsync(out.fileno())
    try:
        atomically_replace(PUBLIC, candidate)
        verify_online()
    except BaseException:
        if sha(PUBLIC.read_bytes()) == NEW:
            atomically_replace(PUBLIC, (BACKUP / "install-v1.sh").read_bytes())
        raise
    print("AI_LAB_INSTALL_V2_PUBLISHED:", PUBLIC_URL)
    print("AI_LAB_INSTALL_V2_SHA256:", NEW)


def main():
    p = argparse.ArgumentParser()
    actions = p.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true")
    actions.add_argument("--apply", action="store_true")
    args = p.parse_args()
    try:
        if args.check:
            preflight()
            print("AI_LAB_INSTALL_V2_CHECK_OK: verified source; no changes")
        else:
            apply()
        return 0
    except (OSError, ValueError, PermissionError, RuntimeError) as exc:
        print("AI_LAB_INSTALL_V2_DENIED:", type(exc).__name__)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
