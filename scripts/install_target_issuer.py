#!/usr/bin/python3 -I
"""One-time root-only Gateway bootstrap for an isolated target permit signer.

No MCP approval, no TOTP bypass, no service restart and no remote sudo.
After this creates the key, the broker STILL requires separate human approval
over its dedicated approver Unix socket before signing any voucher.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

REGISTRY = Path("/etc/ai-lab-gateway/devices.json")
ISSUER_DIR = Path("/etc/ai-lab-target-issuer")
DEVICE_RE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")


def root_file(path: Path):
    st = path.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or (stat.S_IMODE(st.st_mode) & 0o022)):
        raise PermissionError("gateway registry must be root-owned/nonwritable")


def verify_registered_device(device: str) -> None:
    if not isinstance(device, str) or not DEVICE_RE.fullmatch(device):
        raise ValueError("invalid target ID")
    root_file(REGISTRY)
    data = json.loads(REGISTRY.read_text(encoding="utf8"))
    devices = data.get("devices")
    if not isinstance(devices, list):
        raise ValueError("bad registry")
    found = [d for d in devices if isinstance(d, dict)
             and d.get("id") == device and d.get("enabled") is True]
    if (len(found) != 1 or found[0].get("ssh_user") != "ai-gateway"
            or found[0].get("tunnel_host") != "127.0.0.1"
            or type(found[0].get("tunnel_port")) is not int
            or not 11000 <= found[0]["tunnel_port"] <= 11999):
        raise PermissionError("target not an active restricted SSH device in root registry")


def install(device: str, *, plan: bool) -> str:
    verify_registered_device(device)
    if plan:
        return "DRY_RUN_OK: eligible registered target; nothing changed"
    if os.geteuid() != 0:
        raise PermissionError("root-only local administrator bootstrap required")
    if ISSUER_DIR.exists() or ISSUER_DIR.is_symlink():
        raise FileExistsError("issuer already installed; cannot silently overwrite")
    parent = ISSUER_DIR.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_mode & 0o022):
        raise PermissionError("issuer parent unsafe")
    ISSUER_DIR.mkdir(mode=0o700)
    try:
        os.chown(ISSUER_DIR, 0, 0)
        os.chmod(ISSUER_DIR, 0o700)
        key = ISSUER_DIR / "issuer_ed25519"
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(key)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=15, check=True,
                       env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        os.chmod(key, 0o600)
        os.chmod(ISSUER_DIR / "issuer_ed25519.pub", 0o600)
        public_line = (ISSUER_DIR / "issuer_ed25519.pub").read_text().split()
        if len(public_line) < 2 or public_line[0] != "ssh-ed25519":
            raise RuntimeError("generated key invalid")
        path = ISSUER_DIR / "targets.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"version": 1, "devices": [device]}, stream)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        dfd = os.open(ISSUER_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        print("Public issuer key (not secret):", " ".join(public_line[:2]))
        return "ISSUER_PREPARED: root-owned, one enabled target; no human approval issued"
    except BaseException:
        for entry in ISSUER_DIR.iterdir():
            if not entry.is_file() or entry.is_symlink():
                raise RuntimeError("manual root review required to roll back issuer")
            entry.unlink()
        ISSUER_DIR.rmdir()
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--device-id", required=True)
    args = parser.parse_args()
    try:
        print(install(args.device_id, plan=args.check))
        return 0
    except (OSError, RuntimeError, PermissionError, ValueError,
            subprocess.SubprocessError) as e:
        print("TARGET_ISSUER_NOT_PREPARED: " + type(e).__name__, file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
