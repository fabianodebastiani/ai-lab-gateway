#!/usr/bin/python3 -I
"""One-time ORIGINAL GATEWAY ADMIN opt-in: request-only sudo onboarding.

Independent human sudo required. This does not authorize, approve, sign or
execute ANY privileged operation. No Auth0 logins or device keys are changed.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ISSUER_DIR = Path("/etc/ai-lab-target-issuer")
TARGETS = ISSUER_DIR / "targets.json"
REGISTRY = Path("/etc/ai-lab-gateway/devices.json")
POLICY = Path("/etc/ai-lab-gateway/authorization.json")
BACKUP = Path("/var/backups/ai-lab-auth0-sudo-onboarding-v1")
DEVICE = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
ACTION = "target_privilege_execute"


def protected(path: Path, *, limit: int = 160_000) -> tuple[bytes, os.stat_result]:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
            or metadata.st_mode & 0o022 or metadata.st_nlink != 1
            or metadata.st_size > limit):
        raise PermissionError("unexpected protected file ownership/mode")
    return path.read_bytes(), metadata


def protected_directory(path: Path, *, exact_mode: int) -> None:
    data = path.lstat()
    if (not stat.S_ISDIR(data.st_mode) or data.st_uid != 0
            or data.st_gid != 0 or stat.S_IMODE(data.st_mode) != exact_mode):
        raise PermissionError("unexpected protected directory")


def output(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf8")


def plan(backfill_device: str | None) -> tuple[dict, dict, bytes, bytes, bytes, bytes]:
    protected_directory(ISSUER_DIR, exact_mode=0o700)
    old_targets, _ = protected(TARGETS, limit=4096)
    old_registry, _ = protected(REGISTRY)
    old_policy, _ = protected(POLICY)
    targets = json.loads(old_targets)
    registry = json.loads(old_registry)
    policy = json.loads(old_policy)
    if (type(targets) is not dict or set(targets) != {"version", "devices"}
            or targets["version"] != 1
            or type(targets["devices"]) is not list
            or not all(type(d) is str and DEVICE.fullmatch(d)
                       for d in targets["devices"])
            or len(targets["devices"]) != len(set(targets["devices"]))
            or len(targets["devices"]) > 25):
        raise PermissionError("expected original v1 issuer allowlist (not overwriting v2)")
    if (type(registry) is not dict or set(registry) != {"devices"}
            or type(registry["devices"]) is not list
            or type(policy) is not dict or set(policy) != {"users"}
            or type(policy["users"]) is not list):
        raise PermissionError("unexpected protected Gateway registry/policy")

    updated = copy.deepcopy(policy)
    if backfill_device is not None:
        if not DEVICE.fullmatch(backfill_device):
            raise ValueError("invalid exact existing device ID")
        matches = [d for d in registry["devices"]
                   if isinstance(d, dict) and d.get("id") == backfill_device]
        if len(matches) != 1:
            raise PermissionError("device missing or duplicated in real registry")
        target = matches[0]
        if (target.get("enabled") is not True or
                target.get("ssh_user") != "ai-gateway" or
                target.get("tunnel_host") != "127.0.0.1" or
                type(target.get("tunnel_port")) is not int or
                not 11000 <= target["tunnel_port"] <= 11999 or
                target.get("identity_file") !=
                f"/etc/ai-lab-gateway/device-code-keys/{backfill_device}/identity"):
            raise PermissionError("backfill requires already-verified Restricted SSH")
        owners = [u for u in updated["users"] if isinstance(u, dict)
                  and isinstance(u.get("devices"), dict)
                  and backfill_device in u["devices"]]
        if (len(owners) != 1 or not isinstance(owners[0].get("subject"), str)
                or not owners[0]["subject"]):
            raise PermissionError("ambiguous Auth0 owner; no backfill")
        privileges = owners[0]["devices"][backfill_device]
        if (type(privileges) is not list or
                not {"status", "exec"}.issubset(privileges) or
                ACTION in privileges or not all(type(x) is str for x in privileges)):
            raise PermissionError("unexpected existing device grants")
        privileges.append(ACTION)
    v2 = {"version": 2, "devices": targets["devices"],
          "allow_verified_restricted_onboarding": True}
    return v2, updated, old_targets, old_policy, output(v2), output(updated)


def fsync_dir(folder: Path):
    fd = os.open(folder, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_install(dest: Path, payload: bytes):
    original, meta = protected(dest)
    fd, path = tempfile.mkstemp(prefix=".auth0-sudo-", dir=dest.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchown(out.fileno(), 0, meta.st_gid)
            os.fchmod(out.fileno(), stat.S_IMODE(meta.st_mode))
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
        os.replace(path, dest)
        fsync_dir(dest.parent)
    finally:
        if os.path.lexists(path):
            os.unlink(path)


def save_backup(dest: Path, raw: bytes):
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        os.fchmod(file.fileno(), 0o600)
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())


def apply(backfill_device: str | None):
    if os.geteuid() != 0:
        raise PermissionError("only independent original Oracle admin can opt in")
    _, _, old_targets, old_policy, new_targets, new_policy = plan(backfill_device)
    if BACKUP.exists() or BACKUP.is_symlink():
        raise PermissionError("prior backup exists; root review required")
    protected_directory(BACKUP.parent, exact_mode=0o755)
    BACKUP.mkdir(mode=0o700)
    os.chown(BACKUP, 0, 0)
    os.chmod(BACKUP, 0o700)
    save_backup(BACKUP / "issuer-v1.json", old_targets)
    save_backup(BACKUP / "authz-before.json", old_policy)
    fsync_dir(BACKUP)
    try:
        if old_policy != new_policy:
            atomic_install(POLICY, new_policy)
        atomic_install(TARGETS, new_targets)
    except BaseException:
        # The dynamic issuer config has NOT succeeded until targets.json v2.
        # Roll back only files that still have the expected staged content.
        for destination, before, after in ((TARGETS, old_targets, new_targets),
                                           (POLICY, old_policy, new_policy)):
            current, _ = protected(destination)
            if current == after and current != before:
                atomic_install(destination, before)
            elif current != before:
                raise RuntimeError("ROOT_MANUAL_RECOVERY_REQUIRED")
        raise
    print("AUTH0_SUDO_ONBOARDING_ENABLED: request eligibility only; NO approval issued")
    print("root-only-backup:", BACKUP)


def main() -> int:
    parser = argparse.ArgumentParser()
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--check", action="store_true")
    choice.add_argument("--apply", action="store_true")
    parser.add_argument("--backfill-device", help="one existing enrolled Restricted device")
    args = parser.parse_args()
    try:
        if args.check:
            plan(args.backfill_device)
            print("AUTH0_SUDO_ONBOARDING_CHECK_OK: no modifications")
            print("planned-backfill:", args.backfill_device or "none")
        else:
            apply(args.backfill_device)
        return 0
    except (OSError, ValueError, RuntimeError, PermissionError) as exc:
        print("AUTH0_SUDO_ONBOARDING_DENIED: " + type(exc).__name__)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
