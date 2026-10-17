#!/usr/bin/python3 -I
"""Gateway human-admin transaction: exact one-device target sudo API rollout.

Immutable source blobs are hash-pinned. No network, Git, arbitrary command,
secret logging or private key export. --check is read-only. --apply requires
human local sudo and performs backup; --rollback restores tracked files.
Not a ChatGPT / MCP tool.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

TARGET = "ai-lab-experiments-01-fd3dab34"
SOURCES = {
    "scripts/privilege_broker_daemon.py": (
        "/usr/local/libexec/ai-lab-privilege-brokerd",
        "f75d339600c30a063cb5f556434523e658de048f708429dc1f1dc3ad441b8199"),
    "scripts/approval_web.py": (
        "/usr/local/libexec/ai-lab-approval-web",
        "b6c5b095c88ce8ad839ed5f60f0be784c03c25335e7d4995abf53c395997cde3"),
    "src/ai_lab_gateway/server.py": (
        "/opt/ai-lab-gateway/src/ai_lab_gateway/server.py",
        "6d6b43a24b1abadfd205e7238378aad4a0ee37b99ba680b114746b1459b016c8"),
    "src/ai_lab_gateway/control.py": (
        "/opt/ai-lab-gateway/src/ai_lab_gateway/control.py",
        "bf4f4bef3e79391ac67ce45b4c5f66f90ddb88987afadfecdbc81f85981b2d32"),
    "src/ai_lab_gateway/ssh_exec.py": (
        "/opt/ai-lab-gateway/src/ai_lab_gateway/ssh_exec.py",
        "7bb932b8a04d66c48e265b1203dae617e728f14e48df03c4d491bb220e6cab9f"),
}
POLICY = Path("/etc/ai-lab-gateway/authorization.json")
ISSUER = Path("/etc/ai-lab-target-issuer")
OVERRIDE = Path("/etc/systemd/system/ai-lab-gateway.service.d/40-target-privilege.conf")
OVERRIDE_BYTES = b"[Service]\nEnvironment=AI_LAB_TARGET_PRIVILEGE_MCP_ENABLED=1\n"
BACKUP = Path("/var/backups/ai-lab-target-privilege-rollout-v1")
SYSTEMD = "/usr/bin/systemctl"
SERVICES = ("ai-lab-privilege-broker", "ai-lab-approval-web", "ai-lab-gateway")


def regular_root(path: Path) -> os.stat_result:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise PermissionError("untrusted root-managed file: " + str(path))
    return st


def validate_source(source: Path, expected: str) -> bytes:
    st = source.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_size > 150_000:
        raise PermissionError("invalid source file")
    blob = source.read_bytes()
    if hashlib.sha256(blob).hexdigest() != expected:
        raise PermissionError("artifact hash mismatch for " + source.name)
    return blob


def unique_authorized_user() -> tuple[dict, str]:
    regular_root(POLICY)
    doc = json.loads(POLICY.read_text(encoding="utf-8"))
    if type(doc) is not dict or type(doc.get("users")) is not list:
        raise ValueError("invalid authorization policy structure")
    subjects = set()
    candidates = []
    for user in doc["users"]:
        if type(user) is not dict or not isinstance(user.get("subject"), str):
            raise ValueError("invalid policy identity")
        subject = user["subject"]
        if subject in subjects:
            raise ValueError("duplicate subject")
        subjects.add(subject)
        devices = user.get("devices")
        if type(devices) is not dict:
            raise ValueError("missing device policy")
        existing = devices.get(TARGET)
        if isinstance(existing, list) and "exec" in existing:
            candidates.append(user)
    if len(candidates) != 1:
        raise PermissionError("requires exactly ONE already-authorized second-VM exec user")
    candidate = candidates[0]
    actions = candidate["devices"][TARGET]
    if not all(isinstance(x, str) for x in actions):
        raise ValueError("invalid access action list")
    if "target_privilege_execute" not in actions:
        actions.append("target_privilege_execute")
    return doc, hashlib.sha256(candidate["subject"].encode()).hexdigest()[:12]


def prepare(source_dir: Path) -> tuple[dict[Path, bytes], bytes, str]:
    # This is not a remote installer. Root trust and SSH registry already
    # provisioned and approved in separate original Ubuntu console steps.
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise PermissionError("source directory missing or symlinked")
    if not ISSUER.is_dir() or ISSUER.is_symlink():
        raise PermissionError("root-only issuer has not been provisioned")
    issuer_st = ISSUER.lstat()
    if issuer_st.st_uid != 0 or stat.S_IMODE(issuer_st.st_mode) != 0o700:
        raise PermissionError("untrusted issuer directory")
    regular_root(ISSUER / "issuer_ed25519")
    regular_root(ISSUER / "targets.json")
    issuer_targets = json.loads((ISSUER / "targets.json").read_text())
    if (type(issuer_targets) is not dict
            or issuer_targets != {"version": 1, "devices": [TARGET]}):
        raise PermissionError("issuer allowlist is not exact one-device scope")
    if BACKUP.exists() or BACKUP.is_symlink():
        raise FileExistsError("prior rollout snapshot exists: review/rollback first")
    if OVERRIDE.exists() or OVERRIDE.is_symlink():
        raise FileExistsError("target privilege flag already installed")
    blobs = {}
    for rel, (dst_string, digest) in SOURCES.items():
        dst = Path(dst_string)
        regular_root(dst)
        blobs[dst] = validate_source(source_dir / rel, digest)
    doc, subject_digest = unique_authorized_user()
    policy_blob = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    return blobs, policy_blob, subject_digest


def atomic_write(dst: Path, data: bytes, *, mode: int, uid: int, gid: int) -> None:
    fd, tmp = tempfile.mkstemp(prefix=".ai-lab-priv-", dir=dst.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, dst)
        parent_fd = os.open(dst.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def services(*args: str) -> None:
    p = subprocess.run([SYSTEMD, *args], check=False, timeout=35,
                       capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    if p.returncode:
        raise RuntimeError("systemd operation failed: " + " ".join(args)
                           + "; " + p.stderr[:300])


def restore() -> None:
    if not BACKUP.is_dir() or BACKUP.is_symlink():
        raise PermissionError("missing trusted rollback backup")
    st = BACKUP.lstat()
    if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise PermissionError("rollback backup owner/mode untrusted")
    destinations = [Path(x[0]) for x in SOURCES.values()] + [POLICY]
    for i, dst in enumerate(destinations):
        saved = BACKUP / ("file-" + str(i))
        ss = regular_root(saved)
        metadata = json.loads((BACKUP / ("meta-" + str(i))).read_text())
        if not isinstance(metadata, dict) or set(metadata) != {"uid", "gid", "mode"}:
            raise PermissionError("invalid saved file metadata")
        atomic_write(dst, saved.read_bytes(), mode=metadata["mode"],
                     uid=metadata["uid"], gid=metadata["gid"])
    if OVERRIDE.exists():
        regular_root(OVERRIDE)
        if OVERRIDE.read_bytes() != OVERRIDE_BYTES:
            raise PermissionError("target flag was modified: manual review required")
        OVERRIDE.unlink()
    services("daemon-reload")
    for name in SERVICES:
        services("restart", name)
    for name in SERVICES:
        services("is-active", "--quiet", name)


def apply(blobs: dict[Path, bytes], policy: bytes) -> None:
    os.umask(0o077)
    BACKUP.mkdir(mode=0o700)
    os.chown(BACKUP, 0, 0)
    os.chmod(BACKUP, 0o700)
    destinations = list(blobs) + [POLICY]
    try:
        for i, dst in enumerate(destinations):
            st = regular_root(dst)
            old = dst.read_bytes()
            atomic_write(BACKUP / ("file-" + str(i)), old,
                         mode=0o600, uid=0, gid=0)
            meta = {"uid": st.st_uid, "gid": st.st_gid,
                    "mode": stat.S_IMODE(st.st_mode)}
            atomic_write(BACKUP / ("meta-" + str(i)),
                         json.dumps(meta).encode(), mode=0o600, uid=0, gid=0)
        for dst, blob in blobs.items():
            st = regular_root(dst)
            atomic_write(dst, blob, mode=stat.S_IMODE(st.st_mode),
                         uid=st.st_uid, gid=st.st_gid)
        st = regular_root(POLICY)
        atomic_write(POLICY, policy, mode=stat.S_IMODE(st.st_mode),
                     uid=st.st_uid, gid=st.st_gid)
        atomic_write(OVERRIDE, OVERRIDE_BYTES, mode=0o644, uid=0, gid=0)
        services("daemon-reload")
        for name in SERVICES:
            services("restart", name)
        for name in SERVICES:
            services("is-active", "--quiet", name)
    except BaseException:
        try:
            restore()
        except BaseException:
            print("ROLLBACK REQUIRES ORIGINAL ADMINISTRATOR REVIEW", file=sys.stderr)
        raise


def main() -> int:
    cli = argparse.ArgumentParser()
    options = cli.add_mutually_exclusive_group(required=True)
    options.add_argument("--check", action="store_true")
    options.add_argument("--apply", action="store_true")
    options.add_argument("--rollback", action="store_true")
    cli.add_argument("--source-dir", type=Path)
    args = cli.parse_args()
    try:
        if os.geteuid() != 0:
            raise PermissionError("human operator's local root sudo required")
        if args.rollback:
            restore()
            print("ROLLBACK_OK: five files and policy restored; feature disabled")
            return 0
        if args.source_dir is None:
            raise ValueError("--source-dir required")
        blobs, policy, subject_hash = prepare(args.source_dir)
        print("PRECHECK_OK: five pinned binaries, restricted issuer, one user",
              "subject_hash=" + subject_hash, "no secrets shown")
        if args.check:
            return 0
        apply(blobs, policy)
        print("GATEWAY_TARGET_PRIVILEGE_DEPLOYED: protected policy and five files updated")
        return 0
    except (PermissionError, ValueError, OSError, RuntimeError,
            subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print("GATEWAY_TARGET_DEPLOY_ABORTED:", type(exc).__name__, str(exc)[:280],
              file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
