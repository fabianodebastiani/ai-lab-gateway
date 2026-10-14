#!/usr/bin/env python3
"""Oracle pairing-v2 pilot: SHA-pinned, backup-first, fail-closed root deployment.

This installer is NOT run by MCP. An Oracle console administrator copies the
staged bundle into a private root-owned directory, independently verifies
THIS script's SHA256 against the value supplied through the trusted operator
channel, runs --check, and only then explicitly runs --apply.

No generic sudo grant is created. Existing SSH keys, tunnels and device
registry entries are preserved. Any failed health check triggers rollback.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

STAGE = Path("/root/ai-lab-v2-rollout")
BACKUPS = Path("/var/backups/ai-lab-gateway")
PACKAGE = Path("/opt/ai-lab-gateway/src/ai_lab_gateway")
SYSTEMD = Path("/etc/systemd/system")
POLICY = Path("/etc/ai-lab-gateway/authorization.json")
CADDY = Path("/etc/caddy/Caddyfile")
DROPOUT = SYSTEMD / "ai-lab-gateway.service.d/20-pairing-v2.conf"
EXPECTED = {
    "access_profiles.py": "e9cbeddd37502d4069bba5c782a9b68fd876088d1b8a7e7b4f23c93e65c65b81",
    "approval_web.py": "bac1df979600fa864f28537bd4020cfb55c84d2e8a782e2239c906e2853eb11e",
    "connection_control.py": "f041254bdda9ed1a872924068f2df9b4a5cceb520e1b5d971a8b2448beeb7c98",
    "control.py": "f1f19658b345d7f068a61f8908e6921f56d9751eb34c7c5c15a08aec58914b94",
    "enrollment.py": "9df502b24d8e3129690517a41ec9e70cf956d0885ba10daca496a5678c541e8e",
    "enrollment_http.py": "2eee2397be4d0b3803d13ae46ef6134a3d391a6fb6ea590df634d35421f15805",
    "pairing_client.py": "a1e95f657dab0ed9adfcebe63d303a74ddf460c7751304a0399e2693afe2a3d6",
    "pairing_service.py": "20a5485aea6a8fffbfbcf064d23de6afd2d2399466a8d19740e8fe00128f86e9",
    "registry.py": "2a10698065fbb5338462707f51c68e418e781aaf00f7acd48b786bada4a8f764",
    "scope_stepup.py": "98159c8d92af8203bd5e7a415296bb50e181cd969fbe7ee115d12f9377d6f446",
    "server.py": "62c8d3b4898fe4e5e079a67fd83133635d3a5031ad9f39dda1238bfed40ff12d",
    "ai-lab-pairing.service": "2254309c35a7afaf9774d433fd47c43ed9d11b2612b12990c60d2c940315eab0",
    "ai-lab-pairing-mcp.socket": "72e799a842dd0e7ff1fd68f3c8e34a6e0e063613e13cccdd2d827f820a009682",
    "ai-lab-pairing-approver.socket": "4f63fe9f4bd92405268b834e0e3d62e96eed3cfc9484f7c232361d1d20052dcf",
}
DEST = {
    **{name: PACKAGE / name for name in (
        "access_profiles.py", "connection_control.py", "control.py",
        "enrollment.py", "enrollment_http.py", "pairing_client.py",
        "registry.py", "scope_stepup.py", "server.py"
    )},
    "approval_web.py": Path("/usr/local/libexec/ai-lab-approval-web"),
    "pairing_service.py": Path("/usr/local/libexec/ai-lab-pairing-service"),
    **{name: SYSTEMD / name for name in (
        "ai-lab-pairing.service", "ai-lab-pairing-mcp.socket",
        "ai-lab-pairing-approver.socket"
    )},
}
SERVICES = ("ai-lab-gateway", "ai-lab-approval-web", "ai-lab-privilege-broker", "caddy")


def run(*argv, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=45)


def verify_stage():
    if os.geteuid() != 0:
        raise PermissionError("root is required")
    st = STAGE.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        raise PermissionError("staged bundle must be root-owned with mode 0700")
    for name, digest in EXPECTED.items():
        candidate = STAGE / name
        st = candidate.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise PermissionError("unsafe staged file: " + name)
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            raise ValueError("SHA256 mismatch in staged bundle: " + name)
    # Ensure source/target map is complete and no unreviewed write paths exist.
    if set(DEST) != set(EXPECTED):
        raise RuntimeError("installer target list does not match pinned manifest")
    if not PACKAGE.is_dir() or not POLICY.is_file() or not CADDY.is_file():
        raise RuntimeError("reference gateway installation not found")
    if "gateway.debasti.com {" not in CADDY.read_text():
        raise RuntimeError("unexpected Caddy host configuration")
    current = run("/usr/bin/systemctl", "is-active", *SERVICES)
    if any(x != "active" for x in current.stdout.splitlines()):
        raise RuntimeError("reference services are not healthy")


def atomic_write(path: Path, data: bytes, mode: int):
    if path.is_symlink():
        raise PermissionError("refusing to replace symlink: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".ai-lab-v2-", dir=path.parent)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        if os.path.lexists(temp):
            os.unlink(temp)


def policy_with_enrollment_grant(current: bytes) -> bytes:
    raw = json.loads(current)
    matches = []
    for principal in raw.get("users", []):
        actions = principal.get("devices", {}).get("oracle-gateway", [])
        if isinstance(actions, list) and "privilege_request" in actions:
            matches.append(actions)
    if len(matches) != 1:
        raise RuntimeError("expected exactly one existing Oracle privileged operator")
    if "device_enroll" not in matches[0]:
        matches[0].append("device_enroll")
    return (json.dumps(raw, indent=2, ensure_ascii=False) + "\n").encode()


def caddy_with_pairing(current: bytes) -> bytes:
    content = current.decode("utf-8")
    if "handle /pairing/*" in content:
        raise RuntimeError("pairing Caddy route already exists; do not overwrite")
    head = "gateway.debasti.com {\n"
    route = ("    handle /pairing/* {\n"
             "        reverse_proxy 127.0.0.1:8002\n"
             "    }\n\n")
    if content.count(head) != 1:
        raise RuntimeError("unexpected Caddyfile shape")
    return content.replace(head, head + route, 1).encode()


def ensure_pairing_user():
    try:
        user = pwd.getpwnam("ai-lab-pairing")
    except KeyError:
        run("/usr/sbin/useradd", "--system", "--user-group",
            "--no-create-home", "--shell", "/usr/sbin/nologin",
            "ai-lab-pairing")
        user = pwd.getpwnam("ai-lab-pairing")
    # No membership in private key or TOTP groups.
    groups = os.getgrouplist("ai-lab-pairing", user.pw_gid)
    import grp
    prohibited = {grp.getgrnam("ai-lab-gateway").gr_gid,
                  grp.getgrnam("ai-lab-approver").gr_gid}
    if prohibited.intersection(groups):
        raise PermissionError("pairing daemon has unexpectedly powerful group membership")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true")
    options = parser.parse_args()
    if options.check == options.apply:
        parser.error("select exactly one of --check or --apply")
    verify_stage()
    if options.check:
        print("BUNDLE_SHA256_VERIFIED; services active; no changes")
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = BACKUPS / ("pairing-v2-" + stamp)
    backup.mkdir(parents=True, mode=0o700, exist_ok=False)
    os.chmod(backup, 0o700)
    originals = {}
    target_map = {**{str(x): x for x in DEST.values()},
                  str(POLICY): POLICY, str(CADDY): CADDY,
                  str(DROPOUT): DROPOUT}
    mode_backup = {}
    for path in (Path("/opt/ai-lab-gateway"), Path("/opt/ai-lab-gateway/src"), PACKAGE):
        mode_backup[str(path)] = stat.S_IMODE(path.stat().st_mode)
    for key, path in target_map.items():
        if path.is_symlink():
            raise PermissionError("existing file is a symlink: " + key)
        original = backup / ("file-" + hashlib.sha256(key.encode()).hexdigest())
        if path.exists():
            shutil.copy2(path, original)
            originals[key] = str(original)
        else:
            originals[key] = None
    (backup / "manifest.json").write_text(
        json.dumps({"files": originals, "dirs": mode_backup}, indent=2)
    )
    os.chmod(backup / "manifest.json", 0o600)
    print("BACKUP=" + str(backup), flush=True)

    touched = False
    try:
        ensure_pairing_user()
        for name, target in DEST.items():
            mode = 0o755 if name.endswith("service.py") or name == "approval_web.py" else 0o644
            if name == "pairing_service.py":
                mode = 0o755
            atomic_write(target, (STAGE / name).read_bytes(), mode)
        # Block modifying production importable code from the runtime account.
        for p in mode_backup:
            os.chmod(p, stat.S_IMODE(os.stat(p).st_mode) & ~0o022)

        atomic_write(POLICY, policy_with_enrollment_grant(POLICY.read_bytes()), 0o640)
        atomic_write(DROPOUT,
                     b"[Service]\nEnvironment=PYTHONPATH=/opt/ai-lab-gateway/src\n",
                     0o644)
        atomic_write(CADDY, caddy_with_pairing(CADDY.read_bytes()), 0o644)
        touched = True
        run("/usr/bin/caddy", "validate", "--config", str(CADDY))
        run("/usr/bin/systemctl", "daemon-reload")
        run("/usr/bin/systemctl", "enable", "--now",
            "ai-lab-pairing-mcp.socket", "ai-lab-pairing-approver.socket")
        run("/usr/bin/systemctl", "enable", "--now", "ai-lab-pairing.service")
        run("/usr/bin/systemctl", "restart", "ai-lab-approval-web")
        run("/usr/bin/systemctl", "restart", "ai-lab-gateway")
        run("/usr/bin/systemctl", "reload", "caddy")
        health = run("/usr/bin/curl", "-fsS", "--max-time", "5",
                     "http://127.0.0.1:8002/pairing/health")
        if json.loads(health.stdout).get("status") != "ok":
            raise RuntimeError("pairing HTTP service is unhealthy")
        run("/usr/bin/curl", "-fsS", "--max-time", "8",
            "https://gateway.debasti.com/pairing/health")
        run("/usr/bin/curl", "-fsS", "--max-time", "8",
            "https://gateway.debasti.com/approvals/health")
        services = run("/usr/bin/systemctl", "is-active",
                       *SERVICES, "ai-lab-pairing.service")
        if any(x != "active" for x in services.stdout.splitlines()):
            raise RuntimeError("one or more gateway services are inactive")
        print("PAIRING_PILOT_DEPLOYED; existing SSH keys untouched")
        return 0
    except Exception as exc:
        print("DEPLOYMENT_FAILED; initiating rollback: " + str(exc),
              file=sys.stderr, flush=True)
        try:
            run("/usr/bin/systemctl", "disable", "--now",
                "ai-lab-pairing.service", check=False)
            run("/usr/bin/systemctl", "disable", "--now",
                "ai-lab-pairing-mcp.socket", "ai-lab-pairing-approver.socket",
                check=False)
            for key, original in originals.items():
                path = Path(key)
                if original:
                    backup_file = Path(original)
                    content = backup_file.read_bytes()
                    target_mode = stat.S_IMODE(backup_file.stat().st_mode)
                    atomic_write(path, content, target_mode)
                    os.chown(path, backup_file.stat().st_uid,
                             backup_file.stat().st_gid)
                else:
                    path.unlink(missing_ok=True)
            for key, mode in mode_backup.items():
                os.chmod(key, mode)
            run("/usr/bin/systemctl", "daemon-reload", check=False)
            run("/usr/bin/systemctl", "restart", "ai-lab-gateway", check=False)
            run("/usr/bin/systemctl", "restart", "ai-lab-approval-web", check=False)
            run("/usr/bin/systemctl", "reload", "caddy", check=False)
            print("ROLLBACK_ATTEMPTED; inspect systemd services and backup " + str(backup),
                  file=sys.stderr)
        except Exception as restore_error:
            print("ROLLBACK_ERROR: " + str(restore_error) +
                  " ; emergency backup " + str(backup), file=sys.stderr)
        raise
if __name__ == "__main__":
    raise SystemExit(main())
