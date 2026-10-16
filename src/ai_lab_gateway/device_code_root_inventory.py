"""Root-only read-only discovery of *real* Oracle SSH/registry locations.

NOT a provisioner. This tool exposes ONLY paths, owner/group/mode and
device IDs/ports, NEVER key contents, token values, Environment secrets,
passwords, fingerprints or actual command output from sshd.

Purpose: operator verifies the actual running service configuration before
hardcoded root staging paths are reviewed. The audit does not authorize
deploying/applying any candidate SSH changes.

The SSH device executor uses standard per-user known_hosts (no explicit
UserKnownHostsFile), so the expected target host key source is the runtime
service user's home/.ssh/known_hosts. The registry path comes from the
actual running MCP process's allowlisted AI_LAB_DEVICE_REGISTRY environment
name, not from a speculative constant.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

MAX_PROC_ENV = 256 * 1024
MAX_REGISTRY = 256 * 1024
ALLOWED_REGISTRY_ROOTS = (
    Path("/etc/ai-lab-gateway"),
    Path("/var/lib/ai-lab-gateway"),
)
DEFAULT_REGISTRY = Path("/etc/ai-lab-gateway/devices.json")
SERVICE_NAME = "ai-lab-gateway.service"


def extract_registry_path(environ_raw: bytes) -> Path:
    """Parse only one non-secret path from service env; do not log env text."""
    if not isinstance(environ_raw, bytes) or len(environ_raw) > MAX_PROC_ENV:
        raise PermissionError("untrusted gateway environment size")
    values = []
    for entry in environ_raw.split(b"\x00"):
        if entry.startswith(b"AI_LAB_DEVICE_REGISTRY="):
            values.append(entry.split(b"=", 1)[1])
    if len(values) > 1:
        raise PermissionError("duplicate registry override")
    if not values:
        return DEFAULT_REGISTRY
    try:
        value = values[0].decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise PermissionError("invalid gateway registry override") from exc
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise PermissionError("registry override is not a safe absolute path")
    if path.parent not in ALLOWED_REGISTRY_ROOTS:
        raise PermissionError("registry override outside trusted config roots")
    return path


def parse_tunnel_authorized_keys_location(
        effective_sshd: str, *, tunnel_home: Path) -> tuple[Path, ...]:
    """Resolve only sshd's fixed authorizedkeysfile, without reading secrets."""
    if not isinstance(effective_sshd, str) or len(effective_sshd) > 128 * 1024:
        raise PermissionError("invalid effective sshd output")
    entries = [
        line.split(None, 1)[1].strip()
        for line in effective_sshd.splitlines()
        if line.lower().startswith("authorizedkeysfile ")
        and len(line.split(None, 1)) == 2
    ]
    if len(entries) != 1:
        raise PermissionError("could not uniquely determine SSH authorizedkeysfile")
    choices = entries[0].split()
    if not choices or len(choices) > 4 or choices == ["none"]:
        raise PermissionError("no supported tunnel SSH authorizedkeys file")
    paths = []
    for token in choices:
        if token == "none" or "%" in token or "\x00" in token or ".." in Path(token).parts:
            raise PermissionError("unsupported OpenSSH authorizedkeysfile expansion")
        candidate = Path(token)
        if not candidate.is_absolute():
            candidate = tunnel_home / candidate
        if not candidate.is_absolute():
            raise PermissionError("SSH tunnel home must be absolute")
        if candidate in paths:
            raise PermissionError("ambiguous repeated tunnel authorized_keys")
        paths.append(candidate)
    return tuple(paths)


def path_metadata(path: Path) -> dict:
    """lstat; do not follow symlinks, print sensitive bytes or mislabel EACCES."""
    path = Path(path)
    answer = {"path": str(path)}
    try:
        st = path.lstat()
    except FileNotFoundError:
        return {**answer, "status": "not_found_for_root"}
    except PermissionError:
        return {**answer, "status": "permission_denied"}
    answer.update({
        "status": "exists",
        "type": ("regular" if stat.S_ISREG(st.st_mode)
                 else "directory" if stat.S_ISDIR(st.st_mode)
                 else "symlink" if stat.S_ISLNK(st.st_mode)
                 else "other"),
        "uid": st.st_uid, "gid": st.st_gid,
        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
    })
    return answer


def _root_only():
    if os.geteuid() != 0:
        raise PermissionError("inventory requires an independently authorized root console")


def _run(argv: list[str]) -> str:
    out = subprocess.run(argv, capture_output=True, text=True,
                         check=True, timeout=10)
    if len(out.stdout) > 128 * 1024:
        raise PermissionError("oversized local inspection output")
    return out.stdout


def _service_registry() -> Path:
    text = _run(["/usr/bin/systemctl", "show", SERVICE_NAME,
                 "-p", "MainPID", "--value"]).strip()
    if not re.fullmatch(r"[0-9]{1,9}", text) or int(text) <= 1:
        raise PermissionError("gateway service not running")
    env = Path(f"/proc/{int(text)}/environ").read_bytes()
    return extract_registry_path(env)


def _registry_summary(path: Path) -> list[dict]:
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise PermissionError("registry path is not a regular local file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            raw = f.read(MAX_REGISTRY + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_REGISTRY:
        raise PermissionError("registry data exceeds audit limit")
    obj = json.loads(raw)
    devices = obj.get("devices", [])
    if not isinstance(devices, list) or len(devices) > 500:
        raise PermissionError("unexpected device registry shape")
    return [
        {"id": d["id"], "port": d["tunnel_port"],
         "ssh_user": d["ssh_user"],
         "management_identity_path": d["identity_file"]}
        for d in devices
    ]


def inspect_root_environment() -> dict:
    """Read-only root-console inspection; returns no secrets or private key."""
    _root_only()
    gateway = pwd.getpwnam("ai-lab-gateway")
    tunnel = pwd.getpwnam("tunnel")
    gateway_home = Path(gateway.pw_dir)
    tunnel_home = Path(tunnel.pw_dir)
    registry = _service_registry()
    effective = _run([
        "/usr/sbin/sshd", "-T", "-C",
        "user=tunnel,host=gateway.debasti.com,addr=127.0.0.1"])
    auth_candidates = parse_tunnel_authorized_keys_location(
        effective, tunnel_home=tunnel_home)
    known = gateway_home / ".ssh" / "known_hosts"
    auth_statuses = [path_metadata(p) for p in auth_candidates]
    report = {
        "status": "root_read_only_inventory",
        "gateway_service": SERVICE_NAME,
        "service_users": {
            "gateway": {"uid": gateway.pw_uid, "gid": gateway.pw_gid,
                        "home": str(gateway_home)},
            "tunnel": {"uid": tunnel.pw_uid, "gid": tunnel.pw_gid,
                       "home": str(tunnel_home)},
        },
        "registry": path_metadata(registry),
        "tunnel_authorized_keys_candidates": auth_statuses,
        "gateway_known_hosts": path_metadata(known),
        "gateway_ssh_host_public": path_metadata(
            Path("/etc/ssh/ssh_host_ed25519_key.pub")),
        "root_candidate_identity_dir": path_metadata(
            Path("/etc/ai-lab-gateway/device-code-keys")),
        "root_candidate_journal_dir": path_metadata(
            Path("/var/lib/ai-lab-gateway/root-provision-10003")),
        "legacy_expected_ports": [10001, 10002],
        "candidate_port": 10003,
        "effective_sshd_properties": {
            key: next((
                line.split(None, 1)[1].strip()
                for line in effective.splitlines()
                if line.lower().startswith(key + " ")
            ), "unset")
            for key in (
                "authorizedkeysfile", "authenticationmethods",
                "passwordauthentication", "allowtcpforwarding",
                "gatewayports", "maxsessions",
            )
        },
    }
    if report["registry"]["status"] == "exists":
        report["registry_devices"] = _registry_summary(registry)
    else:
        report["registry_devices"] = "unavailable"
    # No root install can use this report as an authorization token.
    return report


def report_to_json(report: dict) -> str:
    if not isinstance(report, dict) or report.get("status") != "root_read_only_inventory":
        raise ValueError("not a trustworthy inventory result shape")
    return json.dumps(report, indent=2, sort_keys=True)
