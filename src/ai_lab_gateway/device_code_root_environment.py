"""Read-only SSH provisioning environment checks for the WSL v2 candidate.

Security boundary: this module never writes files, starts systemd services,
grants sudo, or opens SSH authentication sessions. The ONLY approved port is
127.0.0.1:10003. A separate root-owned service must hold the *trusted* paths,
verified peer identity, approved candidate and effective sshd policy.

The caller must not populate trusted path/UID arguments from HTTP/MCP or
device data. The future production entrypoint uses fixed constants below;
dependency-injected test paths are only for an offline laboratory.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess

from .device_code_root_preflight import preflight_wsl_candidate
from .enrollment import _validate_public_key

PROD_AUTHORIZED_KEYS = Path("/var/lib/ai-lab-tunnel/.ssh/authorized_keys")
PROD_KNOWN_HOSTS = Path("/var/lib/ai-lab-gateway/.ssh/known_hosts")
PROD_REGISTRY = Path("/etc/ai-lab-gateway/devices.json")
PROD_GATEWAY_HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
PROD_MANAGEMENT_KEY = Path("/var/lib/ai-lab-gateway/keys/windows-wsl-v2-candidate.pub")
PROD_MANAGEMENT_PRIVATE_KEY = Path("/var/lib/ai-lab-gateway/keys/windows-wsl-v2-candidate")
PORT = 10003
MAX_FILE = 256 * 1024


def protected_file(path: Path, *, owner_uid: int, modes: frozenset[int],
                   limit: int = MAX_FILE) -> bytes:
    """Deny symlinks/hardlinks, untrusted owner/mode and oversized sources."""
    if (type(owner_uid) is not int or owner_uid < 0
            or not isinstance(modes, frozenset) or not modes):
        raise ValueError("invalid local file trust policy")
    path = Path(path)
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != owner_uid
            or stat.S_IMODE(parent.st_mode) & 0o022):
        raise PermissionError("untrusted SSH source directory")
    # O_NOFOLLOW and checking fstat on the open descriptor, not only lstat,
    # prevent a symlink swap from changing what root actually reads.
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink != 1):
            raise PermissionError("trusted source file ownership or type mismatch")
        with os.fdopen(fd, "rb", closefd=False) as fp:
            raw = fp.read(limit + 1)
    finally:
        os.close(fd)
    if len(raw) > limit:
        raise PermissionError("trusted source too large")
    return raw


def verify_management_key_pair(private_path: Path, *,
                               expected_public: str, owner_uid: int) -> None:
    """Prove the Gateway actually holds the nonroot management private key.

    The file path and ownership policy must be fixed by root, not supplied
    by the new device. No secret bytes are returned or logged.
    """
    protected_file(private_path, owner_uid=owner_uid,
                   modes=frozenset({0o600}), limit=16384)
    result = subprocess.run(
        ["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(private_path)],
        check=True, capture_output=True, text=True, timeout=7)
    actual = _validate_public_key(result.stdout.strip())
    if actual != _validate_public_key(expected_public):
        raise PermissionError("Gateway management private/public SSH keys differ")


def known_hosts_key(raw: bytes, *, endpoint: str) -> str:
    """Require ONE unhashed, unmarked exact ED25519 pin for fixed endpoint."""
    if endpoint not in ("[127.0.0.1]:10002",):
        raise PermissionError("target SSH host identity source not allowlisted")
    found = []
    for line in raw.decode("ascii").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] == endpoint:
            if len(fields) < 3 or fields[1] != "ssh-ed25519":
                raise PermissionError("unexpected existing target host key")
            value = _validate_public_key(fields[1] + " " + fields[2])
            found.append(value)
        elif fields[0].startswith("@") and endpoint in fields:
            raise PermissionError("marked host entry for target")
    if len(found) != 1:
        raise PermissionError("target sshd must have exactly one trusted ED25519 pin")
    return found[0]


def check_tunnel_sshd_policy(effective: str) -> None:
    """Check only the effective sshd -T configuration for the tunnel account."""
    if not isinstance(effective, str) or len(effective) > 128 * 1024:
        raise PermissionError("invalid effective sshd configuration")
    seen = {}
    for line in effective.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[0] not in seen:
            seen[parts[0].lower()] = parts[1].strip().lower()
    expected = {
        "passwordauthentication": "no",
        "kbdinteractiveauthentication": "no",
        "pubkeyauthentication": "yes",
        "allowtcpforwarding": "remote",
        "gatewayports": "no",
        "x11forwarding": "no",
        "allowagentforwarding": "no",
        "permittty": "no",
        "permituserrc": "no",
        "maxsessions": "0",
    }
    for k, value in expected.items():
        if seen.get(k) != value:
            raise PermissionError("gateway tunnel sshd restrictions not verified")
    if seen.get("authenticationmethods") != "publickey":
        raise PermissionError("tunnel account requires public-key-only authentication")


def loopback_port_available(*, bind_port: int = PORT) -> bool:
    """Probe a non-public listener; actual installer MUST reserve the port."""
    if type(bind_port) is not int or bind_port != PORT:
        raise PermissionError("only candidate port 10003 may be inspected")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind(("127.0.0.1", PORT))
        except OSError:
            return False
    return True


def inspect_candidate_environment(candidate: dict, *, files: dict,
                                  owners: dict, effective_sshd: str,
                                  port_is_free: bool) -> dict:
    """Read-only testable core; trusted file paths/UIDs from root-side config.

    No caller-controlled path is permitted through the IPC. The eventual
    root entrypoint uses only fixed PROD_* paths and passwd-resolved owners.
    """
    if not isinstance(files, dict) or set(files) != {
            "authorized_keys", "known_hosts", "registry",
            "gateway_host_key", "management_key", "management_private_key"}:
        raise PermissionError("invalid trusted path configuration")
    if not isinstance(owners, dict) or set(owners) != {
            "tunnel", "gateway", "registry", "host"}:
        raise PermissionError("invalid owner mapping")
    if port_is_free is not True:
        raise PermissionError("WSL candidate loopback port is unavailable")

    tunnel_auth = protected_file(files["authorized_keys"],
                                 owner_uid=owners["tunnel"], modes=frozenset({0o600}))
    gateway_known = protected_file(files["known_hosts"],
                                   owner_uid=owners["gateway"], modes=frozenset({0o600}))
    registry_raw = protected_file(files["registry"],
                                  owner_uid=owners["registry"], modes=frozenset({0o600, 0o640}))
    gateway_host = protected_file(files["gateway_host_key"],
                                  owner_uid=owners["host"], modes=frozenset({0o644, 0o600}))
    management = protected_file(files["management_key"],
                                owner_uid=owners["gateway"], modes=frozenset({0o644, 0o600}))
    verify_management_key_pair(
        files["management_private_key"],
        expected_public=management.decode("ascii").strip(),
        owner_uid=owners["gateway"])
    # Fail closed before any write if the candidate is already authorized.
    if (b'permitlisten="127.0.0.1:10003"' in tunnel_auth
            or b"[127.0.0.1]:10003 " in gateway_known):
        raise PermissionError("WSL candidate port/key already staged")
    check_tunnel_sshd_policy(effective_sshd)
    gateway_public = _validate_public_key(gateway_host.decode("ascii").strip())
    target_public = known_hosts_key(gateway_known, endpoint="[127.0.0.1]:10002")
    management_public = _validate_public_key(management.decode("ascii").strip())
    try:
        registry = json.loads(registry_raw)
    except (UnicodeError, ValueError) as exc:
        raise PermissionError("unreadable protected device registry") from exc
    return preflight_wsl_candidate(
        candidate,
        trusted_gateway_host_key=gateway_public,
        independently_verified_target_host_key=target_public,
        actual_gateway_management_public_key=management_public,
        protected_registry=registry)


def inspect_fixed_production_environment(candidate: dict, *,
                                         effective_sshd: str,
                                         reserved_socket: socket.socket | None = None) -> dict:
    """Root-only read-only inspection. NOT a deployment or authorization."""
    if os.geteuid() != 0:
        raise PermissionError("actual root required for fixed-path inspection")
    # During the controlled root apply the caller holds an exclusive bind to
    # 127.0.0.1:10003. Rebinding it to test availability would necessarily
    # fail. No caller-provided Boolean can bypass the socket identity check.
    if reserved_socket is not None:
        if (type(reserved_socket) is not socket.socket
                or reserved_socket.fileno() < 0
                or reserved_socket.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                != socket.SOCK_STREAM
                or reserved_socket.getsockname() != ("127.0.0.1", PORT)):
            raise PermissionError("root SSH candidate port is not reserved")
        free_or_reserved = True
    else:
        free_or_reserved = loopback_port_available()
    return inspect_candidate_environment(
        candidate,
        files={
            "authorized_keys": PROD_AUTHORIZED_KEYS,
            "known_hosts": PROD_KNOWN_HOSTS,
            "registry": PROD_REGISTRY,
            "gateway_host_key": PROD_GATEWAY_HOST_KEY,
            "management_key": PROD_MANAGEMENT_KEY,
            "management_private_key": PROD_MANAGEMENT_PRIVATE_KEY,
        },
        owners={
            "tunnel": pwd.getpwnam("tunnel").pw_uid,
            "gateway": pwd.getpwnam("ai-lab-gateway").pw_uid,
            "registry": 0, "host": 0,
        },
        effective_sshd=effective_sshd,
        port_is_free=free_or_reserved,
    )
