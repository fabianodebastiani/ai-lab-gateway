"""Strict OpenSSH client. WireGuard routing is managed outside this project."""
from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import stat
import subprocess

from .store import Device, validate_device


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


def _ssh_argv(device: Device) -> list[str]:
    # Re-check on every operation: changing the DB cannot bypass the network boundary.
    validate_device(device)
    key_dir = Path(os.environ.get("LITE_SSH_KEY_DIR", "/var/lib/ai-lab-gateway-lite/keys")).resolve()
    key = (key_dir / device.key_name).resolve()
    if key.parent != key_dir or not key.is_file():
        raise PermissionError("missing or unsafe SSH key path")
    if stat.S_IMODE(key.stat().st_mode) & 0o077:
        raise PermissionError("SSH key must not be accessible to group/others")
    known_hosts = Path(os.environ.get("LITE_SSH_KNOWN_HOSTS", "/var/lib/ai-lab-gateway-lite/known_hosts")).resolve()
    if not known_hosts.is_file() or not known_hosts.read_text(encoding="utf-8").strip():
        raise PermissionError("pinned SSH known_hosts is missing")
    return [
        "ssh", "-F", "/dev/null", "-T",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UpdateHostKeys=no",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-o", "ConnectTimeout=10",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "UserKnownHostsFile=" + str(known_hosts),
        "-i", str(key),
        "-p", str(device.port),
        device.ssh_user + "@" + device.host,
        "--",
    ]


def execute(device: Device, command: str, timeout: int = 30, stdin_text: str | None = None) -> CommandResult:
    if not isinstance(timeout, int) or not 1 <= timeout <= 120:
        raise ValueError("timeout must be 1..120 seconds")
    if not command or len(command) > 4096:
        raise ValueError("invalid remote command length")
    if stdin_text is not None and len(stdin_text.encode("utf-8")) > 65536:
        raise ValueError("file content exceeds 64 KiB")
    result = subprocess.run(_ssh_argv(device) + [command], input=stdin_text,
                            text=True, capture_output=True, timeout=timeout, check=False)
    return CommandResult(stdout=result.stdout[:1048576], stderr=result.stderr[:16384],
                         exit_code=result.returncode)


def safe_read_command(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048 or "\x00" in path:
        raise ValueError("path must be absolute")
    return "cat -- " + shlex.quote(path)


def safe_write_command(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > 2048 or "\x00" in path:
        raise ValueError("path must be absolute")
    return "cat > " + shlex.quote(path)
