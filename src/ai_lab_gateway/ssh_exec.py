"""SSH execution backend.

This module is intentionally not exposed as an MCP tool yet. Authentication and
user-to-device authorization must be in place before remote execution becomes
part of the public MCP surface.
"""

from dataclasses import dataclass
import subprocess

from .registry import Device


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int


def execute(device: Device, command: str, timeout: int = 30) -> CommandResult:
    if timeout < 1 or timeout > 300:
        raise ValueError("timeout must be between 1 and 300 seconds")

    argv = [
        "ssh",
        "-T",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-i", device.identity_file,
        "-p", str(device.tunnel_port),
        f"{device.ssh_user}@{device.tunnel_host}",
        "--",
        command,
    ]

    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"command timed out after {timeout}s on device {device.id}"
        ) from exc

    return CommandResult(
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
    )
