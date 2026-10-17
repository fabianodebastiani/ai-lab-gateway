"""SSH execution backend.

The MCP control plane invokes this backend only after OAuth scope checks,
deny-by-default subject/device/action authorization, registry validation, and
strict per-device SSH identity selection have succeeded.
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


def execute_privileged_one_use(device: Device, voucher: dict,
                               timeout: int = 25) -> CommandResult:
    """Forward a human-approved signed voucher over SSH STDIN, never argv.

    Do NOT expose the voucher through normal exec, URL or shell history.
    The target's root-owned executor independently verifies the signature
    and records durable one-use consumption. No arbitrary remote command.
    """
    import json
    if type(timeout) is not int or not 1 <= timeout <= 45:
        raise ValueError("invalid privileged execution timeout")
    if (device.ssh_user != "ai-gateway" or device.tunnel_host != "127.0.0.1"
            or not 11000 <= device.tunnel_port <= 11999):
        raise PermissionError("privileged execution requires explicit restricted v2 target")
    if not isinstance(voucher, dict) or set(voucher) != {"permit", "signature"}:
        raise PermissionError("invalid privilege voucher")
    permit = voucher.get("permit")
    if (not isinstance(permit, dict)
            or permit.get("version") != "ai-lab-privexec-one-v1"
            or permit.get("device_id") != device.id
            or permit.get("operation") != "root-identity-check"
            or permit.get("argv") != ["/usr/bin/id", "-u"]
            or not isinstance(voucher.get("signature"), str)):
        raise PermissionError("voucher and target mismatch")
    payload = json.dumps(voucher, separators=(",", ":"), ensure_ascii=True) + "\n"
    if len(payload.encode("ascii")) > 16 * 1024:
        raise PermissionError("oversized signed voucher")
    argv = [
        "/usr/bin/ssh", "-T",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        "-i", device.identity_file,
        "-p", str(device.tunnel_port),
        "ai-gateway@127.0.0.1", "--",
        # Static command ONLY. Voucher travels on an SSH-encrypted stdin
        # channel. No arbitrary command, file or user-supplied arguments.
        "/usr/bin/sudo -n -- /usr/local/libexec/ai-lab-target-privexec",
    ]
    try:
        result = subprocess.run(argv, input=payload, capture_output=True,
                                text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("privileged command timed out; approval consumed") from exc
    return CommandResult(stdout=result.stdout[:1024], stderr=result.stderr[:1024],
                         exit_code=result.returncode)
