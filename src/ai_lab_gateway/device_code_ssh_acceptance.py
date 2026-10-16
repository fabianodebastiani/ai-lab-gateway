"""Read-only SSH acceptance for an independently provisioned WSL pilot.

Does not update the registry, access policy, pairing state, sudoers or SSH
credentials. Root provisioning and native user approval are separate.
"""
from __future__ import annotations

import subprocess

TUNNEL_PORT = 10003
TARGET_USER = "ai-gateway"
TARGET_HOSTNAME = "laptop-5rjj0kbm"
GATEWAY_MANAGEMENT_KEY = (
    "/etc/ai-lab-gateway/device-code-keys/wsl-10003/identity")
PINNED_KNOWN_HOSTS = "/var/lib/ai-lab-gateway/.ssh/known_hosts"


def verify_wsl_ssh_acceptance() -> dict:
    """Prove the existing Gateway credential can reach the nonroot WSL.

    The target identity and command are *fixed*. No client-controlled
    hostname, command, port, SSH key or arbitrary program is interpolated.
    SSH must confirm the independently pre-pinned Ed25519 host identity.
    This is a read-only precondition, not activation or registry permission.
    """
    base = [
        "/usr/bin/ssh", "-T",
        "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
        "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + PINNED_KNOWN_HOSTS,
        "-o", "ConnectTimeout=4",
        "-o", "ControlMaster=no",
        "-o", "ClearAllForwardings=yes",
        "-i", GATEWAY_MANAGEMENT_KEY,
        "-p", str(TUNNEL_PORT),
        TARGET_USER + "@127.0.0.1", "--",
    ]
    try:
        remote_user = subprocess.run(
            base + ["id -un"], capture_output=True, text=True,
            timeout=9, check=False)
        remote_host = subprocess.run(
            base + ["hostname"], capture_output=True, text=True,
            timeout=9, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PermissionError("candidate SSH identity not verified") from exc
    if (remote_user.returncode != 0 or remote_host.returncode != 0
            or remote_user.stdout.strip() != TARGET_USER
            or remote_host.stdout.strip().lower() != TARGET_HOSTNAME):
        raise PermissionError("candidate SSH user or host mismatched")
    return {"verified": True, "user": TARGET_USER,
            "hostname": TARGET_HOSTNAME, "port": TUNNEL_PORT}
