"""Isolated candidate SSH provisioning laboratory for device-code v2.

NOT DEPLOYED; never call from public HTTP/MCP. A future root-owned adapter
must establish UID/policy, select the port from protected registry, verify
live port availability, own keys/paths and perform rollback before approval
can become real SSH connectivity.

This module stages only private laboratory artifacts in a caller-owned 0700
directory; it NEVER edits real SSH authorized_keys, known_hosts, systemd,
sudoers, production device registry, or active tunnel credentials.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

from .device_code_offer import OFFER_VERSION, fingerprint, validate_offer
from .enrollment import _validate_public_key

# Exact WSL pilot: never accept a device-selected gateway port or elevated mode.
PILOT_DEVICE = "windows-wsl"
PILOT_PORT = 10003
LEGACY_PORT = 10002


def build_candidate_plan(store, request_id: str, *, gateway_host_public_key: str,
                         gateway_management_public_key: str,
                         now: int | None = None) -> dict:
    """Create a public-only, *non-activating* plan from the approved DB row.

    The caller's trusted gateway identities must originate from the protected
    local host configuration and a fresh gateway-generated management key.
    Neither is accepted through HTTP, ChatGPT, or the device's offer.
    """
    request = store.approved_candidate_snapshot(request_id=request_id, now=now)
    if request["device_id"] != PILOT_DEVICE or request["persistent"] is not False:
        raise PermissionError("WSL pilot requires known device and on-demand mode")
    tunnel = _validate_public_key(request["tunnel_public_key"])
    host = _validate_public_key(request["host_public_key"])
    gateway_host = _validate_public_key(gateway_host_public_key)
    gateway_management = _validate_public_key(gateway_management_public_key)
    if len({tunnel, host, gateway_host, gateway_management}) != 4:
        raise PermissionError("four independent SSH identities required")
    offer = {
        "version": OFFER_VERSION, "request_id": request_id,
        "device_id": PILOT_DEVICE, "access_mode": "restricted",
        "persistent": False, "gateway_host": "gateway.debasti.com",
        "gateway_ssh_port": 22, "gateway_tunnel_user": "tunnel",
        "gateway_ssh_host_key": gateway_host,
        "gateway_management_public_key": gateway_management,
        "reverse_listen_host": "127.0.0.1",
        "reverse_listen_port": PILOT_PORT,
        "management_user": "ai-gateway",
        "device_tunnel_fingerprint": fingerprint(tunnel),
        "device_host_fingerprint": fingerprint(host),
    }
    validate_offer(offer, request_id=request_id, device_id=PILOT_DEVICE,
                   persistent=False, tunnel_key=tunnel, host_key=host)
    # The gateway sshd MUST independently enforce remote-only forwarding,
    # public-key-only auth, MaxSessions=0 and no other login privilege.
    tunnel_line = (
        'permitlisten="127.0.0.1:10003",no-agent-forwarding,'
        'no-X11-forwarding,no-pty,no-user-rc ' + tunnel + " ai-lab-wsl-v2\n"
    )
    known_line = "[127.0.0.1]:10003 " + host + "\n"
    return {
        "offer": offer,
        "tunnel_authorized_keys_append": tunnel_line,
        "gateway_known_hosts_append": known_line,
        "target_management_authorized_keys_append": gateway_management + "\n",
        "target_gateway_known_hosts": "gateway.debasti.com " + gateway_host + "\n",
    }


def _private_directory(path: Path) -> None:
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise PermissionError("staging root must be an owned 0700 directory")


def _write_private(path: Path, data: str) -> None:
    raw = data.encode("utf-8")
    with open(path, "xb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def stage_lab_candidate(store, request_id: str, *, sandbox_root: Path,
                        trusted_gateway_host_public_key: str,
                        now: int | None = None) -> dict:
    """Stage a candidate **only in a lab**; return no private SSH material.

    This must not be invoked with root service paths. The approval and DB
    check are not a substitute for a root-owned, peer-credential-verified
    production IPC boundary. New management keys never leave the staging dir.
    """
    sandbox_root = Path(sandbox_root)
    _private_directory(sandbox_root)
    if os.geteuid() == 0:
        raise PermissionError("nonroot laboratory only; no production root mode")
    pin = _validate_public_key(trusted_gateway_host_public_key)
    name = "candidate-" + request_id
    if not request_id.isascii() or not all(c.isalnum() or c in "_-" for c in request_id):
        raise ValueError("invalid candidate identifier")
    if not 24 <= len(request_id) <= 64:
        raise ValueError("invalid candidate identifier")
    destination = sandbox_root / name
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("candidate already staged")

    # Reject absent, pending, denied, expired or already staged identities
    # BEFORE creating a keypair or other staged artifacts.
    store.approved_candidate_snapshot(request_id=request_id, now=now)
    temporary = Path(tempfile.mkdtemp(prefix=".candidate-", dir=sandbox_root))
    committed = False
    try:
        _private_directory(temporary)
        key = temporary / "gateway-management-ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(key), "-C", "ai-lab-pairing-candidate"],
                       check=True, capture_output=True, timeout=20)
        os.chmod(key, 0o600)
        public_file = Path(str(key) + ".pub")
        os.chmod(public_file, 0o600)
        plan = build_candidate_plan(
            store, request_id,
            gateway_host_public_key=pin,
            gateway_management_public_key=public_file.read_text("ascii").strip(),
            now=now)
        _write_private(temporary / "offer.json",
                       json.dumps(plan["offer"], sort_keys=True, indent=2) + "\n")
        for filename, field in (
            ("tunnel-authorized_keys.append", "tunnel_authorized_keys_append"),
            ("gateway-known_hosts.append", "gateway_known_hosts_append"),
            ("target-management-authorized_keys.append",
             "target_management_authorized_keys_append"),
            ("target-gateway-known_hosts", "target_gateway_known_hosts"),
        ):
            _write_private(temporary / filename, plan[field])
        _write_private(temporary / "STAGING_ONLY",
                       "Uninstalled candidate; not an SSH service or a registry update.\n")
        # Publish the isolated candidate first; DB publication happens only
        # after all files are complete. A crash here can leave an inert orphan,
        # never live SSH access; a production adapter needs reconciliation.
        temporary.rename(destination)
        committed = True
        try:
            store.stage_connection_offer(
                request_id=request_id, offer=plan["offer"],
                trusted_gateway_host_public_key=pin,
                provisioner_verified=True, now=now)
        except BaseException:
            # Isolated lab: this candidate is the only directory removed,
            # with no external SSH config to restore.
            shutil.rmtree(destination)
            committed = False
            raise
        return {
            "status": "candidate_staged", "device_id": PILOT_DEVICE,
            "access_mode": "restricted", "persistent": False,
            "reverse_listen_port": PILOT_PORT,
            "candidate_directory": str(destination),
            "production_ssh_changed": False,
        }
    finally:
        if not committed and temporary.exists():
            shutil.rmtree(temporary)
