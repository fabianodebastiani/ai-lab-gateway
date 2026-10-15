#!/usr/bin/env python3
"""Root-only WSL v2 SSH CANDIDATE provisioner (no active registry cutover).

Security: inspect independently human-approved claim over pairing root RPC.
Create gateway-owned management ED25519 identity, add a constrained
tunnel public key for loopback 10003, and pin the approved target host key.
Do not change the existing port 10002, active device registry, service
accounts, or operator permissions. No general sudo grants.

The management public key must still be installed on the Linux target
by a separate trusted target-local action. Complete SSH test and manual
cutover are later steps, NOT performed by this program.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

SOCKET = Path("/run/ai-lab-pairing/approver.sock")
TUNNEL_KEYS = Path("/var/lib/ai-lab-tunnel/.ssh/authorized_keys")
GATEWAY_KNOWN = Path("/var/lib/ai-lab-gateway/.ssh/known_hosts")
GATEWAY_KEYS = Path("/var/lib/ai-lab-gateway/keys")
REGISTRY = Path("/etc/ai-lab-gateway/devices.json")
CANDIDATES = Path("/etc/ai-lab-gateway/pairing-candidates")
BACKUPS = Path("/var/backups/ai-lab-gateway")
PORT = 10003
DEVICE = "windows-wsl"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


def rpc_inspect(request_id: str) -> dict:
    if not ID_RE.fullmatch(request_id):
        raise ValueError("invalid pairing request id")
    line = (json.dumps({"action": "inspect", "request_id": request_id}) + "\n").encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(4)
        sock.connect(str(SOCKET))
        sock.sendall(line)
        response = b""
        while not response.endswith(b"\n"):
            block = sock.recv(4096)
            if not block:
                raise ConnectionError("pairing service disconnected")
            response += block
            if len(response) > 8192:
                raise ValueError("oversized pairing RPC response")
    parsed = json.loads(response)
    if not isinstance(parsed, dict) or parsed.get("ok") is not True or not isinstance(parsed.get("request"), dict):
        raise PermissionError("pairing request is not approved or not found")
    return parsed["request"]


def validate_approved(value: dict, *, now: int | None = None) -> dict:
    from base64 import b64decode
    import struct
    moment = int(time.time()) if now is None else now
    if value.get("device_id") != DEVICE or value.get("status") != "approved":
        raise PermissionError("WSL v2 candidate requires independent approval")
    reviewed = value.get("reviewed_at")
    if type(reviewed) is not int or not 0 <= moment - reviewed <= 3600:
        raise PermissionError("approval is missing or stale")
    if value.get("access_mode") != "restricted":
        raise PermissionError("only restricted enrollment is allowed")
    if type(value.get("persistent")) is not bool or value["persistent"] is not False:
        raise PermissionError("WSL pilot must keep on-demand persistence")
    public = {}
    for name in ("tunnel_public_key", "ssh_host_public_key"):
        raw = value.get(name)
        if not isinstance(raw, str) or len(raw)>1024 or "\n" in raw:
            raise ValueError("invalid SSH public key")
        words = raw.split()
        if len(words)<2 or words[0]!="ssh-ed25519":
            raise ValueError("only ed25519 public keys")
        binary = b64decode(words[1], validate=True)
        if len(binary)!=51 or binary[:4]!=struct.pack(">I",11) or binary[4:15]!=b"ssh-ed25519" or binary[15:19]!=struct.pack(">I",32):
            raise ValueError("invalid public-key encoding")
        public[name] = "ssh-ed25519 " + words[1]
    if public["tunnel_public_key"] == public["ssh_host_public_key"]:
        raise ValueError("tunnel and target host key must differ")
    return {**value, **public}


def sha_fp(public: str) -> str:
    blob = base64.b64decode(public.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def safe_existing(path: Path, user: str, mode: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise PermissionError("unexpected key file path type")
    st = path.stat()
    if st.st_uid != pwd.getpwnam(user).pw_uid or stat.S_IMODE(st.st_mode) != mode:
        raise PermissionError("unexpected key file owner or permissions")
    return path.read_bytes()


def atomic_replace(path: Path, data: bytes, uid: int, gid: int, mode: int):
    if path.is_symlink():
        raise PermissionError("refuse to overwrite symlink")
    fd, tmp = tempfile.mkstemp(prefix=".v2-pilot-", dir=path.parent)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def candidate_preflight(request: dict):
    if os.geteuid() != 0:
        raise PermissionError("root required")
    validated = validate_approved(request)
    data = json.loads(REGISTRY.read_text())
    if not any(d.get("id") == DEVICE and d.get("tunnel_port") == 10002
               for d in data.get("devices", [])):
        raise RuntimeError("legacy WSL registry no longer matches expected 10002")
    if any(d.get("tunnel_port") == PORT for d in data.get("devices", [])):
        raise RuntimeError("candidate port is already registered")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind(("127.0.0.1", PORT))
        except OSError as exc:
            raise RuntimeError("candidate TCP port 10003 already in use") from exc
    keyfile = GATEWAY_KEYS / "windows-wsl-v2-candidate"
    metadata = CANDIDATES / (DEVICE + ".json")
    if any(p.exists() or p.is_symlink() for p in
           (keyfile, Path(str(keyfile)+".pub"), metadata)):
        raise RuntimeError("candidate already provisioned; do not overwrite")
    tunnel_original = safe_existing(TUNNEL_KEYS, "tunnel", 0o600)
    known_original = safe_existing(GATEWAY_KNOWN, "ai-lab-gateway", 0o600)
    tunnel = validated["tunnel_public_key"].encode()
    if tunnel.split()[1] in tunnel_original:
        raise RuntimeError("candidate tunnel key already authorized")
    if b"[127.0.0.1]:10003" in known_original:
        raise RuntimeError("candidate port host key already pinned")
    return validated, tunnel_original, known_original, keyfile, metadata


def prepare(request: dict) -> dict:
    validated, tunnel_original, known_original, keyfile, metadata = candidate_preflight(request)
    gw = pwd.getpwnam("ai-lab-gateway")
    tun = pwd.getpwnam("tunnel")
    CANDIDATES.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(CANDIDATES, 0, 0)
    os.chmod(CANDIDATES, 0o700)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup = BACKUPS / ("wsl-v2-candidate-" + stamp)
    backup.mkdir(mode=0o700, exist_ok=False)
    os.chown(backup, 0, 0)
    (backup / "authorized_keys.original").write_bytes(tunnel_original)
    (backup / "known_hosts.original").write_bytes(known_original)
    for name in ("authorized_keys.original", "known_hosts.original"):
        os.chmod(backup/name, 0o600)
    key_created=False
    tunnel_modified=False
    known_modified=False
    try:
        subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                        "-N", "", "-f", str(keyfile), "-C", "ai-lab-wsl-v2"],
                       check=True, capture_output=True, text=True, timeout=20)
        key_created=True
        os.chown(keyfile, gw.pw_uid, gw.pw_gid)
        os.chmod(keyfile, 0o600)
        public_path=Path(str(keyfile)+".pub")
        os.chown(public_path, gw.pw_uid, gw.pw_gid)
        os.chmod(public_path, 0o644)
        new_tunnel_line = ('permitlisten="127.0.0.1:10003",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc ' +
                           validated["tunnel_public_key"] + " ai-lab-wsl-v2\n").encode()
        atomic_replace(TUNNEL_KEYS, tunnel_original.rstrip(b"\n") + b"\n" + new_tunnel_line,
                       tun.pw_uid, tun.pw_gid, 0o600)
        tunnel_modified=True
        new_known = (f"[127.0.0.1]:10003 {validated['ssh_host_public_key']}\n").encode()
        atomic_replace(GATEWAY_KNOWN, known_original.rstrip(b"\n") + b"\n" + new_known,
                       gw.pw_uid, gw.pw_gid, 0o600)
        known_modified=True
        candidate = {
            "device_id": DEVICE, "port": PORT,
            "status": "awaiting_new_tunnel_and_management_login",
            "request_id": validated["request_id"],
            "identity_file": str(keyfile), "ssh_user": "ai-gateway",
            "persistent": False, "access_mode": "restricted",
            "tunnel_fingerprint": sha_fp(validated["tunnel_public_key"]),
            "host_fingerprint": sha_fp(validated["ssh_host_public_key"]),
            "management_public_key": public_path.read_text().splitlines()[0],
            "backup": str(backup),
        }
        atomic_replace(metadata, (json.dumps(candidate, indent=2)+"\n").encode(), 0, 0, 0o600)
        return {
            "status": "candidate_prepared",
            "device_id": DEVICE, "port": PORT,
            "management_public_key_path": str(public_path),
            "backup": str(backup),
            "note": "Legacy registry, port 10002 and original keys unchanged",
        }
    except BaseException:
        if known_modified:
            atomic_replace(GATEWAY_KNOWN, known_original, gw.pw_uid, gw.pw_gid, 0o600)
        if tunnel_modified:
            atomic_replace(TUNNEL_KEYS, tunnel_original, tun.pw_uid, tun.pw_gid, 0o600)
        if key_created:
            for p in (keyfile, Path(str(keyfile)+".pub")):
                p.unlink(missing_ok=True)
        metadata.unlink(missing_ok=True)
        raise


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args=parser.parse_args()
    if args.check==args.apply:
        parser.error("select --check or --apply")
    if os.geteuid()!=0:
        raise PermissionError("root required")
    request=rpc_inspect(args.request_id)
    if args.check:
        candidate_preflight(request)
        print("APPROVED_WSL_CANDIDATE; port=10003; only restricted/on-demand; no changes")
        return
    print(json.dumps(prepare(request), sort_keys=True))


if __name__=="__main__":
    main()
