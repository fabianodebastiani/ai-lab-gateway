#!/usr/bin/env python3
"""AI Lab Gateway v2 Linux pairing CLIENT (prepare / claim only).

Runs on a Linux target, including a fresh host behind NAT. Requires only
Python >=3.10, OpenSSH's ssh-keygen, and outbound verified HTTPS.

It never touches sudoers, systemd, authorized_keys, host-key trust, existing
tunnels, or the gateway device registry. A successful claim is PENDING human
verification, NOT SSH activation. Separate provisioner handles activation.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

DEFAULT_ENDPOINT = "https://gateway.debasti.com/pairing/claim"
ID_RE = re.compile(r"^[a-z][a-z0-9-]{2,47}$")
MAX_RESPONSE = 4096
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")


def ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("refusing symlink directory")
    if path.exists():
        if not path.is_dir() or path.stat().st_uid != os.getuid():
            raise PermissionError("pairing directory owner or type is unsafe")
        if path.stat().st_mode & 0o077:
            raise PermissionError("pairing directory must be mode 0700")
    else:
        path.mkdir(mode=0o700, parents=False)
        os.chmod(path, 0o700)


def key_paths(directory: Path, device_id: str) -> tuple[Path, Path]:
    private = directory / ("tunnel-" + device_id + "-ed25519")
    return private, Path(str(private) + ".pub")


def ed25519_key(text: str) -> str:
    from base64 import b64decode
    import struct
    words = text.split()
    if len(words) < 2 or words[0] != "ssh-ed25519":
        raise ValueError("expected ssh-ed25519 public key")
    if len(text) > 1024:
        raise ValueError("SSH key too long")
    raw = b64decode(words[1], validate=True)
    if len(raw) != 51 or raw[:4] != struct.pack(">I", 11) or raw[4:15] != b"ssh-ed25519" or raw[15:19] != struct.pack(">I", 32):
        raise ValueError("invalid ssh-ed25519 public key")
    return "ssh-ed25519 " + words[1]


def fingerprint(public: str) -> str:
    blob = base64.b64decode(public.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def prepare(directory: Path, device_id: str, *, host_key_path: Path = HOST_KEY) -> dict:
    if not ID_RE.fullmatch(device_id):
        raise ValueError("invalid device ID")
    if not host_key_path.is_file():
        raise FileNotFoundError("OpenSSH ED25519 host key missing; install/initialize openssh-server locally")
    host_key = ed25519_key(host_key_path.read_text(encoding="utf8"))
    ensure_private_dir(directory)
    private, pub = key_paths(directory, device_id)
    # Do not reuse existing v1 key material. A retry can use the SAME
    # candidate key but must never regenerate it silently.
    if not private.exists() and not pub.exists():
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private),
             "-C", "ai-lab-v2-" + device_id],
            check=True, capture_output=True, text=True, timeout=20
        )
        os.chmod(private, 0o600)
        os.chmod(pub, 0o600)
    else:
        if private.is_symlink() or pub.is_symlink() or not private.is_file() or not pub.is_file():
            raise PermissionError("candidate key paths are incomplete or symlinks")
    if private.stat().st_uid != os.getuid() or private.stat().st_mode & 0o077:
        raise PermissionError("candidate private key owner/mode is unsafe")
    tunnel_key = ed25519_key(pub.read_text(encoding="utf8"))
    return {
        "device_id": device_id,
        "tunnel_public_key": tunnel_key,
        "ssh_host_public_key": host_key,
        "tunnel_key_fingerprint": fingerprint(tunnel_key),
        "host_key_fingerprint": fingerprint(host_key),
        "private_key_path": str(private),
    }


def claim(endpoint: str, token: str, *, device_id: str, device_name: str,
          persistent: bool, tunnel_public_key: str, ssh_host_public_key: str,
          opener=urllib.request.urlopen) -> dict:
    if endpoint != DEFAULT_ENDPOINT:
        raise ValueError("pairing endpoint must be the pinned HTTPS gateway URL")
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43,64}", token):
        raise ValueError("invalid temporary invitation token")
    if not ID_RE.fullmatch(device_id) or not isinstance(device_name, str) or not 1 <= len(device_name.strip()) <= 80:
        raise ValueError("invalid device identity")
    if type(persistent) is not bool:
        raise ValueError("persistent flag must be boolean")
    body = json.dumps({
        "token": token, "device_id": device_id, "device_name": device_name.strip(),
        "persistent": persistent, "tunnel_public_key": ed25519_key(tunnel_public_key),
        "ssh_host_public_key": ed25519_key(ssh_host_public_key),
    }, separators=(",", ":")).encode()
    request = urllib.request.Request(endpoint, data=body, headers={
        "Content-Type": "application/json", "Accept": "application/json"
    }, method="POST")
    with opener(request, timeout=10) as response:
        if response.status != 202:
            raise RuntimeError("pairing was not accepted")
        data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("oversized pairing response")
    result = json.loads(data)
    if not isinstance(result, dict) or result.get("status") != "pending" or result.get("access_mode") != "restricted" or result.get("device_id") != device_id:
        raise RuntimeError("unexpected response from pairing gateway")
    if result.get("tunnel_key_fingerprint") != fingerprint(tunnel_public_key) or result.get("host_key_fingerprint") != fingerprint(ssh_host_public_key):
        raise RuntimeError("pairing gateway reported unexpected public-key fingerprints")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Prepare or claim a Linux v2 pairing invitation")
    parser.add_argument("action", choices=["prepare", "claim"])
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--name", default=None)
    parser.add_argument("--persistent", action="store_true", default=False)
    parser.add_argument("--directory", type=Path, default=Path.home() / ".ssh" / "ai-lab-v2")
    parser.add_argument("--host-key", type=Path, default=HOST_KEY)
    parser.add_argument("--token-stdin", action="store_true",
                        help="Read the invitation from a trusted pipe; never from argv")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run under the target's unprivileged Linux management account, not root")
    os.umask(0o077)
    try:
        details = prepare(args.directory, args.device_id, host_key_path=args.host_key)
        if args.action == "prepare":
            print(json.dumps({
                "status": "prepared", "device_id": args.device_id,
                "tunnel_key_fingerprint": details["tunnel_key_fingerprint"],
                "host_key_fingerprint": details["host_key_fingerprint"],
                "persistent": args.persistent,
                "note": "No SSH account, tunnel or gateway permission changed",
            }, indent=2))
            return 0
        if args.token_stdin:
            token = sys.stdin.readline(256).strip()
        else:
            if not sys.stdin.isatty():
                raise RuntimeError("claim requires a terminal or --token-stdin trusted pipe")
            import getpass
            token = getpass.getpass("One-time pairing invitation (hidden): ").strip()
        result = claim(
            DEFAULT_ENDPOINT, token, device_id=args.device_id,
            device_name=args.name or args.device_id, persistent=args.persistent,
            tunnel_public_key=details["tunnel_public_key"],
            ssh_host_public_key=details["ssh_host_public_key"]
        )
        print(json.dumps(result, indent=2))
        print("PENDING: verify SSH fingerprints and approve independently.")
        return 0
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError,
            urllib.error.URLError, subprocess.SubprocessError, OSError) as exc:
        print("PAIRING_NOT_COMPLETED: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
