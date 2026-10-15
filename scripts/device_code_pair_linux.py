#!/usr/bin/env python3
"""Experimental Linux device-code pairing CLI (ADR-029, NOT installed/live).

A fresh Linux device needs Python 3.10+, OpenSSH ssh-keygen/sshd and the
python3-cryptography package in this prototype. All HTTPS requests are
outbound; no existing Gateway SSH connection, device account, or sudo is used.
The CLI ONLY creates a pending, proven device session and polls its state.
It CANNOT approve, activate, install systemd, or grant Linux permissions.

Do not paste tokens into a terminal or use an unverified curl|sudo shell.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

VERSION = "ai-lab-device-code-v1"
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,47}$")
CODE_PATTERN = re.compile(r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
HOST_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
MAX_REPLY = 4096
POLL_SECONDS = 5


def base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("base URL must have no credentials, path, query or fragment")
    # Never send secrets to a non-TLS remote endpoint.
    if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "::1")):
        raise ValueError("HTTPS required except for isolated loopback testing")
    if not parsed.hostname or parsed.port == 0:
        raise ValueError("invalid Gateway URL")
    return value.rstrip("/")


def ed25519_public(value: str) -> str:
    words = value.split()
    if len(words) < 2 or words[0] != "ssh-ed25519" or len(value) > 1024:
        raise ValueError("invalid Ed25519 public key")
    import struct
    blob = base64.b64decode(words[1], validate=True)
    if (len(blob) != 51 or blob[:4] != struct.pack(">I", 11)
            or blob[4:15] != b"ssh-ed25519"
            or blob[15:19] != struct.pack(">I", 32)):
        raise ValueError("invalid Ed25519 public key encoding")
    return "ssh-ed25519 " + words[1]


def fingerprint(public: str) -> str:
    raw = base64.b64decode(public.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def owned_private_dir(path: Path):
    if path.is_symlink():
        raise PermissionError("refusing symlinked key directory")
    if not path.exists():
        path.mkdir(mode=0o700)
    st = path.stat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise PermissionError("private key directory must be mode 0700, owned by current user")


def local_keys(state_dir: Path, *, host_key_path: Path = HOST_KEY):
    if os.geteuid() == 0:
        raise PermissionError("pairing must run as an unprivileged Linux user")
    owned_private_dir(state_dir.parent)
    owned_private_dir(state_dir)
    if not host_key_path.is_file() or host_key_path.is_symlink():
        raise FileNotFoundError("OpenSSH server host Ed25519 public key is missing")
    host = ed25519_public(host_key_path.read_text(encoding="ascii"))
    private = state_dir / "tunnel-ed25519"
    pub = Path(str(private) + ".pub")
    if not private.exists() and not pub.exists():
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private),
             "-C", "ai-lab-device-code"],
            timeout=20, check=True, capture_output=True)
        private.chmod(0o600)
        pub.chmod(0o600)
    elif (private.is_symlink() or pub.is_symlink()
            or not private.is_file() or not pub.is_file()):
        raise PermissionError("partial or symlinked keypair; refusing to overwrite")
    if (private.stat().st_uid != os.geteuid()
            or stat.S_IMODE(private.stat().st_mode) != 0o600):
        raise PermissionError("candidate SSH private key must be owner-only 0600")
    tunnel = ed25519_public(pub.read_text(encoding="ascii"))
    return private, tunnel, host


def post(url: str, path: str, data: dict) -> dict:
    endpoint = base_url(url) + path
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    if len(payload) > 4096:
        raise ValueError("oversized pairing payload")
    request = urllib.request.Request(endpoint, data=payload, method="POST",
             headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status not in (200, 201):
            raise RuntimeError("unexpected pairing HTTP status")
        raw = response.read(MAX_REPLY + 1)
        if len(raw) > MAX_REPLY:
            raise ValueError("oversized pairing reply")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid pairing response")
    return value


def validate_challenge(reply: dict, *, device_id: str,
                       persistent: bool, tunnel: str, host: str):
    from datetime import datetime, timezone
    if (reply.get("status") != "pending" or reply.get("access_mode") != "restricted"
            or reply.get("persistent") is not persistent
            or not isinstance(reply.get("request_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", reply["request_id"])
            or not isinstance(reply.get("device_secret"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", reply["device_secret"])
            or not isinstance(reply.get("user_code"), str)
            or not CODE_PATTERN.fullmatch(reply["user_code"])
            or not isinstance(reply.get("expires_at"), int)):
        raise ValueError("invalid server pairing fields")
    challenge = base64.b64decode(reply["challenge_b64"], validate=True)
    if len(challenge) > 1024 or not challenge.endswith(b"\n"):
        raise ValueError("invalid versioned challenge")
    details = json.loads(challenge)
    if not isinstance(details, dict):
        raise ValueError("invalid challenge structure")
    expected = {
        "device_id": device_id, "request_id": reply["request_id"],
        "persistent": persistent,
        "host_fingerprint": fingerprint(host),
        "tunnel_fingerprint": fingerprint(tunnel),
        "role": "tunnel-key-possession", "version": VERSION,
        "expires_at": reply["expires_at"],
    }
    if any(details.get(k) != v for k, v in expected.items()):
        raise ValueError("server challenge does not match device identity")
    if not isinstance(details.get("nonce"), str) or len(details["nonce"]) < 24:
        raise ValueError("missing random challenge nonce")
    canonical = (json.dumps(details, sort_keys=True,
                            separators=(",", ":")) + "\n").encode("ascii")
    if challenge != canonical or set(details) != set(expected) | {"nonce"}:
        raise ValueError("noncanonical or extended challenge")
    comparison = base64.b32encode(hashlib.sha256(
        b"ai-lab-device-code-confirm-v1\x00" + challenge).digest()[:5]).decode("ascii")
    if reply.get("confirmation") != comparison[:4] + "-" + comparison[4:]:
        raise ValueError("display confirmation mismatch")
    return challenge


def run(*, url: str, device_id: str, name: str, persistent: bool,
        state_dir: Path, host_key_path: Path, wait: bool) -> int:
    if not ID_PATTERN.fullmatch(device_id) or not 1 <= len(name.strip()) <= 80:
        raise ValueError("invalid device identity")
    target_url = base_url(url)
    private, tunnel, host = local_keys(state_dir, host_key_path=host_key_path)
    started = post(target_url, "/pairing/device/start", {
        "device_id": device_id, "display_name": name,
        "tunnel_public_key": tunnel, "host_public_key": host,
        "persistent": persistent,
    })
    challenge = validate_challenge(started, device_id=device_id, persistent=persistent,
                                   tunnel=tunnel, host=host)
    material = serialization.load_ssh_private_key(private.read_bytes(), password=None)
    if not isinstance(material, Ed25519PrivateKey):
        raise ValueError("unexpected SSH private key type")
    signature = base64.b64encode(material.sign(challenge)).decode("ascii")
    verified = post(target_url, "/pairing/device/prove", {
        "request_id": started["request_id"],
        "device_secret": started["device_secret"],
        "signature_b64": signature,
    })
    if (verified.get("status") != "proven"
            or verified.get("request_id") != started["request_id"]
            or verified.get("access_mode") != "restricted"):
        raise RuntimeError("gateway did not accept proof of key possession")
    print("AI Lab Gateway — Vincular dispositivo", flush=True)
    print("Linux:", name, flush=True)
    print("Código:", started["user_code"], flush=True)
    print("Confirmação:", started["confirmation"], flush=True)
    print("No ChatGPT: Conectar dispositivo " + started["user_code"], flush=True)
    print("Aguardando autorização... (acesso inicial Restrito)", flush=True)
    if not wait:
        print("Laboratório: a sessão foi criada e provada; ainda não ativa.", flush=True)
        return 0
    while time.time() < started["expires_at"]:
        time.sleep(POLL_SECONDS)
        result = post(target_url, "/pairing/device/poll", {
            "request_id": started["request_id"],
            "device_secret": started["device_secret"],
        })
        status = result.get("status")
        if status == "active":
            print("Pareamento ativado pelo Gateway; acesso Restrito.", flush=True)
            return 0
        if status in ("denied", "expired"):
            raise PermissionError("pairing denied or expired")
        if status not in ("pending", "proven", "approved"):
            raise RuntimeError("unexpected pairing status")
    raise TimeoutError("pairing expired; restart to get a new code")


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental one-command Linux device-code pairing")
    parser.add_argument("--base-url", required=True, help="HTTPS Gateway URL or localhost test endpoint")
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--persistent", action="store_true", default=False)
    parser.add_argument("--state-dir", type=Path,
                        default=Path.home() / ".ssh" / "ai-lab-device-code")
    parser.add_argument("--host-key", type=Path, default=HOST_KEY)
    parser.add_argument("--no-wait", action="store_true", help="Only for staging protocol tests")
    args = parser.parse_args()
    try:
        return run(url=args.base_url, device_id=args.device_id,
                   name=args.name, persistent=args.persistent,
                   state_dir=args.state_dir, host_key_path=args.host_key,
                   wait=not args.no_wait)
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError,
            TimeoutError, OSError, urllib.error.URLError,
            subprocess.SubprocessError, TypeError, KeyError) as exc:
        print("PAREAMENTO_NAO_CONCLUIDO: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
