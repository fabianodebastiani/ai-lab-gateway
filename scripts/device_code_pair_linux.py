#!/usr/bin/env python3
"""Experimental Linux device-code pairing CLI (ADR-029, NOT installed/live).

A fresh Linux device needs Python 3.10+ and OpenSSH ssh-keygen only for
this handshake. No Python third-party cryptography is required on the target. All HTTPS requests are
outbound; no existing Gateway SSH connection, device account, or sudo is used.
The CLI ONLY creates a pending, proven device session and polls its state.
It CANNOT approve, activate, install systemd, or grant Linux permissions.

Do not paste tokens into a terminal or use an unverified curl|sudo shell.
"""
from __future__ import annotations

import argparse
import fcntl
import pwd
import base64
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "ai-lab-device-code-v1"
OFFER_VERSION = "ai-lab-ssh-offer-v1"
OFFER_FIELDS = frozenset({"version", "request_id", "device_id", "access_mode",
    "persistent", "gateway_host", "gateway_ssh_port", "gateway_tunnel_user",
    "gateway_ssh_host_key", "gateway_management_public_key", "reverse_listen_host",
    "reverse_listen_port", "management_user", "device_tunnel_fingerprint",
    "device_host_fingerprint"})
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{2,47}$")
CODE_PATTERN = re.compile(r"^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$")
HOST_KEY = None  # generated per-device locally unless --host-key is explicitly provided
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



def load_trusted_gateway_host_key(path: Path | None) -> str:
    """Read a locally protected pin, not a key from the enrollment response."""
    if path is None:
        raise PermissionError("trusted Gateway SSH host key is required")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022):
        raise PermissionError("untrusted Gateway SSH host key pin file")
    raw = path.read_bytes()
    if len(raw) > 1024:
        raise ValueError("oversized SSH host key pin")
    return ed25519_public(raw.decode("ascii").strip())


def validate_connection_offer(offer: object, *, request_id: str,
                              device_id: str, persistent: bool, tunnel_key: str,
                              host_key: str, trusted_gateway_host_key: str) -> dict:
    """Validate a candidate public offer. NEVER install SSH configuration."""
    if not isinstance(offer, dict) or frozenset(offer) != OFFER_FIELDS:
        raise ValueError("unexpected SSH offer fields")
    expected = {
        "version": OFFER_VERSION, "request_id": request_id,
        "device_id": device_id, "access_mode": "restricted",
        "persistent": persistent, "gateway_host": "gateway.debasti.com",
        "gateway_ssh_port": 22, "gateway_tunnel_user": "tunnel",
        "reverse_listen_host": "127.0.0.1", "management_user": "ai-gateway",
        "device_tunnel_fingerprint": fingerprint(ed25519_public(tunnel_key)),
        "device_host_fingerprint": fingerprint(ed25519_public(host_key)),
    }
    for name, value in expected.items():
        if type(offer[name]) is not type(value) or offer[name] != value:
            raise PermissionError("SSH offer does not match verified device request")
    port = offer["reverse_listen_port"]
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("invalid reverse SSH listener port")
    pin = ed25519_public(trusted_gateway_host_key)
    for name in ("gateway_ssh_host_key", "gateway_management_public_key"):
        canonical = ed25519_public(offer[name])
        if offer[name] != canonical:
            raise ValueError("noncanonical SSH public key")
    if offer["gateway_ssh_host_key"] != pin:
        raise PermissionError("Gateway SSH identity differs from trusted key pin")
    if offer["gateway_management_public_key"] == pin:
        raise PermissionError("Gateway management and SSH host keys must differ")
    if len(json.dumps(offer, sort_keys=True)) > MAX_REPLY:
        raise ValueError("oversized SSH offer")
    return dict(offer)


def validate_poll_response(response: object, *, request_id: str,
                           device_id: str, persistent: bool,
                           tunnel_key: str, host_key: str,
                           trusted_gateway_host_key: str | None) -> dict | None:
    """Check session binding and optional offer before acting on poll state."""
    if not isinstance(response, dict):
        raise ValueError("invalid poll response")
    fields = {"status", "request_id", "access_mode"}
    if (not fields <= response.keys()
            or not response.keys() <= fields | {"connection_offer"}
            or response["request_id"] != request_id
            or response["access_mode"] != "restricted"):
        raise PermissionError("unbound pairing poll response")
    status = response["status"]
    if status not in ("pending", "proven", "approved", "active", "denied", "expired"):
        raise ValueError("unexpected pairing status")
    if "connection_offer" not in response:
        if status == "active":
            raise PermissionError("activation without verified SSH offer")
        return None
    if status not in ("approved", "active"):
        raise PermissionError("SSH offer delivered before device approval")
    if trusted_gateway_host_key is None:
        raise PermissionError("SSH offer requires an independently trusted host key")
    return validate_connection_offer(
        response["connection_offer"], request_id=request_id,
        device_id=device_id, persistent=persistent, tunnel_key=tunnel_key,
        host_key=host_key, trusted_gateway_host_key=trusted_gateway_host_key)


def stage_local_candidate(offer: dict, *, state_dir: Path, request_id: str,
                          device_id: str, persistent: bool,
                          tunnel_key: str, host_key: str,
                          trusted_gateway_host_key: str) -> Path:
    """Stage public target-side SSH fragments, without installing anything.

    No sudo, authorized_keys edits, sshd/systemd changes or running SSH.
    A separately approved local administrator must later verify and install
    the fragments using a narrow, auditable installer.
    """
    normalized = validate_connection_offer(
        offer, request_id=request_id, device_id=device_id,
        persistent=persistent, tunnel_key=tunnel_key, host_key=host_key,
        trusted_gateway_host_key=trusted_gateway_host_key)
    if os.geteuid() == 0:
        raise PermissionError("candidate preparation must run without root")
    if not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", request_id):
        raise ValueError("invalid pairing request identifier")
    owned_private_dir(state_dir.parent)
    owned_private_dir(state_dir)
    destination = state_dir / ("candidate-" + request_id)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("candidate artifacts already exist")
    tempdir = Path(tempfile.mkdtemp(prefix=".candidate-", dir=state_dir))
    try:
        def write(name: str, data: str):
            with open(tempdir / name, "xb") as out:
                os.fchmod(out.fileno(), 0o600)
                out.write(data.encode("utf-8"))
                out.flush()
                os.fsync(out.fileno())
        write("offer.json", json.dumps(normalized, sort_keys=True, indent=2) + "\n")
        write("management-authorized_keys.append",
              normalized["gateway_management_public_key"] + "\n")
        write("gateway-known_hosts.append",
              normalized["gateway_host"] + " " +
              normalized["gateway_ssh_host_key"] + "\n")
        write("STAGING_ONLY",
              "Not installed. Target sshd, host key, service, sudoers and "
              "authorized_keys remain unchanged.\n")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("candidate artifacts already exist")
        tempdir.rename(destination)
    finally:
        if tempdir.exists():
            shutil.rmtree(tempdir)
    return destination


def owned_private_dir(path: Path):
    if path.is_symlink():
        raise PermissionError("refusing symlinked key directory")
    if not path.exists():
        path.mkdir(mode=0o700)
    st = path.stat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise PermissionError("private key directory must be mode 0700, owned by current user")


def _generate_identity(path: Path, *, comment: str) -> str:
    """Create/reuse Ed25519 identity only inside a private state directory."""
    pub = Path(str(path) + ".pub")
    if not path.exists() and not pub.exists() and not path.is_symlink() and not pub.is_symlink():
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
             "-f", str(path), "-C", comment],
            timeout=20, check=True, capture_output=True)
        path.chmod(0o600)
        pub.chmod(0o600)
    if (path.is_symlink() or pub.is_symlink() or not path.is_file() or not pub.is_file()):
        raise PermissionError("missing, partial or symlinked Ed25519 identity")
    for file in (path, pub):
        st = file.stat()
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
            raise PermissionError("device identity must be owner-only 0600")
    return ed25519_public(pub.read_text(encoding="ascii"))


def local_keys(state_dir: Path, *, host_key_path: Path | None = HOST_KEY):
    if os.geteuid() == 0:
        raise PermissionError("pairing must run as an unprivileged Linux user")
    owned_private_dir(state_dir.parent)
    owned_private_dir(state_dir)
    private = state_dir / "tunnel-ed25519"
    tunnel = _generate_identity(private, comment="ai-lab-device-code-tunnel")
    if host_key_path is None:
        # The fresh target need not have root access or a running sshd yet.
        # A dedicated host identity is created locally for later provisioning.
        host = _generate_identity(state_dir / "host-ed25519",
                                  comment="ai-lab-device-code-host")
    else:
        if not host_key_path.is_file() or host_key_path.is_symlink():
            raise FileNotFoundError("provided host Ed25519 public key is missing")
        host = ed25519_public(host_key_path.read_text(encoding="ascii"))
    if tunnel == host:
        raise ValueError("tunnel and host SSH identities must be independent")
    return private, tunnel, host

def automatic_device_id(state_dir: Path, *, hostname: str | None = None) -> str:
    """One generated stable device ID for this local keypair, no account input."""
    owned_private_dir(state_dir.parent)
    owned_private_dir(state_dir)
    marker = state_dir / "device-id"
    if not marker.exists() and not marker.is_symlink():
        base = hostname or socket.gethostname()
        label = re.sub(r"[^a-z0-9-]+", "-", base.lower()).strip("-")
        if not label or label[0] not in "abcdefghijklmnopqrstuvwxyz":
            label = "linux-" + label
        candidate = label[:36].strip("-") + "-" + secrets.token_hex(4)
        if not ID_PATTERN.fullmatch(candidate):
            raise ValueError("invalid generated device id")
        try:
            fd = os.open(str(marker), os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(candidate + "\n")
                stream.flush()
                os.fsync(stream.fileno())
    if marker.is_symlink() or not marker.is_file():
        raise PermissionError("invalid local device ID file")
    st = marker.stat()
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o600:
        raise PermissionError("device ID file must be owner-only 0600")
    value = marker.read_text(encoding="ascii").strip()
    if not ID_PATTERN.fullmatch(value):
        raise ValueError("invalid persisted device ID")
    return value


class _RejectPairingRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a device secret or proof to a redirect target."""
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise PermissionError("pairing HTTP redirects are forbidden")


_PAIRING_HTTP = urllib.request.build_opener(_RejectPairingRedirect)


def post(url: str, path: str, data: dict) -> dict:
    endpoint = base_url(url) + path
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    if len(payload) > 4096:
        raise ValueError("oversized pairing payload")
    request = urllib.request.Request(endpoint, data=payload, method="POST",
             headers={"Content-Type": "application/json", "Accept": "application/json"})
    with _PAIRING_HTTP.open(request, timeout=10) as response:
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
    comparison_std = base64.b32encode(hashlib.sha256(
        b"ai-lab-device-code-confirm-v1\x00" + challenge).digest()[:5]).decode("ascii")
    standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    comparison = "".join(CODE_ALPHABET[standard.index(letter)]
                         for letter in comparison_std)
    if reply.get("confirmation") != comparison[:4] + "-" + comparison[4:]:
        raise ValueError("display confirmation mismatch")
    return challenge




def _active_target_sshd_key() -> str:
    """Query the actual local SSH daemon, never a generated unused host key."""
    result = subprocess.run(
        ["ssh-keyscan", "-T", "4", "-t", "ed25519", "-p", "22", "127.0.0.1"],
        capture_output=True, text=True, timeout=8, check=False)
    keys = set()
    for line in result.stdout.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) == 3 and parts[1] == "ssh-ed25519":
            keys.add(ed25519_public(" ".join(parts[1:])))
    if len(keys) != 1:
        raise PermissionError("local SSH server is absent or has ambiguous host key")
    return keys.pop()


def _user_owned_ssh_authorizations(ssh_dir: Path, management_key: str) -> None:
    """Insert one exact Gateway public key, never a private key or sudo rule."""
    owned_private_dir(ssh_dir)
    path = ssh_dir / "authorized_keys"
    if path.is_symlink():
        raise PermissionError("refusing symlinked target authorized_keys")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise PermissionError("untrusted authorized_keys")
        if stat.S_IMODE(info.st_mode) not in (0o600, 0o644):
            raise PermissionError("unsafe authorized_keys mode")
        original = path.read_bytes()
    else:
        original = b""
    if len(original) > 128 * 1024:
        raise PermissionError("authorized_keys exceeds limit")
    key_line = ed25519_public(management_key).encode("ascii")
    existing_lines = [line.split(b" ", 2)[:2] for line in original.splitlines()]
    key_parts = key_line.split(b" ", 1)
    if key_parts not in existing_lines:
        payload = original + (b"\n" if original and not original.endswith(b"\n") else b"") + key_line + b"\n"
    else:
        payload = original
    # The old keys are retained; the target's SSH identity is unchanged.
    tmp = ssh_dir / ".ai-lab-approved-key.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def activate_verified_on_demand_tunnel(*, offer: dict, state_dir: Path,
                                       tunnel_key_path: Path,
                                       signed_host_public_key: str,
                                       gateway_host_pin: str) -> str:
    """Start ordinary non-root, WSL-like outbound reverse SSH after approval.

    No arbitrary command, SSH port, key or privileged mode comes from the
    remote model. The offer must already have passed validate_connection_offer.
    For now this is the on-demand, existing-sshd Unix-user path only.
    """
    if os.geteuid() == 0:
        raise PermissionError("device activation must not run as root")
    if offer["persistent"] is not False or offer["access_mode"] != "restricted":
        raise PermissionError("this client can activate only Restricted on-demand")
    if offer["management_user"] != pwd.getpwuid(os.getuid()).pw_name:
        raise PermissionError("management SSH user differs from installer user")
    if ed25519_public(signed_host_public_key) != _active_target_sshd_key():
        raise PermissionError("device identity does not match active local sshd")
    if ed25519_public(offer["gateway_ssh_host_key"]) != ed25519_public(gateway_host_pin):
        raise PermissionError("Gateway host key differs from independently pinned key")
    if not tunnel_key_path.is_file() or tunnel_key_path.is_symlink():
        raise PermissionError("missing device tunnel private key")
    key_info = tunnel_key_path.stat()
    if key_info.st_uid != os.getuid() or stat.S_IMODE(key_info.st_mode) != 0o600:
        raise PermissionError("untrusted device tunnel private key")
    owned_private_dir(state_dir)
    lock = state_dir / "activation.lock"
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "rb", closefd=False):
            fcntl.flock(fd, fcntl.LOCK_EX)
            ssh_dir = Path.home() / ".ssh"
            _user_owned_ssh_authorizations(
                ssh_dir, offer["gateway_management_public_key"])
            pin = state_dir / "trusted-gateway-known_hosts"
            line = (offer["gateway_host"] + " " +
                    ed25519_public(offer["gateway_ssh_host_key"]) + "\n").encode("ascii")
            if pin.exists() or pin.is_symlink():
                if pin.is_symlink() or pin.read_bytes() != line:
                    raise PermissionError("untrusted or changed Gateway host pin")
            else:
                pin_fd = os.open(pin, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(pin_fd, "wb") as output:
                    output.write(line)
                    output.flush()
                    os.fsync(output.fileno())
            unit = "ai-lab-device-" + offer["device_id"]
            argv = [
                "systemd-run", "--user", "--collect", "--unit=" + unit,
                "--property=Restart=on-failure", "--property=RestartSec=5s",
                "/usr/bin/ssh", "-N", "-T",
                "-i", str(tunnel_key_path),
                "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes",
                "-o", "StrictHostKeyChecking=yes",
                "-o", "ExitOnForwardFailure=yes",
                "-o", "ServerAliveInterval=30",
                "-o", "ServerAliveCountMax=3",
                "-o", "UserKnownHostsFile=" + str(pin),
                "-R", "127.0.0.1:" + str(offer["reverse_listen_port"]) + ":127.0.0.1:22",
                offer["gateway_tunnel_user"] + "@" + offer["gateway_host"],
            ]
            subprocess.run(argv, check=True, capture_output=True, timeout=15)
            return unit
    finally:
        os.close(fd)


def run(*, url: str, device_id: str, name: str, persistent: bool,
        state_dir: Path, host_key_path: Path, wait: bool,
        trusted_gateway_host_key_path: Path | None = None) -> int:
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
    # OpenSSH's SSHSIG signs the canonical gateway challenge using only
    # ssh-keygen; no Python cryptography dependency is needed on Linux.
    signed = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-n", "ai-lab-gateway-device-code",
         "-f", str(private)],
        input=challenge, capture_output=True, timeout=20, check=True)
    armor = signed.stdout.decode("ascii")
    if (len(armor) > 2048 or not armor.startswith("-----BEGIN SSH SIGNATURE-----")
            or not armor.strip().endswith("-----END SSH SIGNATURE-----")):
        raise ValueError("unexpected OpenSSH signature response")
    verified = post(target_url, "/pairing/device/prove", {
        "request_id": started["request_id"],
        "device_secret": started["device_secret"],
        "sshsig": armor,
    })
    if (verified.get("status") != "proven"
            or verified.get("request_id") != started["request_id"]
            or verified.get("access_mode") != "restricted"):
        raise RuntimeError("gateway did not accept proof of key possession")
    print("AI Lab Gateway — Vincular dispositivo", flush=True)
    print("Linux:", name, flush=True)
    print("Código:", started["user_code"], flush=True)
    print("No ChatGPT: Conectar dispositivo " + started["user_code"], flush=True)
    print("Aguardando autorização... (acesso inicial Restrito)", flush=True)
    if not wait:
        print("Laboratório: a sessão foi criada e provada; ainda não ativa.", flush=True)
        return 0
    trusted_key = (load_trusted_gateway_host_key(trusted_gateway_host_key_path)
                   if trusted_gateway_host_key_path is not None else None)
    prior_offer = None
    while time.time() < started["expires_at"]:
        time.sleep(POLL_SECONDS)
        result = post(target_url, "/pairing/device/poll", {
            "request_id": started["request_id"],
            "device_secret": started["device_secret"],
        })
        offer = validate_poll_response(
            result, request_id=started["request_id"], device_id=device_id,
            persistent=persistent, tunnel_key=tunnel, host_key=host,
            trusted_gateway_host_key=trusted_key)
        if offer is not None:
            if prior_offer is not None and offer != prior_offer:
                raise PermissionError("SSH offer changed after initial acceptance")
            if prior_offer is None:
                stage_path = stage_local_candidate(
                    offer, state_dir=state_dir, request_id=started["request_id"],
                    device_id=device_id, persistent=persistent,
                    tunnel_key=tunnel, host_key=host,
                    trusted_gateway_host_key=trusted_key)
                print("Oferta SSH validada; arquivos candidatos em: " +
                      str(stage_path), flush=True)
                print("Preparando conexão SSH restrita...", flush=True)
                unit = activate_verified_on_demand_tunnel(
                    offer=offer, state_dir=state_dir,
                    tunnel_key_path=private, signed_host_public_key=host,
                    gateway_host_pin=trusted_key)
                print("Túnel iniciado pelo usuário Linux: " + unit, flush=True)
                print("Aguardando verificação independente pelo Gateway...", flush=True)
            prior_offer = offer
        status = result["status"]
        if status == "active":
            if prior_offer is None:
                raise PermissionError("activation without verified SSH offer")
            print("Gateway marcou pareamento ativo; acesso Restrito.", flush=True)
            return 0
        if status in ("denied", "expired"):
            raise PermissionError("pairing denied or expired")
        if status not in ("pending", "proven", "approved"):
            raise RuntimeError("unexpected pairing status")
    raise TimeoutError("pairing expired; restart to get a new code")


def main() -> int:
    parser = argparse.ArgumentParser(description="Experimental one-command Linux device-code pairing")
    parser.add_argument("--base-url", required=True, help="HTTPS Gateway URL or localhost test endpoint")
    parser.add_argument("--device-id", help="Optional, generated and saved on first run")
    parser.add_argument("--name", default=socket.gethostname())
    parser.add_argument("--persistent", action="store_true", default=False)
    parser.add_argument("--state-dir", type=Path,
                        default=Path.home() / ".ssh" / "ai-lab-device-code")
    parser.add_argument("--host-key", type=Path, default=HOST_KEY,
                        help="Actual sshd Ed25519 host public key, not a generated substitute")
    parser.add_argument("--trusted-gateway-host-key", type=Path,
                        help="Independent SSH host public key pin obtained securely")
    parser.add_argument("--no-wait", action="store_true", help="Only for staging protocol tests")
    args = parser.parse_args()
    try:
        device_id = args.device_id or automatic_device_id(args.state_dir)
        # Prefer the real SSH server identity on an already configured Linux.
        # A generated fallback is only provisional: no SSH activation until
        # sshd is locally provisioned with that identity.
        system_host = Path("/etc/ssh/ssh_host_ed25519_key.pub")
        actual_host = args.host_key
        if (actual_host is None and args.base_url.startswith("https://")
                and system_host.is_file() and not system_host.is_symlink()):
            actual_host = system_host
        return run(url=args.base_url, device_id=device_id,
                   name=args.name, persistent=args.persistent,
                   state_dir=args.state_dir, host_key_path=actual_host,
                   wait=not args.no_wait,
                   trusted_gateway_host_key_path=args.trusted_gateway_host_key)
    except (ValueError, PermissionError, FileNotFoundError, RuntimeError,
            TimeoutError, OSError, urllib.error.URLError,
            subprocess.SubprocessError, TypeError, KeyError) as exc:
        print("PAREAMENTO_NAO_CONCLUIDO: " + type(exc).__name__ + ": " + str(exc),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
