"""Restricted-first invitation state machine for Linux device enrollment v2.

No public HTTP route is exposed by this module. Network authentication,
human approval, SSH trust, device verification, installation and activation
must be supplied by the control plane before production enrollment.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import time

DEVICE_ID = re.compile(r"^[a-z][a-z0-9-]{2,47}$")
INVITE_TTL = 600
MAX_KEY_LENGTH = 1024


def _validate_public_key(value: str) -> str:
    """Validate one real ED25519 SSH public key, without exposing private keys."""
    if not isinstance(value, str) or "\n" in value or len(value) > MAX_KEY_LENGTH:
        raise ValueError("invalid SSH public key")
    fields = value.strip().split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise ValueError("only SSH Ed25519 public keys are accepted")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        if len(blob) != 51:
            raise ValueError("invalid Ed25519 SSH blob length")
        alg_length = struct.unpack(">I", blob[:4])[0]
        if alg_length != 11 or blob[4:15] != b"ssh-ed25519":
            raise ValueError("unexpected SSH public key algorithm")
        key_length = struct.unpack(">I", blob[15:19])[0]
        if key_length != 32 or len(blob[19:]) != 32:
            raise ValueError("unexpected SSH public key length")
    except (binascii.Error, struct.error) as exc:
        raise ValueError("invalid SSH public key encoding") from exc
    return "ssh-ed25519 " + fields[1]


def _digest(token: str) -> str:
    if not isinstance(token, str) or len(token) > 256:
        raise ValueError("invalid pairing token")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class EnrollmentStore:
    """Local transaction-safe pending invite registry.

    SQLite WAL and BEGIN IMMEDIATE make one-time invitation claiming
    atomic. Token hashes, not raw invitation tokens, are stored on disk.
    Onboarding ALWAYS starts Restricted; connection persistence is a
    separate independently selected boolean.
    """
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        with self._db() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS invites (
                token_hash TEXT PRIMARY KEY,
                operator_subject TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                device_id TEXT,
                device_name TEXT,
                tunnel_public_key TEXT,
                ssh_host_public_key TEXT,
                persistent INTEGER,
                claimed_at INTEGER
            )""")
            conn.execute("""CREATE UNIQUE INDEX IF NOT EXISTS one_live_request_per_device
                ON invites(device_id) WHERE state = 'pending'""")

    def _db(self):
        conn = sqlite3.connect(self.path, timeout=5)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def invite(self, operator_subject: str, *, now: int | None = None) -> str:
        if not isinstance(operator_subject, str) or not operator_subject.strip():
            raise ValueError("verified operator is required")
        moment = int(time.time()) if now is None else now
        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        with self._db() as db:
            db.execute("INSERT INTO invites (token_hash,operator_subject,created_at,"
                       "expires_at,state) VALUES (?,?,?,?,?)",
                       (digest, operator_subject, moment, moment+INVITE_TTL, "invited"))
        return token

    def claim(
        self,
        token: str, *,
        device_id: str, device_name: str,
        tunnel_public_key: str, ssh_host_public_key: str,
        persistent: bool, now: int | None = None,
    ) -> dict:
        """Use an invitation ONCE to request pairing; never activate here."""
        if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
            raise ValueError("invalid device id")
        if not isinstance(device_name, str) or not 1 <= len(device_name.strip()) <= 80:
            raise ValueError("invalid device name")
        if type(persistent) is not bool:
            raise ValueError("persistent must be a boolean")
        tunnel_key = _validate_public_key(tunnel_public_key)
        host_key = _validate_public_key(ssh_host_public_key)
        if tunnel_key == host_key:
            raise ValueError("tunnel and host SSH identity must be distinct")
        now_value = int(time.time()) if now is None else now
        digest = _digest(token)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,expires_at FROM invites WHERE token_hash=?", (digest,)
            ).fetchone()
            if row is None or row[0] != "invited" or now_value >= row[1]:
                raise PermissionError("invitation unavailable, already used or expired")
            try:
                changed = db.execute(
                    """UPDATE invites SET state='pending',device_id=?,device_name=?,
                       tunnel_public_key=?,ssh_host_public_key=?,persistent=?,claimed_at=?
                       WHERE token_hash=? AND state='invited'""",
                    (device_id, device_name.strip(), tunnel_key, host_key,
                     int(persistent), now_value, digest),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("device already has a pending pairing") from exc
            if changed.rowcount != 1:
                raise PermissionError("invitation was already claimed")
        return {
            "status": "pending", "device_id": device_id, "device_name": device_name.strip(),
            "access_mode": "restricted", "persistent": persistent,
            "tunnel_key_fingerprint": "SHA256:" + base64.b64encode(
                hashlib.sha256(base64.b64decode(tunnel_key.split()[1])).digest()
            ).decode().rstrip("="),
            "host_key_fingerprint": "SHA256:" + base64.b64encode(
                hashlib.sha256(base64.b64decode(host_key.split()[1])).digest()
            ).decode().rstrip("="),
        }
