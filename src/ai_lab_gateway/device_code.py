"""Offline-testable device-initiated enrollment core (ADR-029, NOT DEPLOYED).

A short, device-displayed user code is solely an Auth0-operator discovery
identifier. It cannot authorize the device or mint an SSH management key.
Separate high-entropy device secret authenticates polling; a signed challenge
proves possession of the target-generated Ed25519 tunnel key. Explicit human
consent is supplied only by a trusted boundary beyond the MCP model.

This module does NOT expose HTTP endpoints, grant sudo, manage SSH,
or edit the production device registry.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .enrollment import DEVICE_ID, _validate_public_key

VERSION = "ai-lab-device-code-v1"
# Exactly 32 symbols: 24 Latin uppercase letters without I/O + digits 2-9.
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
assert len(CODE_ALPHABET) == 32 and len(set(CODE_ALPHABET)) == 32
CODE_ENTROPY_BITS = 8 * 5
CODE_TTL = 600
MAX_PENDING_PER_SOURCE = 4
MAX_PENDING_PER_DEVICE = 1
MAX_SESSIONS = 10000
POLL_MIN_INTERVAL = 5
MAX_CODE_LOOKUPS_PER_PRINCIPAL = 16
MAX_CODE_LOOKUPS_GLOBAL = 100
CODE_LOOKUP_WINDOW = 600


def _digest_key(key: bytes, domain: bytes, data: str) -> str:
    return hmac.new(key, domain + b"\x00" + data.encode("ascii"), hashlib.sha256).hexdigest()


def _clean_code(code: str) -> str:
    if not isinstance(code, str) or len(code) > 24:
        raise ValueError("invalid code")
    cleaned = code.upper().replace("-", "").replace(" ", "")
    if len(cleaned) != 8 or any(c not in CODE_ALPHABET for c in cleaned):
        raise ValueError("invalid code")
    return cleaned


def _random_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))


def _ssh_ed25519_raw(key: str) -> bytes:
    canonical = _validate_public_key(key)
    data = base64.b64decode(canonical.split()[1], validate=True)
    return data[19:]


def _fingerprint(pubkey: str) -> str:
    blob = base64.b64decode(pubkey.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def _challenge(*, request_id: str, device_id: str, nonce: str,
               tunnel_public_key: str, host_public_key: str,
               persistent: bool, expires_at: int) -> bytes:
    # Versioned deterministic bytes; the device must sign the EXACT bytes.
    details = {
        "device_id": device_id,
        "expires_at": expires_at,
        "host_fingerprint": _fingerprint(host_public_key),
        "nonce": nonce,
        "persistent": persistent,
        "request_id": request_id,
        "role": "tunnel-key-possession",
        "tunnel_fingerprint": _fingerprint(tunnel_public_key),
        "version": VERSION,
    }
    return (json.dumps(details, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _display_confirm(challenge: bytes) -> str:
    # Human compares this compact fingerprint across *both* channels.
    h = hashlib.sha256(b"ai-lab-device-code-confirm-v1\x00" + challenge).digest()
    c = base64.b32encode(h[:5]).decode("ascii")
    return c[:4] + "-" + c[4:]


class DeviceCodeStore:
    def __init__(self, sqlite_path: str | Path, *, hmac_key: bytes):
        if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
            raise ValueError("a server-owned >=256-bit HMAC key is required")
        self.path = Path(sqlite_path)
        self.key = hmac_key
        # SQLite sidecars (journals/WAL) must be protected too, so require a
        # private directory owned by the service identity, not just a 0600 DB.
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_stat = self.path.parent.lstat()
        if (not stat.S_ISDIR(parent_stat.st_mode)
                or parent_stat.st_uid != os.geteuid()
                or stat.S_IMODE(parent_stat.st_mode) & 0o077):
            raise PermissionError("pairing database directory must be owner-only 0700")
        try:
            fd = os.open(str(self.path),
                         os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
        file_stat = self.path.lstat()
        if (not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.geteuid()
                or stat.S_IMODE(file_stat.st_mode) != 0o600):
            raise PermissionError("pairing SQLite file must be owner-only 0600")
        with closing(self._db()) as db, db:
            db.execute("""CREATE TABLE IF NOT EXISTS sessions(
              request_id TEXT PRIMARY KEY,
              code_digest TEXT UNIQUE NOT NULL,
              secret_digest TEXT UNIQUE NOT NULL,
              device_id TEXT NOT NULL,
              display_name TEXT NOT NULL,
              source_digest TEXT NOT NULL,
              tunnel_public_key TEXT NOT NULL,
              host_public_key TEXT NOT NULL,
              nonce TEXT NOT NULL,
              confirmation TEXT NOT NULL,
              persistent INTEGER NOT NULL,
              state TEXT NOT NULL,
              operator_subject TEXT,
              issued_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              proven_at INTEGER,
              reviewed_at INTEGER,
              activated_at INTEGER,
              last_poll INTEGER,
              provision_state TEXT NOT NULL DEFAULT 'not_provisioned'
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS code_lookups(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              principal_digest TEXT NOT NULL,
              attempted_at INTEGER NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS by_expiry ON sessions(expires_at)")
            db.execute("CREATE INDEX IF NOT EXISTS by_lookup_time ON code_lookups(attempted_at)")
            db.execute("CREATE INDEX IF NOT EXISTS by_source ON sessions(source_digest)")

    def _db(self):
        db = sqlite3.connect(str(self.path), isolation_level=None, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def start(self, *, device_id: str, display_name: str,
              tunnel_public_key: str, host_public_key: str,
              persistent: bool, source_id: str, now: int | None = None) -> dict:
        """Anonymous device initiation: returns terminal-only credentials."""
        if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
            raise ValueError("invalid device id")
        if not isinstance(display_name, str) or not 1 <= len(display_name.strip()) <= 80:
            raise ValueError("invalid device name")
        if type(persistent) is not bool:
            raise ValueError("persistent must be a boolean")
        if not isinstance(source_id, str) or not 1 <= len(source_id) <= 200:
            raise ValueError("invalid source id")
        tunnel = _validate_public_key(tunnel_public_key)
        host = _validate_public_key(host_public_key)
        if tunnel == host:
            raise ValueError("SSH host key must not equal tunnel key")
        moment = int(time.time()) if now is None else now
        source_digest = _digest_key(self.key, b"source", source_id)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("UPDATE sessions SET state='expired' WHERE expires_at<=? "
                           "AND state IN ('pending','proven','approved')", (moment,))
                source_count = db.execute(
                    "SELECT count(*) FROM sessions WHERE source_digest=? "
                    "AND expires_at>? AND state IN ('pending','proven','approved')",
                    (source_digest, moment)).fetchone()[0]
                device_count = db.execute(
                    "SELECT count(*) FROM sessions WHERE device_id=? "
                    "AND expires_at>? AND state IN ('pending','proven','approved')",
                    (device_id, moment)).fetchone()[0]
                total_count = db.execute(
                    "SELECT count(*) FROM sessions WHERE expires_at>? "
                    "AND state IN ('pending','proven','approved')",
                    (moment,)).fetchone()[0]
                if source_count >= MAX_PENDING_PER_SOURCE or device_count >= MAX_PENDING_PER_DEVICE or total_count >= MAX_SESSIONS:
                    raise PermissionError("pairing attempt quota reached")
                code = _random_code()
                request_id = secrets.token_urlsafe(18)
                secret = secrets.token_urlsafe(32)
                nonce = secrets.token_urlsafe(24)
                expiry = moment + CODE_TTL
                challenge = _challenge(
                    request_id=request_id, device_id=device_id, nonce=nonce,
                    tunnel_public_key=tunnel, host_public_key=host,
                    persistent=persistent, expires_at=expiry)
                confirmation = _display_confirm(challenge)
                db.execute("""INSERT INTO sessions (
                    request_id,code_digest,secret_digest,device_id,display_name,
                    source_digest,tunnel_public_key,host_public_key,nonce,
                    confirmation,persistent,state,issued_at,expires_at
                 ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    request_id, _digest_key(self.key, b"code", code),
                    _digest_key(self.key, b"device", secret),
                    device_id, display_name.strip(), source_digest,
                    tunnel, host, nonce, confirmation, int(persistent),
                    "pending", moment, expiry))
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {
            "request_id": request_id, "user_code": code[:4]+"-"+code[4:],
            "device_secret": secret, "expires_at": expiry,
            "challenge_b64": base64.b64encode(challenge).decode("ascii"),
            "confirmation": confirmation, "status": "pending",
            "access_mode": "restricted", "persistent": persistent,
        }

    def prove(self, *, request_id: str, device_secret: str,
              signature_b64: str, now: int | None = None) -> dict:
        """Only a valid Ed25519 signature over our challenge advances pending."""
        moment = int(time.time()) if now is None else now
        row = self._get_device_row(request_id, device_secret)
        if row["state"] != "pending" or moment >= row["expires_at"]:
            raise PermissionError("not pending or expired")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except (ValueError, TypeError) as exc:
            raise PermissionError("invalid possession signature") from exc
        if len(signature) != 64:
            raise PermissionError("invalid possession signature")
        challenge = _challenge(
            request_id=row["request_id"], device_id=row["device_id"],
            nonce=row["nonce"], tunnel_public_key=row["tunnel_public_key"],
            host_public_key=row["host_public_key"],
            persistent=bool(row["persistent"]), expires_at=row["expires_at"])
        try:
            Ed25519PublicKey.from_public_bytes(
                _ssh_ed25519_raw(row["tunnel_public_key"])).verify(signature, challenge)
        except (InvalidSignature, ValueError) as exc:
            raise PermissionError("device key-possession proof failed") from exc
        with closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE sessions SET state='proven',proven_at=? "
                "WHERE request_id=? AND secret_digest=? AND state='pending' "
                "AND expires_at>?",
                (moment, request_id, _digest_key(self.key,b"device",device_secret),moment))
            if changed.rowcount != 1:
                raise PermissionError("proof already consumed or expired")
            db.commit()
        return {"request_id": request_id, "status": "proven",
                "access_mode": "restricted"}

    def _get_device_row(self, request_id: str, device_secret: str):
        if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}",request_id):
            raise PermissionError("invalid device request")
        if not isinstance(device_secret, str) or not re.fullmatch(r"[A-Za-z0-9_-]{40,128}",device_secret):
            raise PermissionError("invalid device proof")
        with closing(self._db()) as db:
            row = db.execute(
                "SELECT * FROM sessions WHERE request_id=? AND secret_digest=?",
                (request_id, _digest_key(self.key, b"device", device_secret))).fetchone()
        if row is None:
            raise PermissionError("device session unavailable")
        return row

    def poll(self, *, request_id: str, device_secret: str,
             now: int | None = None) -> dict:
        """Polling never returns SSH keys or the matched user's identity."""
        moment = int(time.time()) if now is None else now
        self._get_device_row(request_id,device_secret)
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT state,expires_at,last_poll FROM sessions "
                "WHERE request_id=? AND secret_digest=?",
                (request_id,_digest_key(self.key,b"device",device_secret))).fetchone()
            if row is None:
                raise PermissionError("device session unavailable")
            if row["last_poll"] is not None and moment-row["last_poll"] < POLL_MIN_INTERVAL:
                raise PermissionError("polling too frequent")
            db.execute("UPDATE sessions SET last_poll=? WHERE request_id=?",
                       (moment,request_id))
            status = row["state"] if moment < row["expires_at"] else (
                "active" if row["state"]=="active" else "expired")
            db.commit()
        return {"status":status,"request_id":request_id,
                "access_mode":"restricted"}

    def lookup(self, *, user_code: str, operator_subject: str,
               now: int | None = None) -> dict:
        """An OAuth-authorized operator can discover and reserve a code.

        Caller MUST already have gateway:control + device_enroll.
        Unknown and unauthorized codes both fail without disclosing details.
        """
        if not isinstance(operator_subject,str) or not 1<=len(operator_subject)<=256:
            raise ValueError("invalid operator subject")
        moment=int(time.time()) if now is None else now
        normalized=_clean_code(user_code)
        principal_digest=_digest_key(self.key,b"principal",operator_subject)
        # Record each GUESS (including failed lookups) in a separate committed
        # transaction: a rollback on unknown code must not erase rate limits.
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM code_lookups WHERE attempted_at<=?",
                       (moment-CODE_LOOKUP_WINDOW,))
            per_user=db.execute(
                "SELECT count(*) FROM code_lookups WHERE principal_digest=?",
                (principal_digest,)).fetchone()[0]
            total=db.execute("SELECT count(*) FROM code_lookups").fetchone()[0]
            if per_user>=MAX_CODE_LOOKUPS_PER_PRINCIPAL or total>=MAX_CODE_LOOKUPS_GLOBAL:
                db.commit()
                raise PermissionError("pairing code lookup quota exceeded")
            db.execute("INSERT INTO code_lookups(principal_digest,attempted_at) "
                       "VALUES (?,?)",(principal_digest,moment))
            db.commit()
        with closing(self._db()) as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT request_id,device_id,display_name,"
                           "tunnel_public_key,host_public_key,confirmation,"
                           "persistent,operator_subject,state,expires_at "
                           "FROM sessions WHERE code_digest=?",
                           (_digest_key(self.key,b"code",normalized),)).fetchone()
            if (row is None or row["state"]!="proven" or
                  row["expires_at"]<=moment or
                  row["operator_subject"] not in (None,operator_subject)):
                raise PermissionError("pairing code unavailable")
            changed=db.execute(
                "UPDATE sessions SET operator_subject=? WHERE request_id=? "
                "AND state='proven' AND expires_at>? "
                "AND (operator_subject IS NULL OR operator_subject=?)",
                (operator_subject,row["request_id"],moment,operator_subject))
            if changed.rowcount!=1:
                raise PermissionError("pairing code unavailable")
            db.commit()
        return {
            "request_id":row["request_id"],"device_id":row["device_id"],
            "device_name":row["display_name"],"confirmation":row["confirmation"],
            "tunnel_fingerprint":_fingerprint(row["tunnel_public_key"]),
            "host_fingerprint":_fingerprint(row["host_public_key"]),
            "persistent":bool(row["persistent"]),"status":"awaiting_human_confirmation",
            "access_mode":"restricted",
        }

    def confirm(self, *, request_id: str, operator_subject: str,
                confirmation: str, consent_verified: bool = False,
                now: int | None = None) -> dict:
        """Trusted service ONLY: caller must independently verify human consent.

        Never map a model-supplied flag or text to consent_verified=True.
        """
        if consent_verified is not True:
            raise PermissionError("independent human consent evidence is required")
        if not isinstance(operator_subject,str) or not operator_subject:
            raise PermissionError("verified Auth0 operator required")
        moment=int(time.time()) if now is None else now
        with closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT confirmation FROM sessions WHERE "
                           "request_id=? AND operator_subject=? AND state='proven' "
                           "AND expires_at>?",(request_id,operator_subject,moment)).fetchone()
            if not row or not isinstance(confirmation,str) or not hmac.compare_digest(
                row["confirmation"],confirmation):
                raise PermissionError("request is unavailable or confirmation mismatched")
            db.execute("UPDATE sessions SET state='approved',reviewed_at=? "
                       "WHERE request_id=? AND operator_subject=? AND state='proven'",
                       (moment,request_id,operator_subject))
            db.commit()
        return {"request_id":request_id,"status":"approved","access_mode":"restricted"}

    def deny(self, *, request_id: str, operator_subject: str,
             now: int | None = None) -> dict:
        moment=int(time.time()) if now is None else now
        with closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            changed=db.execute("UPDATE sessions SET state='denied',reviewed_at=? "
                               "WHERE request_id=? AND operator_subject=? "
                               "AND state='proven' AND expires_at>?",
                               (moment,request_id,operator_subject,moment))
            if changed.rowcount!=1:
                raise PermissionError("pending request not owned by principal")
            db.commit()
        return {"request_id":request_id,"status":"denied"}

    def activate(self, *, request_id: str, provisioner_verified: bool = False,
                 now: int | None = None) -> dict:
        """Root-only adapter must enforce exact SSH acceptance before invoking."""
        if provisioner_verified is not True:
            raise PermissionError("trusted SSH acceptance required")
        moment=int(time.time()) if now is None else now
        with closing(self._db()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            changed=db.execute("UPDATE sessions SET state='active',"
                               "provision_state='verified',activated_at=? "
                               "WHERE request_id=? AND state='approved' AND expires_at>?",
                               (moment,request_id,moment))
            if changed.rowcount!=1:
                raise PermissionError("unavailable, already active or expired")
            db.commit()
        return {"request_id":request_id,"status":"active","access_mode":"restricted"}
