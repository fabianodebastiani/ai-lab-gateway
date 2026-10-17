"""Stage 5 isolated issuer: independently attested Partial grant and short lease.

SOURCE-ONLY LABORATORY. No MCP, SSH, real human approver, deployment or sudo.
A future independent human approval service MUST hold a separate signing key.
A future trusted OAuth boundary MUST supply expected_subject, never model text.
The issuer cannot assert proof of a human solely from a chat message.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
from typing import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .signed_profile_grants import (
    VERSION as GRANT_VERSION, DURATIONS, DOMAIN as GRANT_DOMAIN,
    canonical_grant_bytes, verify_signed_grant,
)
from .profile_lease_state import (
    LEASE_VERSION, CAPABILITY, MAX_LEASE_SECONDS, LEASE_DOMAIN,
    BOOT_ID_PATTERN, canonical_lease_bytes, verify_short_lease,
)

APPROVAL_VERSION = 'ai-lab-human-profile-consent-v1'
APPROVAL_DOMAIN = b'AI-LAB-HUMAN-PROFILE-CONSENT-V1\x00'
RENEWAL_VERSION = 'ai-lab-device-lease-request-v1'
RENEWAL_DOMAIN = b'AI-LAB-DEVICE-LEASE-REQUEST-V1\x00'
MAX_CONSENT_AGE = 120
MAX_REQUEST_AGE = 90
MAX_PACKET = 4096
MAX_CLOCK_SKEW = 30
ID = re.compile(r'[a-f0-9]{64}\Z')
DEVICE = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')
CONSENT_KEYS = frozenset((
    'version', 'decision_id', 'device_id', 'subject', 'approved_by',
    'approval_method', 'mode', 'duration_seconds', 'capabilities',
    'decided_at', 'expires_at', 'confirmed',
))
REQUEST_KEYS = frozenset((
    'version', 'request_id', 'device_id', 'subject', 'grant_id',
    'generation', 'capability', 'boot_id', 'requested_at',
))
CONSENT_METHODS = frozenset(('separate_human_root_console', 'separate_human_web_ui'))


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _decode(raw: bytes, expected: str, keys: frozenset) -> tuple[dict, bytes]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PACKET:
        raise ValueError('invalid signed packet length')
    envelope = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError('JSON constant')))
    if not isinstance(envelope, dict) or set(envelope) != {expected, 'signature'}:
        raise ValueError('invalid envelope')
    payload, signature = envelope[expected], envelope['signature']
    if not isinstance(payload, dict) or set(payload) != keys:
        raise ValueError('invalid signed fields')
    if not isinstance(signature, str) or len(signature) > 120:
        raise ValueError('invalid signature encoding')
    try:
        decoded = base64.b64decode(signature, validate=True)
    except ValueError as exc:
        raise ValueError('invalid signature encoding') from exc
    except Exception as exc:
        raise ValueError('invalid base64 signature') from exc
    if len(decoded) != 64 or base64.b64encode(decoded).decode('ascii') != signature:
        raise ValueError('noncanonical Ed25519 signature')
    return payload, decoded


def _canonical(domain: bytes, payload: dict) -> bytes:
    return domain + (json.dumps(payload, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def _verify(key: bytes, body: bytes, signature: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise PermissionError('trusted authority key missing')
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, body)
    except InvalidSignature as exc:
        raise PermissionError('invalid independent signature') from exc


def _signed(label: str, payload: dict, private: Ed25519PrivateKey, domain: bytes) -> bytes:
    sig = private.sign(_canonical(domain, payload))
    return json.dumps({label: payload, 'signature': base64.b64encode(sig).decode('ascii')},
                      separators=(',', ':')).encode('ascii')


def _pub(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _subject(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and all(33 <= ord(x) <= 126 for x in value)


def _now(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError('invalid trusted time')
    return value


class ProfileLeaseIssuerLab:
    """A root-only durable ledger, isolated from all deployed broker services.

    Keys and authenticated subject must be supplied by separately trusted
    adapters; they are NOT loaded or provisioned by this prototype.
    """
    def __init__(self, root_directory: Path, *, issuer_key: Ed25519PrivateKey,
                 human_approval_key: bytes, device_keys: dict[str, bytes]):
        if not isinstance(issuer_key, Ed25519PrivateKey):
            raise ValueError('a trusted issuer signing key is required')
        if not isinstance(human_approval_key, bytes) or len(human_approval_key) != 32:
            raise ValueError('a separate human consent verifier is required')
        if human_approval_key == _pub(issuer_key):
            raise ValueError('independent approval MUST use a separate authority key')
        if not isinstance(device_keys, dict) or not device_keys or any(
                not isinstance(k, str) or not DEVICE.fullmatch(k)
                or not isinstance(v, bytes) or len(v) != 32
                or v in (human_approval_key, _pub(issuer_key))
                for k, v in device_keys.items()):
            raise ValueError('invalid pinned device attestations')
        self.directory = Path(root_directory)
        self.db = self.directory / 'ledger.sqlite3'
        self.issuer_key = issuer_key
        self.issuer_public = _pub(issuer_key)
        self.approval_public = human_approval_key
        self.device_keys = dict(device_keys)

    def _secure_dir(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError('original local root only')
        st = self.directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0
                or st.st_gid != 0 or stat.S_IMODE(st.st_mode) != 0o700):
            raise PermissionError('untrusted issuer ledger directory')

    def _secure_db(self) -> None:
        st = self.db.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1):
            raise PermissionError('untrusted issuer ledger file')

    def initialize(self, now: int) -> None:
        self._secure_dir()
        _now(now)
        fd = os.open(self.db, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        with self._transaction() as conn:
            conn.executescript("""
                CREATE TABLE grants (
                    grant_id TEXT PRIMARY KEY, approval_id TEXT UNIQUE NOT NULL,
                    device TEXT NOT NULL, subject TEXT NOT NULL,
                    generation INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0, packet BLOB NOT NULL
                );
                CREATE TABLE revoked_device (
                    device TEXT PRIMARY KEY, through_generation INTEGER NOT NULL
                );
                CREATE TABLE renewal_nonces (
                    device TEXT NOT NULL, request_id TEXT NOT NULL,
                    grant_id TEXT NOT NULL, PRIMARY KEY(device,request_id)
                );
                CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
                INSERT INTO meta(key,value) VALUES('last_seen',0);
            """)
        # SQLite DDL can commit implicitly; the database contains only initial
        # tables at this point. Reopening without initialize is supported.
        with self._transaction() as conn:
            self._time(conn, now)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._secure_dir()
        self._secure_db()
        conn = sqlite3.connect(self.db, timeout=5, isolation_level=None)
        try:
            conn.execute('PRAGMA journal_mode=DELETE')
            conn.execute('PRAGMA synchronous=FULL')
            conn.execute('PRAGMA busy_timeout=5000')
            conn.execute('BEGIN IMMEDIATE')
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _time(conn: sqlite3.Connection, now: int) -> None:
        _now(now)
        row = conn.execute("SELECT value FROM meta WHERE key='last_seen'").fetchone()
        if row is None or type(row[0]) is not int or now < row[0]:
            raise PermissionError('issuer clock rollback or missing state')
        conn.execute("UPDATE meta SET value=? WHERE key='last_seen'", (now,))

    def issue_approved_partial(self, consent: bytes, *, expected_subject: str,
                               expected_device: str, now: int) -> bytes:
        """Produce parent grant only with separately signed human approval."""
        _now(now)
        if expected_device not in self.device_keys or not _subject(expected_subject):
            raise PermissionError('unauthorized device or subject')
        approval, signature = _decode(consent, 'consent', CONSENT_KEYS)
        if (approval['version'] != APPROVAL_VERSION
                or approval['device_id'] != expected_device
                or approval['subject'] != expected_subject
                or not _subject(approval['approved_by'])
                or approval['approval_method'] not in CONSENT_METHODS
                or approval['mode'] != 'partial'
                or type(approval['duration_seconds']) is not int
                or approval['duration_seconds'] not in DURATIONS
                or approval['capabilities'] != [CAPABILITY]
                or approval['confirmed'] is not True
                or not isinstance(approval['decision_id'], str)
                or not ID.fullmatch(approval['decision_id'])
                or type(approval['decided_at']) is not int
                or type(approval['expires_at']) is not int
                or approval['decided_at'] > now + MAX_CLOCK_SKEW
                or approval['expires_at'] <= now
                or approval['expires_at'] <= approval['decided_at']
                or approval['expires_at'] - approval['decided_at'] > MAX_CONSENT_AGE):
            raise PermissionError('invalid, unbound or stale human approval evidence')
        _verify(self.approval_public, _canonical(APPROVAL_DOMAIN, approval), signature)
        with self._transaction() as conn:
            self._time(conn, now)
            epoch = conn.execute('SELECT through_generation FROM revoked_device WHERE device=?',
                                 (expected_device,)).fetchone()
            latest = conn.execute('SELECT MAX(generation) FROM grants WHERE device=?',
                                  (expected_device,)).fetchone()[0]
            generation = max(latest or 0, epoch[0] if epoch else 0) + 1
            grant_id = secrets.token_hex(32)
            claim = dict(version=GRANT_VERSION, device_id=expected_device,
                         subject=expected_subject, approved_by=approval['approved_by'],
                         approval_method=approval['approval_method'], mode='partial',
                         issued_at=now, expires_at=now+approval['duration_seconds'],
                         generation=generation, grant_id=grant_id,
                         capabilities=[CAPABILITY])
            packet = _signed('grant', claim, self.issuer_key, GRANT_DOMAIN)
            conn.execute("""INSERT INTO grants
                 (grant_id,approval_id,device,subject,generation,expires_at,packet)
                 VALUES(?,?,?,?,?,?,?)""",
                 (grant_id, approval['decision_id'], expected_device,
                  expected_subject, generation, claim['expires_at'], packet))
            return packet

    def renew_short_lease(self, parent: bytes, request: bytes, *,
                          expected_subject: str, expected_device: str,
                          now: int) -> bytes:
        """Require device-key proof and live local revocation check each time."""
        _now(now)
        if expected_device not in self.device_keys or not _subject(expected_subject):
            raise PermissionError('unauthorized renewal origin')
        grant = verify_signed_grant(parent,
                    trusted_public_key=self.issuer_public,
                    expected_device=expected_device,
                    expected_subject=expected_subject, now=now)
        if grant.mode != 'partial' or CAPABILITY not in grant.capabilities:
            raise PermissionError('non-Partial renewal is forbidden')
        proof, sig = _decode(request, 'renewal', REQUEST_KEYS)
        if (proof['version'] != RENEWAL_VERSION
                or proof['device_id'] != expected_device
                or proof['subject'] != expected_subject
                or proof['grant_id'] != grant.grant_id
                or type(proof['generation']) is not int
                or proof['generation'] != grant.generation
                or proof['capability'] != CAPABILITY
                or not isinstance(proof['boot_id'], str)
                or not BOOT_ID_PATTERN.fullmatch(proof['boot_id'])
                or not isinstance(proof['request_id'], str)
                or not ID.fullmatch(proof['request_id'])
                or type(proof['requested_at']) is not int
                or proof['requested_at'] > now + MAX_CLOCK_SKEW
                or proof['requested_at'] < now - MAX_REQUEST_AGE):
            raise PermissionError('invalid or stale device renewal')
        _verify(self.device_keys[expected_device],
                _canonical(RENEWAL_DOMAIN, proof), sig)
        with self._transaction() as conn:
            self._time(conn, now)
            entry = conn.execute("""SELECT device,subject,generation,expires_at,
                                           revoked,packet FROM grants WHERE grant_id=?""",
                                 (grant.grant_id,)).fetchone()
            if (entry is None or entry[0] != expected_device
                    or entry[1] != expected_subject or entry[2] != grant.generation
                    or entry[3] <= now or entry[4] != 0 or entry[5] != parent):
                raise PermissionError('grant missing, expired or revoked')
            epoch = conn.execute('SELECT through_generation FROM revoked_device WHERE device=?',
                                 (expected_device,)).fetchone()
            if epoch and grant.generation <= epoch[0]:
                raise PermissionError('device generation revoked')
            expiry = min(now+MAX_LEASE_SECONDS, grant.expires_at)
            if expiry <= now:
                raise PermissionError('no remaining grant duration')
            lease = dict(version=LEASE_VERSION, device_id=expected_device,
                         subject=expected_subject, grant_id=grant.grant_id,
                         generation=grant.generation, mode='partial',
                         capability=CAPABILITY, boot_id=proof['boot_id'],
                         issued_at=now, expires_at=expiry,
                         lease_id=secrets.token_hex(32))
            result = _signed('lease', lease, self.issuer_key, LEASE_DOMAIN)
            # Burn the DEVICE nonce transactionally; a renewal request may
            # issue only one lease, even across restarts or concurrent workers.
            conn.execute("""INSERT INTO renewal_nonces(device,request_id,grant_id)
                            VALUES(?,?,?)""",
                         (expected_device, proof['request_id'], grant.grant_id))
            return result

    def revoke_grant(self, grant_id: str, *, now: int) -> None:
        if not isinstance(grant_id, str) or not ID.fullmatch(grant_id):
            raise ValueError('invalid grant identifier')
        with self._transaction() as conn:
            self._time(conn, now)
            if conn.execute('UPDATE grants SET revoked=1 WHERE grant_id=?',
                            (grant_id,)).rowcount != 1:
                raise PermissionError('unknown grant')

    def revoke_through_generation(self, device_id: str, generation: int,
                                  *, now: int) -> None:
        if (device_id not in self.device_keys or type(generation) is not int
                or generation < 0 or generation >= 2**62):
            raise ValueError('invalid device generation')
        with self._transaction() as conn:
            self._time(conn, now)
            current = conn.execute('SELECT through_generation FROM revoked_device WHERE device=?',
                                   (device_id,)).fetchone()
            next_epoch = max(generation, current[0] if current else 0)
            conn.execute("""INSERT INTO revoked_device(device,through_generation)
                            VALUES(?,?)
                            ON CONFLICT(device) DO UPDATE
                            SET through_generation=excluded.through_generation""",
                         (device_id, next_epoch))
