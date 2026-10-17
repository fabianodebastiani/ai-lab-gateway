"""Stage 5 laboratory: signed short leases and root-local revocation state.

NOT wired to sudo, SSH, MCP, issuer, or an installation procedure. Nothing in
this module executes privileged commands. A root process could eventually use
this code ONLY after independent approval, issuer and deployment review.

WARNING: fsync + local time watermark cannot protect against rollback of BOTH
an entire disk snapshot and the system clock. Offline revoke cannot be instant.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signed_profile_grants import (
    VerifiedProfileGrant, verify_signed_grant, assess_signed_profile,
)

LEASE_VERSION = 'ai-lab-target-profile-lease-v1'
LEASE_DOMAIN = b'AI-LAB-TARGET-PROFILE-LEASE-V1\x00'
MAX_LEASE_SECONDS = 300
FUTURE_SKEW_SECONDS = 30
MAX_PACKET_BYTES = 4096
MAX_STATE_BYTES = 65536
MAX_REVOKED_IDS = 256
BOOT_ID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z')
HEX_ID = re.compile(r'[0-9a-f]{64}\Z')
DEVICE_ID = re.compile(r'[a-z][a-z0-9-]{2,47}\Z')
LEASE_FIELDS = frozenset((
    'version', 'device_id', 'subject', 'grant_id', 'generation',
    'mode', 'capability', 'boot_id', 'issued_at', 'expires_at', 'lease_id',
))
STATE_FIELDS = frozenset((
    'version', 'device_id', 'boot_id', 'revision', 'time_floor',
    'revoked_generation', 'revoked_grant_ids',
))
STATE_VERSION = 1
CAPABILITY = 'root-identity-check'  # only non-mutating diagnostic metadata


@dataclass(frozen=True)
class VerifiedShortLease:
    device_id: str
    subject: str
    grant_id: str
    generation: int
    mode: str
    capability: str
    boot_id: str
    issued_at: int
    expires_at: int
    lease_id: str


@dataclass(frozen=True)
class LocalDecision:
    # ALWAYS diagnostic metadata: caller cannot use this as a sudo credential.
    effective_mode: str
    reason: str
    expires_at: int | None = None
    capability: str | None = None


def _unique_pairs(items: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _parse(raw: bytes) -> object:
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid constant')))


def canonical_lease_bytes(lease: dict) -> bytes:
    return LEASE_DOMAIN + (json.dumps(lease, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def verify_short_lease(raw: bytes, *, trusted_public_key: bytes,
                       grant: VerifiedProfileGrant, expected_boot_id: str,
                       now: int) -> VerifiedShortLease:
    """Validate issuer-signed lease bound to one previously verified Partial grant.

    Caller MUST separately verify the grant signature and acquire the issuer
    public key from provisioned root-owned local trust. Not a sudo ticket.
    """
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PACKET_BYTES
            or not isinstance(trusted_public_key, bytes) or len(trusted_public_key) != 32
            or not isinstance(grant, VerifiedProfileGrant)
            or not isinstance(expected_boot_id, str)
            or not BOOT_ID_PATTERN.fullmatch(expected_boot_id)
            or type(now) is not int or now < 0):
        raise ValueError('invalid verifier input')
    envelope = _parse(raw)
    if not isinstance(envelope, dict) or set(envelope) != {'lease', 'signature'}:
        raise ValueError('invalid lease envelope')
    p = envelope['lease']
    if not isinstance(p, dict) or set(p) != LEASE_FIELDS:
        raise ValueError('invalid lease fields')
    issued, expires = p['issued_at'], p['expires_at']
    if (p['version'] != LEASE_VERSION or p['device_id'] != grant.device_id
            or p['subject'] != grant.subject or p['grant_id'] != grant.grant_id
            or type(p['generation']) is not int or p['generation'] != grant.generation
            or p['mode'] != 'partial' or grant.mode != 'partial'
            or p['capability'] != CAPABILITY or CAPABILITY not in grant.capabilities
            or p['boot_id'] != expected_boot_id
            or not isinstance(p['lease_id'], str) or not HEX_ID.fullmatch(p['lease_id'])
            or type(issued) is not int or type(expires) is not int
            or issued < grant.issued_at or issued > now + FUTURE_SKEW_SECONDS
            or expires <= now or expires <= issued
            or expires - issued > MAX_LEASE_SECONDS
            or grant.expires_at is None or expires > grant.expires_at):
        raise PermissionError('lease not bound to active Partial grant or expired')
    value = envelope['signature']
    if not isinstance(value, str) or len(value) > 120:
        raise ValueError('invalid signature')
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError('invalid signature encoding') from exc
    if len(signature) != 64 or base64.b64encode(signature).decode('ascii') != value:
        raise ValueError('noncanonical signature encoding')
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(
            signature, canonical_lease_bytes(p))
    except InvalidSignature as exc:
        raise PermissionError('invalid lease signature') from exc
    return VerifiedShortLease(
        device_id=grant.device_id, subject=grant.subject, grant_id=grant.grant_id,
        generation=grant.generation, mode='partial', capability=CAPABILITY,
        boot_id=expected_boot_id, issued_at=issued, expires_at=expires,
        lease_id=p['lease_id'],
    )


def current_boot_id() -> str:
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not BOOT_ID_PATTERN.fullmatch(value):
        raise PermissionError('invalid local Linux boot identifier')
    return value


def _require_root() -> None:
    if os.geteuid() != 0:
        raise PermissionError('root-only state API')


def _secure_directory(directory: Path) -> None:
    st = directory.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise PermissionError('root-owned 0700 state directory required')


def _open_protected(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_gid != 0
                or stat.S_IMODE(st.st_mode) != 0o600
                or st.st_nlink != 1 or st.st_size > MAX_STATE_BYTES):
            raise PermissionError('untrusted root state file')
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_state(path: Path, device_id: str) -> dict:
    fd = _open_protected(path, os.O_RDONLY)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        raise PermissionError('oversized state')
    state = _parse(raw)
    if not isinstance(state, dict) or set(state) != STATE_FIELDS:
        raise PermissionError('malformed root state')
    if (type(state['version']) is not int or state['version'] != STATE_VERSION
            or state['device_id'] != device_id
            or not isinstance(state['boot_id'], str)
            or not BOOT_ID_PATTERN.fullmatch(state['boot_id'])
            or any(type(state[field]) is not int or state[field] < 0
                   for field in ('revision', 'time_floor', 'revoked_generation'))
            or type(state['revoked_grant_ids']) is not list
            or len(state['revoked_grant_ids']) > MAX_REVOKED_IDS
            or any(not isinstance(s, str) or not HEX_ID.fullmatch(s)
                   for s in state['revoked_grant_ids'])
            or state['revoked_grant_ids'] != sorted(set(state['revoked_grant_ids']))):
        raise PermissionError('invalid root state')
    return state


def _write_state(directory: Path, state: dict, *, exclusive: bool = False) -> None:
    """Write canonical state via fsynced temp + replace + directory fsync."""
    target = directory / 'state.json'
    payload = (json.dumps(state, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(payload) > MAX_STATE_BYTES:
        raise PermissionError('oversized state')
    if exclusive and (target.exists() or target.is_symlink()):
        raise PermissionError('state already initialized; reset prohibited')
    fd, name = tempfile.mkstemp(prefix='.stage5-', dir=directory)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if exclusive and (target.exists() or target.is_symlink()):
            raise PermissionError('state initialized concurrently')
        # Safe only because directory is 0700 root-owned and under root operation.
        os.replace(name, target)
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class RootProfileState:
    """Root-local prototype state with per-device lock and fail-closed checks.

    Trusted path, time source and boot ID reader MUST be provided by the future
    original-admin installer / root runtime, never from MCP request arguments.
    The override functions are ONLY for synthetic tests.
    """
    def __init__(self, directory: Path, device_id: str, *,
                 clock: Callable[[], int] | None = None,
                 boot_reader: Callable[[], str] | None = None):
        if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
            raise ValueError('invalid device ID')
        self.directory = Path(directory)
        self.device_id = device_id
        self.clock = clock or (lambda: int(time.time()))
        self.boot_reader = boot_reader or current_boot_id

    def _now(self) -> int:
        moment = self.clock()
        if type(moment) is not int or moment < 0:
            raise PermissionError('invalid trusted local time')
        return moment

    def _boot(self) -> str:
        boot = self.boot_reader()
        if not isinstance(boot, str) or not BOOT_ID_PATTERN.fullmatch(boot):
            raise PermissionError('invalid local boot ID')
        return boot

    def initialize(self) -> None:
        """One-time local-root bootstrap; no MCP surface and no reset/regrant."""
        _require_root()
        _secure_directory(self.directory)
        now, boot = self._now(), self._boot()
        lock = self.directory / 'lock'
        if lock.exists() or lock.is_symlink() or (self.directory / 'state.json').exists():
            raise PermissionError('existing root state; refusing re-initialization')
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        _write_state(self.directory, dict(version=STATE_VERSION, device_id=self.device_id,
            boot_id=boot, revision=0, time_floor=now, revoked_generation=0,
            revoked_grant_ids=[]), exclusive=True)

    def _locked(self, action: Callable[[dict, int], LocalDecision | None]) -> LocalDecision | None:
        _require_root()
        _secure_directory(self.directory)
        lock_fd = _open_protected(self.directory / 'lock', os.O_RDONLY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            state = _read_state(self.directory / 'state.json', self.device_id)
            moment, boot = self._now(), self._boot()
            if state['boot_id'] != boot:
                raise PermissionError('boot changed; fresh online reauthorization required')
            if moment < state['time_floor']:
                raise PermissionError('clock rollback detected')
            decision = action(state, moment)
            state['revision'] += 1
            state['time_floor'] = moment
            _write_state(self.directory, state)
            return decision
        finally:
            os.close(lock_fd)

    def revoke_id(self, grant_id: str) -> None:
        if not isinstance(grant_id, str) or not HEX_ID.fullmatch(grant_id):
            raise ValueError('invalid grant ID')
        def update(state: dict, _: int) -> None:
            ids = set(state['revoked_grant_ids'])
            ids.add(grant_id)
            if len(ids) > MAX_REVOKED_IDS:
                raise PermissionError('revocation list full; fail closed')
            state['revoked_grant_ids'] = sorted(ids)
        self._locked(update)

    def revoke_through_generation(self, generation: int) -> None:
        if type(generation) is not int or generation < 0 or generation > 2**63-1:
            raise ValueError('invalid revocation generation')
        def update(state: dict, _: int) -> None:
            state['revoked_generation'] = max(state['revoked_generation'], generation)
        self._locked(update)

    def evaluate_signed(self, raw_grant: bytes, raw_lease: bytes, *,
                        trusted_public_key: bytes, expected_subject: str) -> LocalDecision:
        """Read-only policy result; NEVER authorizes a root operation by itself."""
        _require_root()
        def evaluate(state: dict, now: int) -> LocalDecision:
            if (not isinstance(raw_grant, bytes) or not isinstance(raw_lease, bytes)):
                raise PermissionError('missing signed authorization')
            verified = verify_signed_grant(raw_grant,
                    trusted_public_key=trusted_public_key, expected_device=self.device_id,
                    expected_subject=expected_subject, now=now)
            profile = assess_signed_profile(verified, now=now,
                    trusted_time_floor=state['time_floor'],
                    revoked_generation=state['revoked_generation'],
                    revoked_grant_ids=state['revoked_grant_ids'])
            if profile.effective_mode != 'partial':
                return LocalDecision('restricted', profile.reason)
            lease = verify_short_lease(raw_lease, trusted_public_key=trusted_public_key,
                                       grant=verified, expected_boot_id=state['boot_id'], now=now)
            return LocalDecision('partial', 'signed_lease_metadata_only',
                                 lease.expires_at, lease.capability)
        return self._locked(evaluate)
