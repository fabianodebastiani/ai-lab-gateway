"""Signed device access-profile *claims* (Stage 5, isolated laboratory code).

Not installed as a root executor, not wired to MCP, and never authorizes sudo.
A validated signed grant is evidence of what a human-approval issuer attested,
NOT proof that the target's root-controlled local state authorizes execution.

This protocol has its OWN Ed25519 key and domain; do not reuse target one-use
SSHSIG material. The issuer must verify independent human consent BEFORE
signing; a string inside the signed message is not independent consent.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import json
import re
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "ai-lab-target-profile-grant-v1"
DOMAIN = b"AI-LAB-TARGET-PROFILE-GRANT-V1\x00"
MAX_INPUT_BYTES = 4096
FUTURE_SKEW_SECONDS = 30
DURATIONS = frozenset((900, 1800, 3600, 7200, 14400, 28800, 86400))
MODES = frozenset(("restricted", "partial", "unrestricted"))
APPROVAL_METHODS = frozenset(("separate_human_root_console", "separate_human_web_ui"))
DEVICE_ID = re.compile(r"[a-z][a-z0-9-]{2,47}\Z")
GRANT_ID = re.compile(r"[a-f0-9]{64}\Z")
GRANT_FIELDS = frozenset((
    "version", "device_id", "subject", "approved_by", "approval_method",
    "mode", "issued_at", "expires_at", "generation", "grant_id", "capabilities",
))
ENVELOPE_FIELDS = frozenset(("grant", "signature"))
# NO arbitrary shell, package manager, file mutation or generic sudo scope.
LAB_PARTIAL_CAPABILITIES = ("root-identity-check",)


@dataclass(frozen=True)
class VerifiedProfileGrant:
    device_id: str
    subject: str
    approved_by: str
    approval_method: str
    mode: str
    issued_at: int
    expires_at: int | None
    generation: int
    grant_id: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class ProfileAssessment:
    """A read-only decision; no caller may use this as a sudo ticket."""
    effective_mode: str
    reason: str
    capabilities: tuple[str, ...]


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _identity(value: object) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and all(33 <= ord(char) <= 126 for char in value))


def canonical_grant_bytes(claim: dict) -> bytes:
    """Canonical *signed* body with explicit protocol domain separation."""
    return DOMAIN + (json.dumps(claim, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def verify_signed_grant(raw: bytes, *, trusted_public_key: bytes,
                        expected_device: str, expected_subject: str, now: int) -> VerifiedProfileGrant:
    """Verify schema, exact target, time rules and detached Ed25519 signature.

    Trusted public key must come from protected pre-provisioned LOCAL trust,
    never from the claim/MCP/user. Does not authorize execution or write state.
    """
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INPUT_BYTES
            or not isinstance(trusted_public_key, bytes)
            or len(trusted_public_key) != 32
            or type(now) is not int or now < 0
            or not isinstance(expected_device, str)
            or not DEVICE_ID.fullmatch(expected_device)
            or not _identity(expected_subject)):
        raise ValueError("invalid verifier input")
    try:
        envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON literal")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid grant encoding") from exc
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise ValueError("unexpected signed envelope")
    claim = envelope["grant"]
    if not isinstance(claim, dict) or set(claim) != GRANT_FIELDS:
        raise ValueError("unexpected grant fields")
    if (claim["version"] != VERSION
            or not isinstance(claim["device_id"], str)
            or claim["device_id"] != expected_device
            or claim["subject"] != expected_subject
            or not _identity(claim["subject"])
            or not _identity(claim["approved_by"])
            or not isinstance(claim["approval_method"], str)
            or claim["approval_method"] not in APPROVAL_METHODS
            or not isinstance(claim["mode"], str) or claim["mode"] not in MODES
            or not isinstance(claim["grant_id"], str)
            or not GRANT_ID.fullmatch(claim["grant_id"])
            or type(claim["generation"]) is not int
            or not 1 <= claim["generation"] <= 2**63 - 1):
        raise PermissionError("unrecognized or unbound grant")
    issued, expires, mode = claim["issued_at"], claim["expires_at"], claim["mode"]
    if (type(issued) is not int or issued < 0
            or issued > now + FUTURE_SKEW_SECONDS):
        raise PermissionError("invalid grant issue time")
    if mode == "partial":
        if (type(expires) is not int or expires <= now
                or expires - issued not in DURATIONS):
            raise PermissionError("unsupported or expired partial window")
        if type(claim["capabilities"]) is not list or claim["capabilities"] != list(LAB_PARTIAL_CAPABILITIES):
            raise PermissionError("partial lab capabilities must be exactly allowlisted")
    else:
        if expires is not None or claim["capabilities"] != []:
            raise PermissionError("non-partial grants cannot specify duration/capabilities")
    signature = envelope["signature"]
    if not isinstance(signature, str) or len(signature) > 120:
        raise ValueError("invalid signature encoding")
    try:
        sig = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid signature encoding") from exc
    if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != signature:
        raise ValueError("noncanonical Ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(sig, canonical_grant_bytes(claim))
    except InvalidSignature as exc:
        raise PermissionError("invalid independent signature") from exc
    return VerifiedProfileGrant(
        device_id=claim["device_id"], subject=claim["subject"],
        approved_by=claim["approved_by"], approval_method=claim["approval_method"],
        mode=mode, issued_at=issued, expires_at=expires,
        generation=claim["generation"], grant_id=claim["grant_id"],
        capabilities=tuple(claim["capabilities"]),
    )


def assess_signed_profile(grant: VerifiedProfileGrant, *, now: int,
                          trusted_time_floor: int, revoked_generation: int,
                          revoked_grant_ids: Iterable[str]) -> ProfileAssessment:
    """Fail-closed lab evaluation for a root-state owner to integrate later.

    The caller MUST obtain floor, generation and revocations from verified
    root-controlled local storage. If unavailable it MUST reject, not pass
    default integers. No grant here can launch an elevated command. In
    particular, unrestricted always requires a future distinct online
    authorization/enforcement implementation; we deliberately deny it now.
    """
    if (not isinstance(grant, VerifiedProfileGrant)
            or type(now) is not int or type(trusted_time_floor) is not int
            or type(revoked_generation) is not int
            or min(now, trusted_time_floor, revoked_generation) < 0):
        raise PermissionError("missing or invalid trusted target state")
    if now < trusted_time_floor:
        raise PermissionError("trusted clock moved backwards")
    if (not isinstance(revoked_grant_ids, (frozenset, set, tuple, list))
            or any(not isinstance(value, str) or not GRANT_ID.fullmatch(value)
                   for value in revoked_grant_ids)):
        raise PermissionError("untrusted revocation input")
    if grant.generation <= revoked_generation or grant.grant_id in revoked_grant_ids:
        return ProfileAssessment("restricted", "revoked", ())
    if grant.mode == "restricted":
        return ProfileAssessment("restricted", "explicitly_restricted", ())
    if grant.mode == "unrestricted":
        return ProfileAssessment("restricted", "unrestricted_not_enabled_in_lab", ())
    if now >= grant.expires_at:
        return ProfileAssessment("restricted", "expired", ())
    return ProfileAssessment("partial", "signed_partial_metadata_only", grant.capabilities)
