"""Strict OpenSSH SSHSIG Ed25519 verifier for zero-third-party-dependency targets.

OpenSSH ssh-keygen -Y sign works with only the standard SSH client installed.
The Gateway verifies using its own cryptography dependency. The signed object
binds to our versioned device-code challenge; arbitrary SSHSIG namespaces,
algorithms, keys, and altered messages are refused.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SSHSIG_NAMESPACE = b"ai-lab-gateway-device-code"
BEGIN = "-----BEGIN SSH SIGNATURE-----"
END = "-----END SSH SIGNATURE-----"
MAX_ARMORED = 2048


def _string(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def _field(blob: bytes, offset: int, *, limit: int = 1024) -> tuple[bytes, int]:
    if offset + 4 > len(blob):
        raise ValueError("truncated SSHSIG field length")
    size = struct.unpack(">I", blob[offset:offset + 4])[0]
    offset += 4
    if size > limit or offset + size > len(blob):
        raise ValueError("invalid SSHSIG field length")
    return blob[offset:offset + size], offset + size


def _keyblob(expected_key: str) -> bytes:
    words = expected_key.split()
    if len(words) < 2 or words[0] != "ssh-ed25519":
        raise ValueError("expected key is not Ed25519")
    blob = base64.b64decode(words[1], validate=True)
    off = 0
    alg, off = _field(blob, off, limit=30)
    pub, off = _field(blob, off, limit=64)
    if alg != b"ssh-ed25519" or len(pub) != 32 or off != len(blob):
        raise ValueError("invalid Ed25519 key encoding")
    return blob


def verify_sshsig(*, armor: str, challenge: bytes, expected_public_key: str) -> None:
    """Raise ValueError on malformed armor, PermissionError on failed proof."""
    if not isinstance(armor, str) or not 64 <= len(armor) <= MAX_ARMORED:
        raise ValueError("invalid SSHSIG armored length")
    lines = armor.strip().splitlines()
    if (len(lines) < 3 or lines[0] != BEGIN or lines[-1] != END
            or any(not re.fullmatch(r"[A-Za-z0-9+/=]+", line) for line in lines[1:-1])):
        raise ValueError("invalid SSHSIG armor")
    try:
        blob = base64.b64decode("".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid SSHSIG base64") from exc
    if len(blob) > 1024 or len(blob) < 40 or not blob.startswith(b"SSHSIG"):
        raise ValueError("invalid SSHSIG magic or size")
    version = struct.unpack(">I", blob[6:10])[0]
    if version != 1:
        raise ValueError("unsupported SSHSIG version")
    off = 10
    pubblob, off = _field(blob, off, limit=128)
    namespace, off = _field(blob, off, limit=64)
    reserved, off = _field(blob, off, limit=32)
    algorithm, off = _field(blob, off, limit=32)
    signature_blob, off = _field(blob, off, limit=128)
    if off != len(blob):
        raise ValueError("trailing SSHSIG bytes")
    if (pubblob != _keyblob(expected_public_key)
            or namespace != SSHSIG_NAMESPACE or reserved != b""
            or algorithm not in (b"sha256", b"sha512")):
        raise PermissionError("wrong SSHSIG identity or namespace")
    alg, index = _field(signature_blob, 0, limit=32)
    signature, index = _field(signature_blob, index, limit=80)
    if alg != b"ssh-ed25519" or len(signature) != 64 or index != len(signature_blob):
        raise ValueError("invalid SSHSIG Ed25519 signature")
    digest = hashlib.sha512(challenge).digest() if algorithm == b"sha512" else hashlib.sha256(challenge).digest()
    signed = b"SSHSIG" + _string(namespace) + _string(reserved) + _string(algorithm) + _string(digest)
    raw_public = _field(pubblob, 4 + 11)[0]
    try:
        Ed25519PublicKey.from_public_bytes(raw_public).verify(signature, signed)
    except (InvalidSignature, ValueError) as exc:
        raise PermissionError("SSHSIG possession signature failed") from exc
