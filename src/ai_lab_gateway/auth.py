"""OAuth resource-server primitives.

Provider-specific login/token issuance is intentionally outside this module.
This code models the security checks the gateway must apply to already-issued
Bearer access tokens before privileged MCP tools are allowed to run.
"""

from dataclasses import dataclass
import os
from typing import Any

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken, TokenVerifier


@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    audience: str
    jwks_url: str
    resource_metadata_url: str

    @classmethod
    def from_env(cls) -> "AuthConfig":
        required = {
            "issuer": os.getenv("AI_LAB_OAUTH_ISSUER"),
            "audience": os.getenv("AI_LAB_OAUTH_AUDIENCE"),
            "jwks_url": os.getenv("AI_LAB_OAUTH_JWKS_URL"),
            "resource_metadata_url": os.getenv(
                "AI_LAB_OAUTH_RESOURCE_METADATA_URL",
                "https://gateway.debasti.com/.well-known/oauth-protected-resource",
            ),
        }
        missing = [key for key, value in required.items() if not value]
        if missing:
            raise RuntimeError(
                "missing OAuth configuration: " + ", ".join(sorted(missing))
            )
        return cls(**required)  # type: ignore[arg-type]


@dataclass(frozen=True)
class VerifiedIdentity:
    subject: str
    scopes: frozenset[str]
    claims: dict[str, Any]

    def require_scopes(self, *required: str) -> None:
        missing = set(required) - self.scopes
        if missing:
            raise PermissionError(
                "missing OAuth scope(s): " + ", ".join(sorted(missing))
            )


def scopes_from_claims(claims: dict[str, Any]) -> frozenset[str]:
    """Normalize common OAuth scope claim encodings."""
    raw = claims.get("scope", claims.get("scp", []))
    if isinstance(raw, str):
        return frozenset(part for part in raw.split() if part)
    if isinstance(raw, (list, tuple, set)):
        return frozenset(str(part) for part in raw)
    return frozenset()


def identity_from_verified_claims(claims: dict[str, Any]) -> VerifiedIdentity:
    """Create an application identity only after cryptographic verification.

    The caller must already have verified signature, issuer, audience, expiry
    and not-before constraints using the configured authorization server/JWKS.
    """
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise PermissionError("verified token has no stable subject")
    return VerifiedIdentity(
        subject=subject,
        scopes=scopes_from_claims(claims),
        claims=dict(claims),
    )


class Auth0TokenVerifier(TokenVerifier):
    """Verify Auth0 RS256 access tokens against the tenant JWKS."""

    def __init__(self, config: AuthConfig, jwk_client: PyJWKClient | None = None):
        self.config = config
        self.jwk_client = jwk_client or PyJWKClient(
            config.jwks_url, cache_jwk_set=True, lifespan=300
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            signing_key = self.jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self.config.audience,
                issuer=self.config.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
            identity = identity_from_verified_claims(claims)
            exp = claims.get("exp")
            return AccessToken(
                token=token,
                client_id=str(
                    claims.get("azp") or claims.get("client_id") or identity.subject
                ),
                scopes=list(identity.scopes),
                expires_at=int(exp) if isinstance(exp, (int, float)) else None,
                resource=self.config.audience,
                subject=identity.subject,
                claims=dict(claims),
            )
        except (jwt.PyJWTError, ValueError, TypeError, PermissionError):
            return None


def bearer_challenge(config: AuthConfig, *scopes: str, error: str | None = None) -> str:
    fields = [
        f'resource_metadata="{config.resource_metadata_url}"',
    ]
    if scopes:
        fields.append(f'scope="{" ".join(scopes)}"')
    if error:
        fields.append(f'error="{error}"')
    return "Bearer " + ", ".join(fields)
