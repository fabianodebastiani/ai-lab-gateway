import asyncio
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from ai_lab_gateway.auth import (
    Auth0TokenVerifier,
    AuthConfig,
    bearer_challenge,
    identity_from_verified_claims,
    scopes_from_claims,
)


def config():
    return AuthConfig(
        issuer="https://auth.example",
        audience="https://gateway.debasti.com",
        jwks_url="https://auth.example/.well-known/jwks.json",
        resource_metadata_url=(
            "https://gateway.debasti.com/.well-known/oauth-protected-resource"
        ),
    )


def test_scope_normalization():
    assert scopes_from_claims({"scope": "gateway:read gateway:control"}) == {
        "gateway:read", "gateway:control"
    }
    assert scopes_from_claims({"scp": ["gateway:read"]}) == {"gateway:read"}


def test_identity_requires_subject():
    with pytest.raises(PermissionError):
        identity_from_verified_claims({"scope": "gateway:read"})


def test_identity_requires_scope():
    identity = identity_from_verified_claims({
        "sub": "user-1",
        "scope": "gateway:read",
    })
    identity.require_scopes("gateway:read")
    with pytest.raises(PermissionError):
        identity.require_scopes("gateway:control")


def test_bearer_challenge_points_to_metadata():
    challenge = bearer_challenge(config(), "gateway:control", error="invalid_token")
    assert "resource_metadata=" in challenge
    assert 'scope="gateway:control"' in challenge
    assert 'error="invalid_token"' in challenge


class StaticJWKClient:
    def __init__(self, public_key):
        self.public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return type("SigningKey", (), {"key": self.public_key})()


def make_token(private_key, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://auth.example",
        "aud": "https://gateway.debasti.com",
        "sub": "auth0|user-1",
        "iat": now,
        "exp": now + 300,
        "scope": "gateway:read gateway:control",
        "azp": "chatgpt-client",
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "test"})


def test_auth0_verifier_accepts_valid_rs256_token():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = Auth0TokenVerifier(config(), StaticJWKClient(private_key.public_key()))
    access = asyncio.run(verifier.verify_token(make_token(private_key)))
    assert access is not None
    assert access.subject == "auth0|user-1"
    assert access.client_id == "chatgpt-client"
    assert access.resource == "https://gateway.debasti.com"
    assert set(access.scopes) == {"gateway:read", "gateway:control"}


@pytest.mark.parametrize("overrides", [
    {"aud": "https://wrong.example"},
    {"iss": "https://wrong.example"},
    {"exp": 1},
])
def test_auth0_verifier_rejects_invalid_claims(overrides):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = Auth0TokenVerifier(config(), StaticJWKClient(private_key.public_key()))
    assert asyncio.run(verifier.verify_token(make_token(private_key, **overrides))) is None


def test_auth0_verifier_rejects_token_issued_before_cutoff():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cfg = config()
    cfg = AuthConfig(
        issuer=cfg.issuer,
        audience=cfg.audience,
        jwks_url=cfg.jwks_url,
        resource_metadata_url=cfg.resource_metadata_url,
        min_iat=int(time.time()),
    )
    verifier = Auth0TokenVerifier(cfg, StaticJWKClient(private_key.public_key()))
    old_iat = int(time.time()) - 60
    assert asyncio.run(
        verifier.verify_token(make_token(private_key, iat=old_iat))
    ) is None


def test_auth0_verifier_accepts_token_issued_after_cutoff():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cutoff = int(time.time()) - 1
    cfg = config()
    cfg = AuthConfig(
        issuer=cfg.issuer,
        audience=cfg.audience,
        jwks_url=cfg.jwks_url,
        resource_metadata_url=cfg.resource_metadata_url,
        min_iat=cutoff,
    )
    verifier = Auth0TokenVerifier(cfg, StaticJWKClient(private_key.public_key()))
    assert asyncio.run(verifier.verify_token(make_token(private_key))) is not None


def test_auth_config_derives_resource_metadata_url_from_audience(monkeypatch):
    monkeypatch.setenv("AI_LAB_OAUTH_ISSUER", "https://auth.example/")
    monkeypatch.setenv("AI_LAB_OAUTH_AUDIENCE", "https://gateway.example/mcp")
    monkeypatch.setenv("AI_LAB_OAUTH_JWKS_URL", "https://auth.example/jwks")
    monkeypatch.delenv("AI_LAB_OAUTH_RESOURCE_METADATA_URL", raising=False)

    cfg = AuthConfig.from_env()

    assert cfg.resource_metadata_url == (
        "https://gateway.example/.well-known/oauth-protected-resource/mcp"
    )
