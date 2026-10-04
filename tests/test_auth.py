import pytest

from ai_lab_gateway.auth import (
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
