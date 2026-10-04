from ai_lab_gateway.auth import AuthConfig
from ai_lab_gateway.oauth_metadata import protected_resource_metadata


def test_metadata_binds_gateway_resource_to_issuer():
    config = AuthConfig(
        issuer="https://auth.example",
        audience="https://gateway.debasti.com",
        jwks_url="https://auth.example/jwks",
        resource_metadata_url=(
            "https://gateway.debasti.com/.well-known/oauth-protected-resource"
        ),
    )
    metadata = protected_resource_metadata(config)
    assert metadata["resource"] == "https://gateway.debasti.com"
    assert metadata["authorization_servers"] == ["https://auth.example"]
    assert "gateway:control" in metadata["scopes_supported"]
