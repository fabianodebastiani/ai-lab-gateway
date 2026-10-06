import asyncio
import json

from ai_lab_gateway.auth import AuthConfig
from ai_lab_gateway.oauth_metadata import (
    ProtectedResourceMetadataOverride,
    protected_resource_metadata,
    protected_resource_metadata_path,
)


def _config() -> AuthConfig:
    return AuthConfig(
        issuer="https://auth.example/",
        audience="https://gateway.debasti.com/mcp",
        jwks_url="https://auth.example/jwks",
        resource_metadata_url=(
            "https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp"
        ),
    )


def test_metadata_binds_gateway_resource_to_issuer():
    config = _config()
    metadata = protected_resource_metadata(config)
    assert metadata["resource"] == "https://gateway.debasti.com/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example/"]
    assert metadata["scopes_supported"] == ["gateway:read", "gateway:control"]
    assert protected_resource_metadata_path(config) == (
        "/.well-known/oauth-protected-resource/mcp"
    )


def test_metadata_override_serves_all_supported_scopes_before_sdk_route():
    delegated = False

    async def inner(scope, receive, send):
        nonlocal delegated
        delegated = True

    app = ProtectedResourceMetadataOverride(inner, _config())
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    path = "/.well-known/oauth-protected-resource/mcp"
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("gateway.debasti.com", 443),
        "root_path": "",
    }

    asyncio.run(app(scope, receive, send))

    assert delegated is False
    assert messages[0]["status"] == 200
    body = json.loads(messages[1]["body"])
    assert body["scopes_supported"] == ["gateway:read", "gateway:control"]


def test_metadata_override_delegates_other_paths():
    delegated = False

    async def inner(scope, receive, send):
        nonlocal delegated
        delegated = True

    app = ProtectedResourceMetadataOverride(inner, _config())

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        return None

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/mcp",
    }
    asyncio.run(app(scope, receive, send))
    assert delegated is True
