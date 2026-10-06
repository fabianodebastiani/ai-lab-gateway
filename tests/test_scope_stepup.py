import asyncio
import json

from ai_lab_gateway.auth import AuthConfig
from ai_lab_gateway.scope_stepup import OAuthScopeStepUp


class StaticVerifier:
    def __init__(self, scopes):
        self.scopes = scopes

    async def verify_token(self, token):
        return type("Access", (), {"scopes": self.scopes})()


def config():
    return AuthConfig(
        issuer="https://auth.example/",
        audience="https://gateway.example/mcp",
        jwks_url="https://auth.example/jwks",
        resource_metadata_url=(
            "https://gateway.example/.well-known/oauth-protected-resource/mcp"
        ),
    )


def scope_for(body: bytes):
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "headers": [(b"authorization", b"Bearer test-token")],
        "client": ("127.0.0.1", 12345),
        "server": ("gateway.example", 443),
        "root_path": "",
    }


def request_body(tool: str) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {}},
    }).encode()


def run_app(app, body: bytes):
    sent = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope_for(body), receive, send))
    return sent


def test_control_tool_returns_transport_403_for_read_only_token():
    delegated = False

    async def inner(scope, receive, send):
        nonlocal delegated
        delegated = True

    app = OAuthScopeStepUp(inner, StaticVerifier(["gateway:read"]), config())
    sent = run_app(app, request_body("exec"))

    assert delegated is False
    assert sent[0]["status"] == 403
    headers = dict(sent[0]["headers"])
    challenge = headers[b"www-authenticate"].decode()
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="gateway:control"' in challenge
    assert "resource_metadata=" in challenge


def test_control_tool_passes_with_control_scope_and_preserves_body():
    received_body = None

    async def inner(scope, receive, send):
        nonlocal received_body
        message = await receive()
        received_body = message["body"]

    body = request_body("write_file")
    app = OAuthScopeStepUp(
        inner,
        StaticVerifier(["gateway:read", "gateway:control"]),
        config(),
    )
    run_app(app, body)
    assert received_body == body


def test_read_tool_does_not_require_control_scope():
    delegated = False

    async def inner(scope, receive, send):
        nonlocal delegated
        delegated = True

    app = OAuthScopeStepUp(inner, StaticVerifier(["gateway:read"]), config())
    sent = run_app(app, request_body("read_file"))

    assert delegated is True
    assert sent == []
