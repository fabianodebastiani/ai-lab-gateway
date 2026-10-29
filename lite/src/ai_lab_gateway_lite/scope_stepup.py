"""Transport-level OAuth scope step-up for privileged MCP tools."""

import json

from mcp.server.auth.provider import TokenVerifier
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import AuthConfig


CONTROL_SCOPE = "gateway:control"
CONTROL_TOOLS = frozenset({"exec", "write_file"})


def _requested_tool_names(body: bytes) -> set[str]:
    """Extract tools/call names from one JSON-RPC request or a batch."""
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return set()

    messages = payload if isinstance(payload, list) else [payload]
    names: set[str] = set()
    for message in messages:
        if not isinstance(message, dict) or message.get("method") != "tools/call":
            continue
        params = message.get("params")
        if isinstance(params, dict) and isinstance(params.get("name"), str):
            names.add(params["name"])
    return names


def _bearer_token(scope: Scope) -> str | None:
    for raw_name, raw_value in scope.get("headers", []):
        if raw_name.lower() != b"authorization":
            continue
        value = raw_value.decode("latin-1")
        scheme, sep, token = value.partition(" ")
        if sep and scheme.lower() == "bearer" and token:
            return token
    return None


async def _buffer_request(receive: Receive) -> tuple[bytes, list[Message]]:
    messages: list[Message] = []
    body_parts: list[bytes] = []
    while True:
        message = await receive()
        messages.append(message)
        if message["type"] == "http.request":
            body_parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    return b"".join(body_parts), messages


def _replay_receive(messages: list[Message]) -> Receive:
    iterator = iter(messages)

    async def receive() -> Message:
        try:
            return next(iterator)
        except StopIteration:
            return {"type": "http.disconnect"}

    return receive


class OAuthScopeStepUp:
    """Return RFC 6750 insufficient_scope for privileged MCP tool calls.

    MCP clients can use this transport-level 403 challenge to perform OAuth
    scope step-up. Read-only requests still flow through the SDK with only
    gateway:read required globally.
    """

    def __init__(self, app: ASGIApp, verifier: TokenVerifier, config: AuthConfig):
        self.app = app
        self.verifier = verifier
        self.resource_metadata_url = config.resource_metadata_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/mcp"
        ):
            await self.app(scope, receive, send)
            return

        body, messages = await _buffer_request(receive)
        tool_names = _requested_tool_names(body)
        if not tool_names.intersection(CONTROL_TOOLS):
            await self.app(scope, _replay_receive(messages), send)
            return

        token = _bearer_token(scope)
        if token is None:
            await self.app(scope, _replay_receive(messages), send)
            return

        access = await self.verifier.verify_token(token)
        if access is None:
            await self.app(scope, _replay_receive(messages), send)
            return

        if CONTROL_SCOPE not in access.scopes:
            description = f"Required scope: {CONTROL_SCOPE}"
            challenge = (
                'Bearer error="insufficient_scope", '
                f'error_description="{description}", '
                f'scope="{CONTROL_SCOPE}", '
                f'resource_metadata="{self.resource_metadata_url}"'
            )
            response = JSONResponse(
                {"error": "insufficient_scope", "error_description": description},
                status_code=403,
                headers={"WWW-Authenticate": challenge},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, _replay_receive(messages), send)
