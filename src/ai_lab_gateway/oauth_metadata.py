"""RFC 9728 protected-resource metadata helpers for the MCP gateway."""

from urllib.parse import urlparse

from mcp.server.auth.routes import build_resource_metadata_url
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

from .auth import AuthConfig


def protected_resource_metadata(config: AuthConfig) -> dict:
    """Describe every OAuth scope this resource server supports."""
    return {
        "resource": config.audience,
        "authorization_servers": [config.issuer],
        "scopes_supported": ["gateway:read", "gateway:control"],
        "resource_documentation": "https://github.com/fabianodebastiani/ai-lab-gateway",
    }


def protected_resource_metadata_path(config: AuthConfig) -> str:
    """Return the RFC 9728 well-known path used by the MCP SDK challenge."""
    metadata_url = build_resource_metadata_url(AnyHttpUrl(config.audience))
    return urlparse(str(metadata_url)).path


class ProtectedResourceMetadataOverride:
    """Serve complete PRM while leaving the SDK auth boundary untouched.

    MCP SDK 2.3 derives both its global required scopes and the PRM
    scopes_supported field from one AuthSettings.required_scopes list.
    The gateway deliberately requires only gateway:read globally while
    supporting additional per-tool scopes such as gateway:control.

    This ASGI wrapper intercepts only the public RFC 9728 metadata path.
    All other HTTP and lifespan traffic is delegated unchanged to the MCP SDK
    application, so its bearer-token middleware and WWW-Authenticate challenge
    remain authoritative.
    """

    def __init__(self, app: ASGIApp, config: AuthConfig):
        self.app = app
        self.metadata = protected_resource_metadata(config)
        self.path = protected_resource_metadata_path(config)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("path") == self.path:
            method = scope.get("method", "GET")
            headers = {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
                "Access-Control-Allow-Headers": "*",
            }
            if method == "OPTIONS":
                response = Response(status_code=204, headers=headers)
            elif method in {"GET", "HEAD"}:
                response = JSONResponse(self.metadata, headers=headers)
            else:
                response = Response(status_code=405, headers=headers)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
