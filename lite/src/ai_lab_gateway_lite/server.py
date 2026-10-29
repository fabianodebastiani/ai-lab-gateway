"""OAuth-protected MCP and separate Auth0 OIDC admin UI on one HTTPS origin."""
from datetime import datetime, timezone
import os
import platform
import socket
from urllib.parse import urlparse

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
import uvicorn

from .audit import JsonlAuditLog
from .auth import Auth0TokenVerifier, AuthConfig, identity_from_verified_claims
from .control import ControlPlane
from .oauth_metadata import ProtectedResourceMetadataOverride
from .panel import create_panel
from .scope_stepup import OAuthScopeStepUp
from .store import Store


def _identity():
    access = get_access_token()
    if access is None:
        raise PermissionError("no authenticated MCP access token")
    return identity_from_verified_claims(dict(access.claims or {}))


def build_app():
    config = AuthConfig.from_env()
    expected = os.environ["LITE_BASE_URL"].rstrip("/") + "/mcp"
    if config.audience != expected:
        raise ValueError("Lite OAuth audience must equal the Lite MCP URL")
    store = Store.from_env()
    store.initialize()
    audit = JsonlAuditLog(os.environ.get("LITE_AUDIT_LOG", "/var/lib/ai-lab-gateway-lite/audit.jsonl"))
    control = ControlPlane(store, audit)
    verifier = Auth0TokenVerifier(config)
    hostname = urlparse(expected).hostname
    mcp = MCPServer(
        "AI Lab Gateway Lite",
        description="Authenticated SSH management of explicitly permitted WireGuard Linux devices",
        version="0.1.0",
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.issuer),
            resource_server_url=AnyHttpUrl(config.audience),
            required_scopes=["gateway:read"],
            validate_token_resource=False,
        ),
    )

    @mcp.tool()
    def gateway_status() -> dict:
        return {
            "status": "ok", "service": "ai-lab-gateway-lite",
            "hostname": socket.gethostname(),
            "python": platform.python_version(),
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    @mcp.tool()
    def list_devices() -> list[dict[str, str]]:
        return control.list_devices(_identity())

    @mcp.tool()
    def device_status(device_id: str) -> dict:
        return control.device_status(_identity(), device_id)

    @mcp.tool()
    def exec(device_id: str, command: str, timeout: int = 30) -> dict:
        result = control.exec(_identity(), device_id, command, timeout)
        return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}

    @mcp.tool()
    def read_file(device_id: str, path: str, timeout: int = 30) -> str:
        return control.read_file(_identity(), device_id, path, timeout)

    @mcp.tool()
    def write_file(device_id: str, path: str, content: str, timeout: int = 30) -> dict:
        return control.write_file(_identity(), device_id, path, content, timeout)

    security = TransportSecuritySettings(
        allowed_hosts=[hostname, hostname + ":*", "127.0.0.1", "127.0.0.1:*",
                       "localhost", "localhost:*"]
    )
    sdk_app = mcp.streamable_http_app(
        streamable_http_path="/mcp", json_response=True, stateless_http=True,
        transport_security=security, host="127.0.0.1",
    )
    resource_app = ProtectedResourceMetadataOverride(OAuthScopeStepUp(sdk_app, verifier, config), config)
    panel_app = create_panel(store)

    async def application(scope, receive, send):
        if scope["type"] == "http" and (
            scope.get("path") in {"/", "/admin", "/admin/device", "/admin/grant", "/admin/check"}
            or scope.get("path", "").startswith("/auth/")
        ):
            return await panel_app(scope, receive, send)
        return await resource_app(scope, receive, send)

    return application


def main():
    # Never listen publicly; HTTPS and the firewall are Caddy's responsibility.
    uvicorn.run(build_app(), host="127.0.0.1", port=int(os.environ.get("LITE_BIND_PORT", "8010")),
                log_level="info")


if __name__ == "__main__":
    main()
