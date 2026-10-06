"""AI Lab Gateway MCP server.

The public MCP surface is deliberately small. Authenticated read-only device
listing is exposed before any command-execution capability.
"""

from datetime import datetime, timezone
import os
import platform
import socket

from pydantic import AnyHttpUrl
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .audit import JsonlAuditLog
from .auth import Auth0TokenVerifier, AuthConfig, identity_from_verified_claims
from .authz import AuthorizationPolicy
from .control import ControlPlane
from .registry import DeviceRegistry

auth_config = AuthConfig.from_env()

mcp = MCPServer(
    "AI Lab Gateway",
    description="Remote MCP gateway for controlled access to Linux lab devices",
    version="0.1.0",
    token_verifier=Auth0TokenVerifier(auth_config),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(auth_config.issuer),
        resource_server_url=AnyHttpUrl(auth_config.audience),
        required_scopes=["gateway:read"],
        validate_token_resource=False,
    ),
)

transport_security = TransportSecuritySettings(
    allowed_hosts=[
        "gateway.debasti.com",
        "gateway.debasti.com:*",
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
    ],
)


def _control_plane() -> ControlPlane:
    """Load private runtime registry/policy state.

    Defaults intentionally live outside the public repository. Operators may
    override them with environment variables when using another filesystem
    layout.
    """
    registry_path = os.getenv(
        "AI_LAB_DEVICE_REGISTRY", "/etc/ai-lab-gateway/devices.json"
    )
    policy_path = os.getenv(
        "AI_LAB_AUTHORIZATION_POLICY", "/etc/ai-lab-gateway/authorization.json"
    )
    audit_path = os.getenv(
        "AI_LAB_AUDIT_LOG", "/var/lib/ai-lab-gateway/audit.jsonl"
    )
    return ControlPlane(
        registry=DeviceRegistry.load(registry_path),
        policy=AuthorizationPolicy.load(policy_path),
        audit=JsonlAuditLog(audit_path),
    )


def _verified_identity():
    """Recover the already-verified caller identity from MCP request context."""
    token = get_access_token()
    if token is None:
        raise PermissionError("authenticated access token is unavailable")
    return identity_from_verified_claims(dict(token.claims or {}))


@mcp.tool()
def gateway_status() -> dict[str, str]:
    """Return basic status of the authenticated AI Lab Gateway service."""
    return {
        "status": "ok",
        "service": "ai-lab-gateway",
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "architecture": platform.machine(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


@mcp.tool()
def list_devices() -> list[dict[str, str]]:
    """List enabled lab devices explicitly authorized for the current user."""
    return _control_plane().list_devices(_verified_identity())


@mcp.tool()
def device_status(device_id: str) -> dict[str, str | int]:
    """Check an authorized lab device live over the managed SSH tunnel."""
    return _control_plane().device_status(_verified_identity(), device_id)


@mcp.tool()
def exec(device_id: str, command: str, timeout: int = 30) -> dict[str, str | int]:
    """Execute a command on an authorized lab device."""
    result = _control_plane().exec(_verified_identity(), device_id, command, timeout)
    return {"stdout": result.stdout, "stderr": result.stderr, "exit_code": result.exit_code}


@mcp.tool()
def read_file(device_id: str, path: str, timeout: int = 30) -> str:
    """Read a text file from an authorized lab device."""
    return _control_plane().read_file(_verified_identity(), device_id, path, timeout)


@mcp.tool()
def write_file(device_id: str, path: str, content: str, timeout: int = 30) -> dict[str, str]:
    """Write a UTF-8 text file on an authorized lab device."""
    _control_plane().write_file(_verified_identity(), device_id, path, content, timeout)
    return {"status": "ok"}


def _http_app():
    """Build the production ASGI app with complete OAuth metadata."""
    sdk_app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=transport_security,
        host="127.0.0.1",
    )
    return ProtectedResourceMetadataOverride(sdk_app, auth_config)


def main() -> None:
    """Run the MCP server using Streamable HTTP."""
    uvicorn.run(_http_app(), host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
