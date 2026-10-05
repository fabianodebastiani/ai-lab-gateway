"""Minimal AI Lab Gateway MCP server.

The first milestone intentionally exposes only a harmless status tool.
Device access and SSH execution will be added only after the MCP transport
has been validated end-to-end.
"""

from datetime import datetime, timezone
import platform
import socket

from pydantic import AnyHttpUrl
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .auth import Auth0TokenVerifier, AuthConfig

auth_config = AuthConfig.from_env()

mcp = MCPServer(
    "AI Lab Gateway",
    description="Remote MCP gateway for controlled access to Linux lab devices",
    version="0.1.0",
    token_verifier=Auth0TokenVerifier(auth_config),
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(auth_config.issuer),
        resource_server_url=AnyHttpUrl("https://gateway.debasti.com/mcp"),
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


def main() -> None:
    """Run the MCP server using Streamable HTTP."""
    mcp.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=8000,
        json_response=True,
        stateless_http=True,
        transport_security=transport_security,
    )


if __name__ == "__main__":
    main()
