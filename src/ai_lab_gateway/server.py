"""Minimal AI Lab Gateway MCP server.

The first milestone intentionally exposes only a harmless status tool.
Device access and SSH execution will be added only after the MCP transport
has been validated end-to-end.
"""

from datetime import datetime, timezone
import platform
import socket

from mcp.server.mcpserver import MCPServer

mcp = MCPServer(
    "AI Lab Gateway",
    description="Remote MCP gateway for controlled access to Linux lab devices",
    version="0.1.0",
)


@mcp.tool()
def gateway_status() -> dict[str, str]:
    """Return basic status of the AI Lab Gateway service."""
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
    )


if __name__ == "__main__":
    main()
