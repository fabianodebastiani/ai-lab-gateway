"""AI Lab Gateway MCP server.

The public MCP surface provides a small set of generic remote-Linux primitives.
OAuth scopes and the per-device authorization policy jointly gate operations.
"""

from datetime import datetime, timezone
import os
import platform
import socket

import uvicorn
from pydantic import AnyHttpUrl
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from .audit import JsonlAuditLog
from .auth import Auth0TokenVerifier, AuthConfig, identity_from_verified_claims
from .authz import AuthorizationPolicy
from .broker_client import broker_call
from .control import ControlPlane
from .pairing_client import pairing_call
from .oauth_metadata import ProtectedResourceMetadataOverride
from .registry import DeviceRegistry
from .scope_stepup import OAuthScopeStepUp

auth_config = AuthConfig.from_env()
token_verifier = Auth0TokenVerifier(auth_config)

mcp = MCPServer(
    "AI Lab Gateway",
    description="Remote MCP gateway for controlled access to Linux lab devices",
    version="0.1.0",
    token_verifier=token_verifier,
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
def device_connection_status(device_id: str) -> dict:
    """Get live connectivity and the enabled/disabled persistence flag.

    The preference is available for any enrolled Linux with a configured
    systemd tunnel unit. Offline state is distinct from persistent=False.
    """
    return _control_plane().device_connection_status(_verified_identity(), device_id)


@mcp.tool()
def set_device_persistent(device_id: str, persistent: bool) -> dict:
    """Enable/disable automatic tunnel startup on a reachable Linux target.

    Requires explicit OAuth control scope, the per-device connection_manage
    action grant and a narrow local helper. Turning persistence off does not
    disconnect the currently active tunnel. Offline devices cannot be
    modified via the absent reverse tunnel.
    """
    return _control_plane().set_device_persistent(
        _verified_identity(), device_id, persistent
    )


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



def _authorize_privilege_request():
    """Only an authenticated and explicitly granted caller can use the broker."""
    identity = _verified_identity()
    _control_plane()._authorize(
        identity, "oracle-gateway", "privilege_request", "gateway:control"
    )
    return identity


@mcp.tool()
def privilege_request(operation: str, ttl_seconds: int = 1800) -> dict:
    """Request a supervised Oracle operation. Approval is separate and manual."""
    identity = _authorize_privilege_request()
    return broker_call("request", identity.subject, operation=operation,
                       ttl_seconds=ttl_seconds)


@mcp.tool()
def privilege_status(request_id: str) -> dict:
    """Read the state of your own supervised privilege request."""
    identity = _authorize_privilege_request()
    return broker_call("status", identity.subject, request_id=request_id)


@mcp.tool()
def privilege_execute(request_id: str) -> dict:
    """Execute one explicitly approved, predefined Oracle operation once."""
    identity = _authorize_privilege_request()
    return broker_call("execute", identity.subject, request_id=request_id)


@mcp.tool()
def privilege_revoke(request_id: str) -> dict:
    """Revoke your own pending or approved Oracle operation."""
    identity = _authorize_privilege_request()
    return broker_call("revoke", identity.subject, request_id=request_id)


def _authorize_device_pairing():
    """Require an explicit enrollment grant, separate from normal exec."""
    identity = _verified_identity()
    _control_plane()._authorize(
        identity, "oracle-gateway", "device_enroll", "gateway:control"
    )
    return identity


@mcp.tool()
def pairing_invite() -> dict:
    """Start restricted-first pairing; returns a 10-minute single-use token.

    A token only lets the target request pairing: it cannot approve, activate
    or grant administrative privileges. Human authorization is independent.
    """
    identity = _authorize_device_pairing()
    return pairing_call("invite", identity.subject)


@mcp.tool()
def pairing_requests() -> dict:
    """List your own pending/approved device pairings (no SSH secrets)."""
    identity = _authorize_device_pairing()
    return pairing_call("list_mine", identity.subject)


@mcp.tool()
def pairing_status(request_id: str) -> dict:
    """Get the state of your own device pairing request."""
    identity = _authorize_device_pairing()
    return pairing_call("status", identity.subject, request_id=request_id)


def _http_app():
    """Build the production ASGI app with complete OAuth metadata."""
    sdk_app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=transport_security,
        host="127.0.0.1",
    )
    scoped_app = OAuthScopeStepUp(sdk_app, token_verifier, auth_config)
    return ProtectedResourceMetadataOverride(scoped_app, auth_config)


def main() -> None:
    """Run the MCP server using Streamable HTTP."""
    uvicorn.run(_http_app(), host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
