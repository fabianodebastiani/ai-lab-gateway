"""Authenticated control-plane orchestration.

This module joins identity, OAuth scope, application authorization, registry,
SSH execution and audit. It is intentionally independent from MCP transport so
the security path can be tested before public tools are registered.
"""

from dataclasses import dataclass
from time import monotonic

from .audit import AuditEvent, JsonlAuditLog
from .auth import VerifiedIdentity
from .authz import AuthorizationPolicy, Principal
from .registry import DeviceRegistry
from .ssh_exec import CommandResult, execute


@dataclass
class ControlPlane:
    registry: DeviceRegistry
    policy: AuthorizationPolicy
    audit: JsonlAuditLog

    def _authorize(self, identity: VerifiedIdentity, device_id: str, action: str,
                   scope: str) -> None:
        identity.require_scopes(scope)
        self.policy.require(Principal(identity.subject), device_id, action)

    def list_devices(self, identity: VerifiedIdentity) -> list[dict[str, str]]:
        identity.require_scopes("gateway:read")
        visible = []
        principal = Principal(identity.subject)
        for device in self.registry.list_enabled():
            if any(
                self.policy.allows(principal, device.id, action)
                for action in ("status", "exec", "read_file", "write_file")
            ):
                visible.append({"id": device.id, "name": device.name})
        return visible

    def device_status(self, identity: VerifiedIdentity, device_id: str) -> dict[str, str | int]:
        """Return minimal live status from an authorized device over SSH."""
        self._authorize(identity, device_id, "status", "gateway:read")
        device = self.registry.get(device_id)
        started = monotonic()
        result: CommandResult | None = None
        success = False
        try:
            result = execute(device, "hostname", 10)
            success = result.exit_code == 0
            return {
                "id": device.id,
                "name": device.name,
                "hostname": result.stdout.strip(),
                "status": "online" if success else "error",
                "exit_code": result.exit_code,
            }
        finally:
            duration_ms = int((monotonic() - started) * 1000)
            self.audit.append(AuditEvent(
                subject=identity.subject,
                device_id=device_id,
                action="status",
                success=success,
                duration_ms=duration_ms,
                exit_code=result.exit_code if result else None,
            ))

    def exec(self, identity: VerifiedIdentity, device_id: str, command: str,
             timeout: int = 30) -> CommandResult:
        self._authorize(identity, device_id, "exec", "gateway:control")
        device = self.registry.get(device_id)
        started = monotonic()
        result: CommandResult | None = None
        success = False
        try:
            result = execute(device, command, timeout)
            success = result.exit_code == 0
            return result
        finally:
            duration_ms = int((monotonic() - started) * 1000)
            self.audit.append(AuditEvent(
                subject=identity.subject,
                device_id=device_id,
                action="exec",
                success=success,
                duration_ms=duration_ms,
                exit_code=result.exit_code if result else None,
            ))
