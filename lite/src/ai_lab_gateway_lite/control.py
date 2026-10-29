"""OAuth scope + explicit per-device authorization + SSH + metadata-only audit."""
from dataclasses import dataclass
from time import monotonic

from .audit import AuditEvent, JsonlAuditLog
from .auth import VerifiedIdentity
from .ssh_exec import CommandResult, execute, safe_read_command, safe_write_command
from .store import Store


@dataclass
class ControlPlane:
    store: Store
    audit: JsonlAuditLog

    def _invoke(self, identity: VerifiedIdentity, device_id: str, action: str,
                scope: str, command: str, timeout: int = 30, content: str | None = None) -> CommandResult:
        identity.require_scopes(scope)
        self.store.require(identity.subject, device_id, action)
        device = self.store.get_device(device_id)
        started = monotonic()
        code = None
        ok = False
        try:
            result = execute(device, command, timeout, stdin_text=content)
            code = result.exit_code
            ok = code == 0
            return result
        finally:
            self.audit.append(AuditEvent(
                subject=identity.subject, device_id=device_id, action=action,
                success=ok, duration_ms=int((monotonic()-started)*1000), exit_code=code))

    def list_devices(self, identity: VerifiedIdentity):
        identity.require_scopes("gateway:read")
        return [{"id": d.id, "name": d.name} for d in self.store.list_devices(identity.subject)]

    def device_status(self, identity: VerifiedIdentity, device_id: str):
        result = self._invoke(identity, device_id, "status", "gateway:read", "hostname", timeout=10)
        return {
            "id": device_id, "hostname": result.stdout.strip(),
            "status": "online" if result.exit_code == 0 else "error",
            "exit_code": result.exit_code,
        }

    def exec(self, identity: VerifiedIdentity, device_id: str, command: str, timeout: int = 30):
        return self._invoke(identity, device_id, "exec", "gateway:control", command, timeout)

    def read_file(self, identity: VerifiedIdentity, device_id: str, path: str, timeout: int = 30):
        result = self._invoke(identity, device_id, "read_file", "gateway:read",
                              safe_read_command(path), timeout)
        if result.exit_code != 0:
            raise RuntimeError("remote read failed")
        return result.stdout

    def write_file(self, identity: VerifiedIdentity, device_id: str, path: str,
                   content: str, timeout: int = 30):
        result = self._invoke(identity, device_id, "write_file", "gateway:control",
                              safe_write_command(path), timeout, content)
        if result.exit_code != 0:
            raise RuntimeError("remote write failed")
        return {"status": "ok"}
