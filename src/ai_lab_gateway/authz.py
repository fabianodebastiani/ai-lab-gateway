"""Application-level user-to-device authorization.

Platform users are identities established by the MCP authentication layer.
They are deliberately independent from Unix accounts on the gateway and target.
"""

from dataclasses import dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class Principal:
    subject: str


class AuthorizationPolicy:
    def __init__(self, grants: dict[str, dict[str, set[str]]]):
        self._grants = grants

    @classmethod
    def load(cls, path: str | Path) -> "AuthorizationPolicy":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        grants: dict[str, dict[str, set[str]]] = {}

        for user in raw.get("users", []):
            subject = str(user["subject"])
            if subject in grants:
                raise ValueError(f"duplicate subject: {subject}")
            grants[subject] = {
                str(device_id): set(map(str, actions))
                for device_id, actions in user.get("devices", {}).items()
            }

        return cls(grants)

    def allows(self, principal: Principal, device_id: str, action: str) -> bool:
        return action in self._grants.get(principal.subject, {}).get(device_id, set())

    def require(self, principal: Principal, device_id: str, action: str) -> None:
        if not self.allows(principal, device_id, action):
            raise PermissionError(
                f"subject {principal.subject!r} is not allowed to {action!r} "
                f"on device {device_id!r}"
            )
