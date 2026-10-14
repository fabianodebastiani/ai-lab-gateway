"""Three explicit access modes for an enrolled Linux device.

This module models grants; enforcement MUST happen on the target (or a
privileged per-target broker), never by merely hiding UI controls.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
import time

DEVICE_ID = re.compile(r"^[a-z][a-z0-9-]{2,47}$")
DURATIONS = (900, 1800, 3600, 7200, 14400, 28800, 86400)


class AccessMode(str, Enum):
    RESTRICTED = "restricted"
    PARTIAL = "partial"
    UNRESTRICTED = "unrestricted"


@dataclass(frozen=True)
class AccessSelection:
    """The exact three-radio-button UI contract.

    Only PARTIAL exposes a duration dropdown. Restricted and unrestricted
    have no duration field. An unrestricted grant requires explicit approval
    at the call site and MUST NOT be the enrollment default.
    """
    mode: AccessMode
    duration_seconds: int | None = None

    @classmethod
    def validate(cls, mode: str, duration_seconds: int | None = None) -> "AccessSelection":
        try:
            selection = AccessMode(mode)
        except (ValueError, TypeError):
            raise ValueError("invalid access mode; choose restricted, partial, or unrestricted") from None
        if selection is AccessMode.PARTIAL:
            if type(duration_seconds) is not int or duration_seconds not in DURATIONS:
                raise ValueError("partial access requires a supported dropdown duration")
        elif duration_seconds is not None:
            raise ValueError("only partial access may specify a duration")
        return cls(selection, duration_seconds)


@dataclass(frozen=True)
class AccessGrant:
    """Auditable access choice for one device and one operator.

    The privilege window is checked on EACH privileged command, not at
    connection time. Grant records alone do NOT grant sudo: an enforcing
    component on the target must validate them.
    """
    device_id: str
    approved_by: str
    mode: AccessMode
    created_at: int
    expires_at: int | None = None

    @classmethod
    def issue(
        cls, device_id: str, approved_by: str, selection: AccessSelection,
        *, explicit_confirmation: bool, now: int | None = None,
    ) -> "AccessGrant":
        if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
            raise ValueError("invalid device id")
        if not isinstance(approved_by, str) or not approved_by.strip():
            raise ValueError("approved_by must be an authenticated identity")
        if explicit_confirmation is not True:
            raise PermissionError("explicit human confirmation required")
        moment = int(time.time()) if now is None else now
        if type(moment) is not int or moment < 0:
            raise ValueError("invalid grant time")
        if selection.mode is AccessMode.PARTIAL:
            if selection.duration_seconds not in DURATIONS:
                raise ValueError("unsupported temporary duration")
            deadline = moment + selection.duration_seconds
        else:
            deadline = None
        return cls(
            device_id=device_id, approved_by=approved_by, mode=selection.mode,
            created_at=moment, expires_at=deadline,
        )

    def effective_mode(self, *, now: int | None = None) -> AccessMode:
        moment = int(time.time()) if now is None else now
        if self.mode is AccessMode.PARTIAL and (
            self.expires_at is None or moment >= self.expires_at
        ):
            return AccessMode.RESTRICTED
        return self.mode

    def administrative_access(self, *, now: int | None = None) -> bool:
        return self.effective_mode(now=now) is not AccessMode.RESTRICTED


DEFAULT_SELECTION = AccessSelection(AccessMode.RESTRICTED)
