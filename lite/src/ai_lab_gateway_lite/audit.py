"""Append-only JSONL audit records for gateway actions."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(frozen=True)
class AuditEvent:
    subject: str
    device_id: str
    action: str
    success: bool
    duration_ms: int
    exit_code: int | None = None

    def to_record(self) -> dict:
        return {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            **asdict(self),
        }


class JsonlAuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, event: AuditEvent) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_record(), separators=(",", ":"), ensure_ascii=False)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
