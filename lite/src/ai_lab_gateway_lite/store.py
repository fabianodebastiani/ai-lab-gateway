"""SQLite registry and deny-by-default user-device authorization."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import sqlite3

ACTIONS = frozenset(("status", "read_file", "exec", "write_file"))
ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
KEY_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$")


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    host: str
    port: int
    ssh_user: str
    key_name: str
    enabled: bool = True


def allowed_networks(value: str | None = None) -> tuple:
    raw = value if value is not None else os.environ.get("LITE_ALLOWED_SSH_CIDRS", "")
    if not raw.strip():
        raise ValueError("LITE_ALLOWED_SSH_CIDRS is required (fail closed)")
    networks = tuple(ipaddress.ip_network(p.strip(), strict=False) for p in raw.split(",") if p.strip())
    if not networks or any(net.prefixlen < 8 for net in networks):
        raise ValueError("wireguard allowlist may not contain unrestricted networks")
    return networks


def validate_device(device: Device, networks: tuple | None = None) -> None:
    if not ID_RE.fullmatch(device.id):
        raise ValueError("invalid device ID")
    if not 1 <= len(device.name) <= 120:
        raise ValueError("invalid device name")
    if not 1 <= device.port <= 65535:
        raise ValueError("invalid SSH port")
    if not USER_RE.fullmatch(device.ssh_user) or device.ssh_user == "root":
        raise ValueError("SSH user must be a valid non-root account")
    if not KEY_RE.fullmatch(device.key_name) or device.key_name.startswith(".") or ".." in device.key_name:
        raise ValueError("invalid SSH key name")
    ip = ipaddress.ip_address(device.host)  # DNS names are intentionally forbidden
    approved = networks if networks is not None else allowed_networks()
    if ip.is_loopback:
        # Isolated self-SSH pilot only: no WireGuard, no public SSH target and no
        # reuse of the original ai-gateway management identity. This exception
        # requires BOTH an explicit opt-in and a /32 network allowlist.
        if (str(ip) != "127.0.0.1"
                or os.environ.get("LITE_ENABLE_LOOPBACK_TARGET") != "1"
                or ipaddress.ip_network("127.0.0.1/32") not in approved
                or device.port != 22 or device.ssh_user != "lite-target"):
            raise ValueError("loopback SSH pilot requires explicit opt-in, 127.0.0.1:22 and lite-target")
    elif ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ValueError("SSH device must use an approved internal IP")
    if not any(ip in net for net in approved):
        raise ValueError("SSH address is outside approved SSH CIDRs")


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @classmethod
    def from_env(cls) -> "Store":
        return cls(os.environ.get("LITE_DATABASE", "/var/lib/ai-lab-gateway-lite/lite.sqlite3"))

    @contextmanager
    def connection(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys = ON")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self):
        with self.connection() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users(
                    subject TEXT PRIMARY KEY,
                    email TEXT NOT NULL DEFAULT '',
                    display_name TEXT NOT NULL DEFAULT '',
                    last_seen TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS devices(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    ssh_user TEXT NOT NULL,
                    key_name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS grants(
                    subject TEXT NOT NULL REFERENCES users(subject) ON DELETE CASCADE,
                    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                    action TEXT NOT NULL,
                    PRIMARY KEY (subject, device_id, action)
                );
                CREATE INDEX IF NOT EXISTS grants_subject ON grants(subject);
            """)

    def record_user(self, subject: str, email: str = "", display_name: str = ""):
        if not subject or len(subject) > 256:
            raise ValueError("invalid Auth0 subject")
        with self.connection() as db:
            db.execute("""INSERT INTO users (subject, email, display_name) VALUES (?, ?, ?)
                ON CONFLICT(subject) DO UPDATE SET
                    email=excluded.email, display_name=excluded.display_name,
                    last_seen=CURRENT_TIMESTAMP""", (subject, email[:255], display_name[:120]))

    def list_users(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT subject, email, display_name, last_seen FROM users ORDER BY last_seen DESC")]

    def save_device(self, device: Device):
        validate_device(device)
        with self.connection() as db:
            db.execute("""INSERT INTO devices(id,name,host,port,ssh_user,key_name,enabled)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,host=excluded.host,port=excluded.port,
                ssh_user=excluded.ssh_user,key_name=excluded.key_name,enabled=excluded.enabled
                """, (device.id, device.name, device.host, device.port, device.ssh_user, device.key_name, int(device.enabled)))

    def list_devices(self, subject: str | None = None):
        with self.connection() as db:
            if subject is None:
                rows = db.execute("SELECT * FROM devices ORDER BY id")
            else:
                rows = db.execute("""SELECT DISTINCT d.* FROM devices d
                    INNER JOIN grants g ON g.device_id=d.id
                    WHERE d.enabled=1 AND g.subject=?
                    ORDER BY d.id""", (subject,))
            return [Device(**{**dict(r), "enabled": bool(r["enabled"])}) for r in rows]

    def get_device(self, device_id: str):
        with self.connection() as db:
            row = db.execute("SELECT * FROM devices WHERE id=? AND enabled=1", (device_id,)).fetchone()
        if row is None:
            raise PermissionError("unknown or disabled device")
        device = Device(**{**dict(row), "enabled": bool(row["enabled"])})
        validate_device(device)
        return device

    def permits(self, subject: str, device_id: str, action: str) -> bool:
        if action not in ACTIONS:
            return False
        with self.connection() as db:
            row = db.execute("""SELECT 1 FROM grants g
                JOIN devices d ON d.id=g.device_id
                WHERE g.subject=? AND g.device_id=? AND g.action=? AND d.enabled=1""",
                (subject, device_id, action)).fetchone()
        return row is not None

    def require(self, subject: str, device_id: str, action: str):
        if not self.permits(subject, device_id, action):
            raise PermissionError("not authorized for this device/action")

    def set_grant(self, subject: str, device_id: str, action: str, enable: bool):
        if action not in ACTIONS:
            raise ValueError("invalid action")
        with self.connection() as db:
            if enable:
                db.execute("INSERT OR IGNORE INTO grants(subject, device_id, action) VALUES(?,?,?)",
                           (subject, device_id, action))
            else:
                db.execute("DELETE FROM grants WHERE subject=? AND device_id=? AND action=?",
                           (subject, device_id, action))

    def list_grants(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute("SELECT subject, device_id, action FROM grants ORDER BY subject, device_id, action")]
