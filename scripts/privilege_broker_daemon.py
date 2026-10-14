#!/usr/bin/env python3
"""AI Lab Gateway privilege broker daemon (prototype).

Root-owned Unix socket service. The MCP gateway authenticates OAuth subjects;
the broker trusts only its dedicated Unix service UID to forward that identity.
Root console CLI is the ONLY approval interface. No arbitrary shell commands.
"""
import argparse
import fcntl
import json
import os
import pwd
import secrets
import stat
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

STATE = Path("/var/lib/ai-lab-privilege-broker")
DB = STATE / "requests.json"
AUDIT = STATE / "requests-audit.jsonl"
LOCK = STATE / "requests.lock"
SOCKET = Path("/run/ai-lab-privilege-broker/broker.sock")
OPERATIONS = {
    "gateway-service-status": ("/usr/bin/systemctl", "is-active", "ai-lab-gateway"),
    "gateway-service-enabled": ("/usr/bin/systemctl", "is-enabled", "ai-lab-gateway"),
    "broker-root-write-selftest": ("/usr/bin/touch", "/var/lib/ai-lab-privilege-broker/root-write-selftest.ok"),
}
MAX_TTL = 86400
MAX_REQUEST_BYTES = 16384
PENDING_TTL = 3600
MAX_PENDING_PER_SUBJECT = 20

def audit(action, outcome, request_id=None, subject=None):
    event = {"time": int(time.time()), "action": action, "outcome": outcome,
             "request_id": request_id, "subject": subject}
    with AUDIT.open("a", encoding="utf8") as f:
        f.write(json.dumps(event, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())

def load():
    if not DB.exists():
        return {}
    value = json.loads(DB.read_text(encoding="utf8"))
    if not isinstance(value, dict):
        raise ValueError("invalid request store")
    return value

def save(value):
    fd, tmp = tempfile.mkstemp(prefix=".request-", dir=STATE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(value, f, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, DB)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

@contextmanager
def locked():
    with LOCK.open("a+") as f:
        os.chmod(LOCK, 0o600)
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield

def check_subject(value):
    return isinstance(value, str) and 1 <= len(value) <= 256 and all(32 <= ord(ch) < 127 for ch in value)

def dispatch(message):
    if not isinstance(message, dict):
        return {"ok": False, "error": "invalid_request"}
    action = message.get("action")
    subject = message.get("subject")
    if not check_subject(subject):
        audit("unknown", "invalid_subject")
        return {"ok": False, "error": "invalid_subject"}
    with locked():
        entries = load()
        now = int(time.time())
        if action == "request":
            operation = message.get("operation")
            ttl = message.get("ttl_seconds")
            if not isinstance(operation, str) or operation not in OPERATIONS or type(ttl) is not int or not 1 <= ttl <= MAX_TTL:
                audit("request", "invalid_parameters", subject=subject)
                return {"ok": False, "error": "invalid_parameters"}
            pending_count = sum(
                1 for item in entries.values()
                if item.get("subject") == subject
                and item.get("status") == "pending"
                and now < item.get("approval_deadline", 0)
            )
            if pending_count >= MAX_PENDING_PER_SUBJECT:
                audit("request", "pending_quota_reached", subject=subject)
                return {"ok": False, "error": "pending_quota_reached"}
            request_id = secrets.token_urlsafe(24)
            entries[request_id] = {
                "subject": subject, "operation": operation, "ttl_seconds": ttl,
                "created_at": now, "approval_deadline": now + PENDING_TTL,
                "status": "pending", "device_id": "oracle-gateway"}
            save(entries)
            audit("request", "pending", request_id, subject)
            return {"ok": True, "request_id": request_id, "status": "pending",
                    "operation": operation, "approval_deadline": now + PENDING_TTL}
        request_id = message.get("request_id")
        entry = entries.get(request_id) if isinstance(request_id, str) else None
        if not entry or entry.get("subject") != subject:
            audit(str(action), "not_found_or_wrong_subject", subject=subject)
            return {"ok": False, "error": "not_found"}
        # Expiry is enforced at each access and persisted.
        if entry["status"] == "pending" and now >= entry["approval_deadline"]:
            entry["status"] = "expired"
            save(entries)
        if entry["status"] == "approved" and now >= entry["expires_at"]:
            entry["status"] = "expired"
            save(entries)
        if action == "status":
            audit("status", "ok", request_id, subject)
            return {"ok": True, "request_id": request_id, "operation": entry["operation"],
                    "status": entry["status"], "expires_at": entry.get("expires_at")}
        if action == "revoke":
            if entry["status"] in ("pending", "approved"):
                entry["status"] = "revoked"
                save(entries)
            audit("revoke", "ok", request_id, subject)
            return {"ok": True, "request_id": request_id, "status": entry["status"]}
        if action == "execute":
            if entry["status"] != "approved" or entry["operation"] not in OPERATIONS:
                audit("execute", "denied", request_id, subject)
                return {"ok": False, "error": "not_approved", "status": entry["status"]}
            entry["status"] = "consumed"
            save(entries)  # Consume BEFORE command: durable replay defense.
            try:
                p = subprocess.run(OPERATIONS[entry["operation"]], shell=False,
                                   capture_output=True, text=True, timeout=15)
                audit("execute", "ok" if p.returncode == 0 else "failed", request_id, subject)
                return {"ok": p.returncode == 0, "status": "consumed",
                        "exit_code": p.returncode, "stdout": p.stdout[:4096],
                        "stderr": p.stderr[:4096]}
            except subprocess.TimeoutExpired:
                audit("execute", "timeout", request_id, subject)
                return {"ok": False, "error": "timeout", "status": "consumed"}
        audit(str(action), "unsupported", request_id, subject)
        return {"ok": False, "error": "unsupported_action"}

def admin(command, request_id=None):
    if command == "list":
        with locked():
            entries = load()
            out = [
                {"request_id": rid, "operation": e["operation"],
                 "status": e["status"], "created_at": e["created_at"],
                 "approval_deadline": e["approval_deadline"], "subject": e["subject"]}
                for rid, e in entries.items() if e["status"] == "pending"]
        print(json.dumps(out, indent=2))
        return 0
    with locked():
        entries = load()
        entry = entries.get(request_id)
        if not entry or entry["status"] != "pending":
            print("DENIED: no pending request", file=sys.stderr)
            return 77
        now = int(time.time())
        if now >= entry["approval_deadline"]:
            entry["status"] = "expired"
            save(entries)
            return 77
        entry["status"] = "approved" if command == "approve" else "denied"
        if command == "approve":
            entry["approved_at"] = now
            entry["expires_at"] = now + entry["ttl_seconds"]
        save(entries)
        audit("admin_" + command, "ok", request_id, entry["subject"])
        print(json.dumps({"request_id": request_id, "status": entry["status"],
                          "operation": entry["operation"],
                          "expires_at": entry.get("expires_at")}))
        return 0

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(10)
        try:
            creds = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", creds)
            allowed = pwd.getpwnam("ai-lab-gateway").pw_uid
            if uid != allowed:
                self.wfile.write(b'{"ok":false,"error":"unauthorized_peer"}\n')
                return
            raw = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
                return
            result = dispatch(json.loads(raw))
            self.wfile.write((json.dumps(result, separators=(",", ":")) + "\n").encode())
        except (ValueError, json.JSONDecodeError, OSError, KeyError) as exc:
            try:
                self.wfile.write(b'{"ok":false,"error":"invalid_message"}\n')
            except OSError:
                pass

class ThreadServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

def daemon():
    gid = pwd.getpwnam("ai-lab-gateway").pw_gid
    SOCKET.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(SOCKET.parent, 0, gid)
    os.chmod(SOCKET.parent, 0o750)
    # Recover from a crash that left behind a stale Unix socket. Never remove
    # a non-socket path or the socket of a still-running server.
    try:
        existing = SOCKET.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if not stat.S_ISSOCK(existing.st_mode) or existing.st_uid != 0:
            raise RuntimeError("unexpected socket path: refusing to replace")
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(1)
            try:
                probe.connect(str(SOCKET))
            except ConnectionRefusedError:
                SOCKET.unlink()
            else:
                raise RuntimeError("another broker is already listening")
    with ThreadServer(str(SOCKET), Handler) as server:
        os.chown(SOCKET, 0, gid)
        os.chmod(SOCKET, 0o660)
        server.serve_forever(poll_interval=0.25)

def main():
    if os.geteuid() != 0:
        raise PermissionError("root required")
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    AUDIT.touch(exist_ok=True)
    os.chmod(AUDIT, 0o600)
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--serve", action="store_true")
    group.add_argument("--list", action="store_true")
    group.add_argument("--approve")
    group.add_argument("--deny")
    args = parser.parse_args()
    if args.serve:
        daemon()
        return 0
    if args.list:
        return admin("list")
    if args.approve:
        return admin("approve", args.approve)
    return admin("deny", args.deny)

if __name__ == "__main__":
    sys.exit(main())
