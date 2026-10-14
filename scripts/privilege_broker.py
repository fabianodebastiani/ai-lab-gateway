#!/usr/bin/env python3
"""AI Lab privileged broker v0.3: local root-only prototype.

This is NOT a remotely approvable interface. Root bootstrap can issue grants.
All operations are fixed argv read-only commands, never shell strings.
"""
import argparse
import fcntl
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

STATE = Path("/var/lib/ai-lab-privilege-broker")
DB = STATE / "grants.json"
AUDIT = STATE / "audit.jsonl"
LOCK = STATE / "lock"
OPS = {
    "gateway-service-status": ["/usr/bin/systemctl", "is-active", "ai-lab-gateway"],
    "gateway-service-enabled": ["/usr/bin/systemctl", "is-enabled", "ai-lab-gateway"],
}
MAX_TTL = 86400

def audit(action, result, grant_id=None, subject=None):
    entry = {"time": int(time.time()), "action": action, "result": result,
             "grant_id": grant_id, "subject": subject}
    with AUDIT.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())

def load():
    if not DB.exists():
        return {}
    data = json.loads(DB.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("invalid grant database")
    return data

def save(data):
    fd, tmp = tempfile.mkstemp(prefix=".grant-", dir=STATE)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, DB)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

@contextmanager
def locked():
    STATE.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE, 0o700)
    with LOCK.open("a+") as lock:
        os.chmod(LOCK, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield

def run(args):
    with locked():
        AUDIT.touch(exist_ok=True)
        os.chmod(AUDIT, 0o600)
        data = load()
        if args.command == "status":
            audit("status", "ok")
            print(json.dumps({"version": "0.3-local", "grants": len(data),
                "operations": sorted(OPS), "remote_approval_enabled": False,
                "arbitrary_shell_enabled": False, "locking": "flock"}))
            return 0
        if args.command == "issue":
            if not 1 <= args.ttl <= MAX_TTL:
                audit("issue", "denied")
                return 77
            grant_id = secrets.token_urlsafe(24)
            data[grant_id] = {"operation": args.operation,
                "expires_at": int(time.time()) + args.ttl,
                "subject": args.subject, "state": "active",
                "issuer": "local-root-bootstrap"}
            save(data)
            audit("issue", "ok", grant_id, args.subject)
            print(json.dumps({"grant_id": grant_id, "operation": args.operation,
                "subject": args.subject, "expires_at": data[grant_id]["expires_at"]}))
            return 0
        grant = data.get(args.grant_id)
        if not grant:
            audit(args.command, "denied")
            return 77
        if grant.get("subject") != args.subject:
            audit(args.command, "subject_mismatch", args.grant_id, args.subject)
            return 77
        if args.command == "revoke":
            grant["state"] = "revoked"
            save(data)
            audit("revoke", "ok", args.grant_id, args.subject)
            print("revoked")
            return 0
        if (grant.get("state") != "active"
            or int(time.time()) >= grant.get("expires_at", 0)
            or grant.get("operation") not in OPS):
            audit("execute", "denied", args.grant_id, args.subject)
            return 77
        grant["state"] = "consumed"
        save(data)
        # Lock stays held until operation completes: no concurrent replay.
        result = subprocess.run(OPS[grant["operation"]], shell=False,
                                capture_output=True, text=True, timeout=15)
        audit("execute", "ok" if result.returncode == 0 else "failed",
              args.grant_id, args.subject)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

def main():
    if os.geteuid() != 0:
        raise PermissionError("root required")
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("status")
    issue = subs.add_parser("issue")
    issue.add_argument("operation", choices=sorted(OPS))
    issue.add_argument("--ttl", type=int, default=1800)
    issue.add_argument("--subject", required=True)
    for command in ("execute", "revoke"):
        p = subs.add_parser(command)
        p.add_argument("grant_id")
        p.add_argument("--subject", required=True)
    return run(parser.parse_args())

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PermissionError, ValueError, subprocess.TimeoutExpired) as exc:
        print("DENIED:", type(exc).__name__, file=sys.stderr)
        sys.exit(77)
