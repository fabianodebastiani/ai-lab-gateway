#!/usr/bin/env python3
"""Dual-boundary device enrollment v2 service.

- HTTPS claim handler (Caddy -> loopback 127.0.0.1:8002) accepts a one-time
  pairing invitation but cannot approve or activate a device.
- A Unix control socket only accepts the MCP server's Linux UID, and can
  issue invitations/check the OAuth subject's claims.
- A separate Unix approval socket only accepts the independent browser
  approver Linux UID, and can review pending pairings.
- Only local root through the approval socket may read approved SSH key
  material for trusted provisioning or record verified activation.

The service itself has no sudo, no SSH management private keys, and cannot
modify the production registry or tunnel-account authorized_keys.
"""
from __future__ import annotations

import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import socket
import socketserver
import stat
import struct
import threading

from ai_lab_gateway.enrollment import EnrollmentStore, INVITE_TTL
from ai_lab_gateway.enrollment_http import run_claim_server

STATE = Path("/var/lib/ai-lab-pairing")
RUNTIME = Path("/run/ai-lab-pairing")
MCP_SOCKET = RUNTIME / "mcp.sock"
APPROVER_SOCKET = RUNTIME / "approver.sock"
MAX_RPC = 8192


class PairingRPC:
    def __init__(self, store: EnrollmentStore):
        self.store = store

    def dispatch(self, role: str, message: object) -> dict:
        if not isinstance(message, dict):
            return {"ok": False, "error": "invalid_request"}
        action = message.get("action")
        try:
            if role == "mcp":
                subject = message.get("subject")
                if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
                    raise ValueError("invalid subject")
                if action == "invite":
                    # A token does NOT authorize a device; independent human
                    # approval and trusted root provisioning are still needed.
                    token = self.store.invite(subject)
                    return {"ok": True, "token": token,
                            "expires_in": INVITE_TTL, "status": "invited"}
                if action == "list_mine":
                    return {"ok": True,
                            "requests": self.store.my_requests(subject)}
                if action == "status":
                    value = self.store.inspect(message.get("request_id"),
                                               operator_subject=subject)
                    # Minimize data returned over MCP; avoid raw SSH pubkeys.
                    for key in ("tunnel_public_key", "ssh_host_public_key"):
                        value.pop(key, None)
                    return {"ok": True, "request": value}
                return {"ok": False, "error": "unsupported"}
            if role == "approver":
                if action == "list":
                    return {"ok": True, "requests": self.store.pending_requests()}
                if action in {"approve", "deny"}:
                    result = self.store.review(
                        message.get("request_id"),
                        human_actor="authenticated-approval-web",
                        approve=action == "approve"
                    )
                    return {"ok": True, **result}
                return {"ok": False, "error": "unsupported"}
            if role == "root":
                if action == "inspect":
                    return {"ok": True,
                            "request": self.store.inspect(message.get("request_id"))}
                if action == "activate":
                    result = self.store.activation_record(
                        message.get("request_id"),
                        host_public_key=message.get("ssh_host_public_key"),
                        tunnel_public_key=message.get("tunnel_public_key")
                    )
                    return {"ok": True, **result}
                return {"ok": False, "error": "unsupported"}
        except (ValueError, KeyError, PermissionError, TypeError) as exc:
            # Reject without reflecting raw tokens/SSH material.
            return {"ok": False, "error": type(exc).__name__}
        return {"ok": False, "error": "denied"}


class ThreadedUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def unix_handler(app: PairingRPC, *, role: str, expected_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            uid_data = self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", uid_data)
            if uid != expected_uid and not (role == "approver" and uid == 0):
                self._reply({"ok": False, "error": "unauthorized_peer"})
                return
            line = self.rfile.readline(MAX_RPC + 1)
            if not line.endswith(b"\n") or len(line) > MAX_RPC:
                self._reply({"ok": False, "error": "invalid_body"})
                return
            try:
                data = json.loads(line)
            except (ValueError, UnicodeError):
                self._reply({"ok": False, "error": "bad_json"})
                return
            auth_role = "root" if (role == "approver" and uid == 0) else role
            self._reply(app.dispatch(auth_role, data))

        def _reply(self, payload: dict):
            self.wfile.write(
                (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            )

        def log_message(self, *args):
            pass

    return Handler


def start_unix_server(path: Path, group_name: str, app: PairingRPC,
                      role: str, uid: int):
    if path.exists() or path.is_symlink():
        # Fail closed: never unlink someone else's socket or symlink.
        raise RuntimeError(f"socket path already exists: {path}")
    server = ThreadedUnixServer(str(path), unix_handler(
        app, role=role, expected_uid=uid
    ))
    try:
        gid = grp.getgrnam(group_name).gr_gid
        if gid not in os.getgroups() and gid != os.getegid():
            raise PermissionError("service lacks expected Unix group")
        os.chown(path, -1, gid)
        os.chmod(path, 0o660)
    except BaseException:
        server.server_close()
        path.unlink(missing_ok=True)
        raise
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    if os.geteuid() == 0:
        raise PermissionError("pairing service must run as a non-root identity")
    if not STATE.is_dir() or not RUNTIME.is_dir():
        raise RuntimeError("StateDirectory and RuntimeDirectory required")
    app = PairingRPC(EnrollmentStore(STATE / "pairing.sqlite3"))
    gateway_uid = pwd.getpwnam("ai-lab-gateway").pw_uid
    approver_uid = pwd.getpwnam("ai-lab-approver").pw_uid
    with start_unix_server(MCP_SOCKET, "ai-lab-gateway",
                           app, "mcp", gateway_uid) as mcp_sock, \
         start_unix_server(APPROVER_SOCKET, "ai-lab-approver",
                           app, "approver", approver_uid) as approver_sock:
        run_claim_server(app.store, port=8002)


if __name__ == "__main__":
    main()
