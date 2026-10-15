"""Read-only, public-key-only approval handoff to a future root provisioner.

NOT DEPLOYED. The pairing-state owner serves an approved and already staged
candidate through a separate Unix socket. Only the kernel-verified installer
UID may inspect it. No call can confirm, stage, activate, modify SSH or grant
sudo. This is the approval-*read* half of a future two-service architecture.

In production the server runs under the pairing DB service UID and must set
allowed_installer_uid=0, using an independently protected root-only endpoint;
lab tests exercise the same boundary with the current unprivileged UID.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct

REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")
RPC_LIMIT = 384
REPLY_LIMIT = 4096


class ApprovalHandoff:
    def __init__(self, store):
        self.store = store

    def dispatch(self, payload: object) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"action", "request_id"}:
            return {"ok": False, "error": "invalid_request"}
        if payload["action"] != "inspect_staged_wsl":
            return {"ok": False, "error": "unsupported"}
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            return {"ok": False, "error": "invalid_request"}
        try:
            snapshot = self.store.staged_candidate_snapshot(request_id=request_id)
        except (PermissionError, ValueError, TypeError, KeyError):
            return {"ok": False, "error": "candidate_unavailable"}
        if snapshot["device_id"] != "windows-wsl" or snapshot["persistent"] is not False:
            return {"ok": False, "error": "candidate_unavailable"}
        offer = snapshot["offer"]
        if (offer.get("access_mode") != "restricted"
                or offer.get("reverse_listen_port") != 10003
                or offer.get("request_id") != request_id):
            return {"ok": False, "error": "candidate_unavailable"}
        # Never include the terminal confirmation, device secret, Auth0
        # subject, management private key, or any privileged instruction.
        return {"ok": True, "candidate": {
            "request_id": request_id, "device_id": snapshot["device_id"],
            "persistent": False, "access_mode": "restricted",
            "tunnel_public_key": snapshot["tunnel_public_key"],
            "host_public_key": snapshot["host_public_key"],
            "offer": offer,
        }}


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def _handler(protocol: ApprovalHandoff, *, allowed_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            _, uid, _ = struct.unpack(
                "3i", self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != allowed_uid:
                self._send({"ok": False, "error": "unauthorized_peer"})
                return
            raw = self.rfile.readline(RPC_LIMIT + 1)
            if len(raw) > RPC_LIMIT or not raw.endswith(b"\n"):
                self._send({"ok": False, "error": "invalid_request"})
                return
            try:
                payload = json.loads(raw)
            except (UnicodeError, ValueError):
                self._send({"ok": False, "error": "invalid_request"})
                return
            self._send(protocol.dispatch(payload))

        def _send(self, payload):
            raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            if len(raw) > REPLY_LIMIT:
                raise ValueError("approval inspection response exceeds bound")
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                return
    return Handler


def create_lab_approval_handoff(path: Path, protocol: ApprovalHandoff, *,
                                allowed_uid: int):
    """Create non-root lab Unix endpoint; production socket is not installed."""
    if os.geteuid() == 0:
        raise PermissionError("nonroot lab only")
    path = Path(path)
    folder = path.parent
    if path.exists() or path.is_symlink() or folder.is_symlink():
        raise PermissionError("unsafe handoff socket path")
    info = folder.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError("handoff directory must be private 0700")
    if type(allowed_uid) is not int or allowed_uid < 0:
        raise ValueError("invalid peer UID")
    server = _Server(str(path), _handler(protocol, allowed_uid=allowed_uid))
    os.chmod(path, 0o600)
    return server


def inspect_candidate_over_unix(path: Path, *, request_id: str) -> dict:
    """Read approved public material only; cannot trigger provisioning."""
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("invalid request ID")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        conn.sendall(json.dumps({
            "action": "inspect_staged_wsl", "request_id": request_id
        }).encode() + b"\n")
        output = bytearray()
        while not output.endswith(b"\n"):
            chunk = conn.recv(1024)
            if not chunk:
                raise ConnectionError("handoff service disconnected")
            output.extend(chunk)
            if len(output) > REPLY_LIMIT:
                raise ValueError("oversized approval handoff")
    return json.loads(output)
