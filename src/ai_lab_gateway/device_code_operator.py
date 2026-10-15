"""Isolated UNIX operator lookup boundary for ADR-029, NOT DEPLOYED.

The anonymous device HTTP listener cannot read authenticated principals or
approve device pairing. This companion UNIX socket checks peer Linux UID and
lets the existing Auth0-authenticated MCP identity reserve a proven device
code. No confirm/activate/root operation is exposed through this adapter.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct

from .device_code import DeviceCodeStore

RPC_LIMIT = 2048
ANSWER_LIMIT = 4096
DEFAULT_SOCKET = Path("/run/ai-lab-device-code/operator.sock")


class OperatorProtocol:
    def __init__(self, store: DeviceCodeStore):
        self.store = store

    def dispatch(self, message: object) -> dict:
        if not isinstance(message, dict) or set(message) != {"action", "subject", "user_code"}:
            return {"ok": False, "error": "invalid_request"}
        if message["action"] != "lookup":
            return {"ok": False, "error": "unsupported"}
        try:
            result = self.store.lookup(
                user_code=message["user_code"],
                operator_subject=message["subject"],
            )
            return {"ok": True, "request": result}
        except (TypeError, ValueError, PermissionError, KeyError):
            return {"ok": False, "error": "pairing_unavailable"}


class ThreadedUnix(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def operator_handler(protocol: OperatorProtocol, *, allowed_gateway_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            # The caller's UID is enforced by the kernel, NOT by supplied JSON.
            pid, uid, gid = struct.unpack(
                "3i", self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            )
            if uid != allowed_gateway_uid:
                self._send({"ok": False, "error": "unauthorized_peer"})
                return
            message = self.rfile.readline(RPC_LIMIT + 1)
            if len(message) > RPC_LIMIT or not message.endswith(b"\n"):
                self._send({"ok": False, "error": "invalid_request"})
                return
            try:
                decoded = json.loads(message)
            except (UnicodeError, ValueError):
                self._send({"ok": False, "error": "invalid_request"})
                return
            self._send(protocol.dispatch(decoded))

        def _send(self, result: dict):
            value = (json.dumps(result, separators=(",", ":")) + "\n").encode("utf-8")
            self.wfile.write(value)

    return Handler


def create_operator_socket(path: Path, store: DeviceCodeStore, *,
                           allowed_gateway_uid: int) -> ThreadedUnix:
    """Use only in protected standalone staging. Production: systemd socket."""
    if path.exists() or path.is_symlink():
        raise PermissionError("refusing existing operator socket")
    folder = path.parent
    if not folder.is_dir() or folder.is_symlink():
        raise PermissionError("a private runtime directory is required")
    mode = folder.stat()
    if (mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) != 0o700):
        raise PermissionError("runtime directory must be mode 0700 and owner-only")
    srv = ThreadedUnix(str(path), operator_handler(
        OperatorProtocol(store), allowed_gateway_uid=allowed_gateway_uid))
    os.chmod(path, 0o600)
    return srv


def call_operator_lookup(*, path: Path, subject: str, user_code: str) -> dict:
    """Client-side primitive; only call after OAuth control + enroll grant."""
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise ValueError("verified operator subject required")
    if not isinstance(user_code, str) or not 1 <= len(user_code) <= 24:
        raise ValueError("invalid user code")
    payload = json.dumps({
        "action": "lookup", "subject": subject, "user_code": user_code,
    }, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        sock.sendall(payload)
        reply = bytearray()
        while not reply.endswith(b"\n"):
            data = sock.recv(1024)
            if not data:
                raise ConnectionError("operator IPC unexpectedly disconnected")
            reply.extend(data)
            if len(reply) > ANSWER_LIMIT:
                raise ValueError("operator IPC response too large")
    result = json.loads(reply)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise PermissionError("pairing code unavailable or unauthorized")
    return result["request"]
