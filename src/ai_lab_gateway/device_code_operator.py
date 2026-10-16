"""Isolated UNIX operator device-code boundary for ADR-029, NOT DEPLOYED.

The anonymous device HTTP listener cannot read authenticated principals or
approve device pairing. This companion UNIX socket checks peer Linux UID and
lets the Auth0-authenticated MCP identity reserve a proven device code and
submit a separate **terminal-only** confirmation PIN that the lookup tool
cannot see. No SSH activate/root/credential operation is exposed.
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
        if not isinstance(message, dict):
            return {"ok": False, "error": "invalid_request"}
        action = message.get("action")
        if action == "lookup":
            if set(message) != {"action", "subject", "user_code"}:
                return {"ok": False, "error": "invalid_request"}
            try:
                return {"ok": True, "request": self.store.lookup(
                    user_code=message["user_code"],
                    operator_subject=message["subject"])}
            except (TypeError, ValueError, PermissionError, KeyError):
                return {"ok": False, "error": "pairing_unavailable"}
        if action == "confirm":
            if set(message) != {"action", "subject", "request_id", "confirmation"}:
                return {"ok": False, "error": "invalid_request"}
            try:
                return {"ok": True, "request": self.store.confirm(
                    request_id=message["request_id"],
                    confirmation=message["confirmation"],
                    operator_subject=message["subject"])}
            except (TypeError, ValueError, PermissionError, KeyError):
                return {"ok": False, "error": "pairing_unavailable"}
        if action == "confirm_single_code":
            if set(message) != {"action", "subject", "request_id", "user_code"}:
                return {"ok": False, "error": "invalid_request"}
            try:
                return {"ok": True, "request": self.store.confirm_with_pairing_code(
                    request_id=message["request_id"],
                    user_code=message["user_code"],
                    operator_subject=message["subject"])}
            except (TypeError, ValueError, PermissionError, KeyError):
                return {"ok": False, "error": "pairing_unavailable"}
        return {"ok": False, "error": "unsupported"}

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
                           allowed_gateway_uid: int,
                           production_gateway_gid: int | None = None) -> ThreadedUnix:
    """Create a private lab socket or group-restricted production IPC.

    In production only the real Gateway group can CONNECT to the socket.
    Kernel SO_PEERCRED checks the exact Gateway UID independently.
    """
    if path.exists() or path.is_symlink():
        raise PermissionError("refusing existing operator socket")
    folder = path.parent
    if not folder.is_dir() or folder.is_symlink():
        raise PermissionError("a private runtime directory is required")
    mode = folder.stat()
    expected = 0o700 if production_gateway_gid is None else 0o711
    if (mode.st_uid != os.geteuid() or stat.S_IMODE(mode.st_mode) != expected):
        raise PermissionError("runtime directory ownership or mode mismatch")
    if production_gateway_gid is not None and (
            type(production_gateway_gid) is not int
            or production_gateway_gid not in os.getgroups()):
        raise PermissionError("production gateway group not available")
    srv = ThreadedUnix(str(path), operator_handler(
        OperatorProtocol(store), allowed_gateway_uid=allowed_gateway_uid))
    try:
        if production_gateway_gid is not None:
            os.chown(path, -1, production_gateway_gid)
        os.chmod(path, 0o600 if production_gateway_gid is None else 0o660)
        return srv
    except BaseException:
        srv.server_close()
        path.unlink(missing_ok=True)
        raise


def _operator_rpc(*, path: Path, payload: dict) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        sock.sendall(json.dumps(
            payload, separators=(",", ":")).encode("utf-8") + b"\n")
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
        raise PermissionError("pairing unavailable or unauthorized")
    return result["request"]


def call_operator_lookup(*, path: Path, subject: str, user_code: str) -> dict:
    """Client-side primitive; call after real OAuth control+device_enroll."""
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise ValueError("verified operator subject required")
    if not isinstance(user_code, str) or not 1 <= len(user_code) <= 24:
        raise ValueError("invalid user code")
    return _operator_rpc(path=path, payload={
        "action": "lookup", "subject": subject, "user_code": user_code})


def call_operator_confirm(*, path: Path, subject: str,
                          request_id: str, confirmation: str) -> dict:
    """Terminal-only second code; never fetched from operator lookup.

    Use only after verified Auth0 + scoped enrollment access and a
    user-supplied code read from their physical Linux terminal.
    """
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise ValueError("verified operator subject required")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise ValueError("invalid request_id")
    if not isinstance(confirmation, str) or not 1 <= len(confirmation) <= 24:
        raise ValueError("invalid terminal confirmation code")
    return _operator_rpc(path=path, payload={
        "action": "confirm", "subject": subject,
        "request_id": request_id, "confirmation": confirmation})


def call_operator_confirm_single_code(*, path: Path, subject: str,
                                      request_id: str, user_code: str) -> dict:
    """Redeem original device-displayed code under authenticated subject.

    Does NOT grant SSH or sudo; use only after showing pending target
    identity and collecting explicit operator instruction.
    """
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise ValueError("verified operator subject required")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 128:
        raise ValueError("invalid request ID")
    if not isinstance(user_code, str) or not 1 <= len(user_code) <= 24:
        raise ValueError("invalid device code")
    return _operator_rpc(path=path, payload={
        "action": "confirm_single_code", "subject": subject,
        "request_id": request_id, "user_code": user_code})
