"""Protected candidate-provisioning RPC: isolated, non-root implementation.

NOT DEPLOYED. The real root-owned adapter is *not* enabled here. This
laboratory protocol demonstrates a tight Unix SO_PEERCRED gate, exact request
schema and request-only approval lookup. It never accepts caller-supplied
key material, target device IDs, shell commands, port numbers or file paths.

The handler runs as an unprivileged sandbox process, and calls ONLY
stage_lab_candidate. Production will need an independently authorized
root-owned service, protected pairing-state handoff, fixed paths/ownership,
atomic SSH edits, rollback, audit, and live SSH acceptance.
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

from .device_code_candidate import stage_lab_candidate

RPC_MAX = 384
REPLY_MAX = 1024
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")


class CandidateProvisionProtocol:
    """Only one hard-coded candidate action is possible."""

    def __init__(self, store, *, sandbox_root: Path,
                 trusted_gateway_host_public_key: str):
        self.store = store
        self.sandbox_root = Path(sandbox_root)
        self.gateway_pin = trusted_gateway_host_public_key

    def dispatch(self, payload: object) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"action", "request_id"}:
            return {"ok": False, "error": "invalid_request"}
        if payload["action"] != "stage_wsl_candidate":
            return {"ok": False, "error": "unsupported"}
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            return {"ok": False, "error": "invalid_request"}
        try:
            stage_lab_candidate(
                self.store, request_id, sandbox_root=self.sandbox_root,
                trusted_gateway_host_public_key=self.gateway_pin)
        except (ValueError, PermissionError, FileExistsError, OSError):
            # No secret material, SSH fingerprints, paths or DB clues.
            return {"ok": False, "error": "candidate_unavailable"}
        return {"ok": True, "status": "candidate_staged",
                "access_mode": "restricted", "live_ssh_changed": False}


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def _handler(protocol: CandidateProvisionProtocol, *, allowed_peer_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                _, uid, _ = struct.unpack(
                    "3i", self.request.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED,
                        struct.calcsize("3i")))
                if uid != allowed_peer_uid:
                    self._reply({"ok": False, "error": "unauthorized_peer"})
                    return
                data = self.rfile.readline(RPC_MAX + 1)
                if len(data) > RPC_MAX or not data.endswith(b"\n"):
                    self._reply({"ok": False, "error": "invalid_request"})
                    return
                try:
                    payload = json.loads(data)
                except (UnicodeError, ValueError):
                    self._reply({"ok": False, "error": "invalid_request"})
                    return
                self._reply(protocol.dispatch(payload))
            except (BrokenPipeError, ConnectionResetError):
                return

        def _reply(self, payload):
            response = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            if len(response) > REPLY_MAX:
                raise ValueError("candidate RPC response exceeds limit")
            self.wfile.write(response)
    return Handler


def create_lab_provision_socket(path: Path, protocol: CandidateProvisionProtocol,
                                *, allowed_peer_uid: int):
    """Non-root laboratory socket in an owned 0700 directory, always 0600."""
    if os.geteuid() == 0:
        raise PermissionError("root adapter is NOT implemented; nonroot lab only")
    path = Path(path)
    parent = path.parent
    if path.exists() or path.is_symlink() or parent.is_symlink():
        raise PermissionError("refusing existing socket or symlink")
    mode = parent.lstat()
    if (not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.geteuid()
            or stat.S_IMODE(mode.st_mode) != 0o700):
        raise PermissionError("socket parent must be private 0700")
    if type(allowed_peer_uid) is not int or allowed_peer_uid < 0:
        raise ValueError("invalid peer UID")
    server = _UnixServer(
        str(path), _handler(protocol, allowed_peer_uid=allowed_peer_uid))
    os.chmod(path, 0o600)
    return server


def call_lab_provision_socket(path: Path, *, request_id: str) -> dict:
    """Return only status, never public/private SSH keys or internal paths."""
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise ValueError("invalid candidate request")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        payload = json.dumps({"action": "stage_wsl_candidate",
                              "request_id": request_id}).encode() + b"\n"
        conn.sendall(payload)
        output = bytearray()
        while not output.endswith(b"\n"):
            fragment = conn.recv(512)
            if not fragment:
                raise ConnectionError("candidate socket disconnected")
            output.extend(fragment)
            if len(output) > REPLY_MAX:
                raise ValueError("oversized candidate response")
    result = json.loads(output)
    if not isinstance(result, dict):
        raise ValueError("invalid candidate RPC reply")
    return result
