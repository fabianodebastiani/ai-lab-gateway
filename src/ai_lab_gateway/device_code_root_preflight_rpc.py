"""Non-activating root-side preflight RPC for the WSL device-code pilot.

Root constructor is fixed to protected production paths and independently
verified approval handoff. This module has NO SSH file writes, key creation,
registry mutation, sudo grants or tunnel activation. It is not deployed.

Client can request only "preflight_wsl_candidate" and a request_id. A real
root-owned listener enforces the kernel SO_PEERCRED UID of ai-lab-gateway.
A separate nonroot lab factory exercises the exact same protocol/peer gate.
No payload field may select paths, keys, UID, device, SSH ports or commands.

A successful preflight response is NOT an authorization token to call apply.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import re
import socket
import socketserver
import stat
import struct
import subprocess

from .device_code_approval_handoff import inspect_candidate_over_unix
from .device_code_root_environment import inspect_fixed_production_environment

ROOT_SOCKET = Path("/run/ai-lab-device-code-root/preflight.sock")
APPROVAL_SOCKET = Path("/run/ai-lab-device-code/approval.sock")
ROOT_UID = 0
REQUEST = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")
INPUT_LIMIT = 384
OUTPUT_LIMIT = 512

_SSHD_PROBE = (
    "/usr/sbin/sshd", "-T", "-C",
    "user=tunnel,host=gateway.debasti.com,addr=127.0.0.1",
)


class RootPreflightProtocol:
    def __init__(self, *, trusted_approval_reader, trusted_environment_probe):
        # These callbacks are injected ONLY when explicitly constructing a
        # test protocol; the production constructor binds both internally.
        self._read_approved = trusted_approval_reader
        self._probe = trusted_environment_probe

    def dispatch(self, payload: object) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"action", "request_id"}:
            return {"ok": False, "error": "invalid_request"}
        if payload["action"] != "preflight_wsl_candidate":
            return {"ok": False, "error": "unsupported"}
        rid = payload["request_id"]
        if not isinstance(rid, str) or not REQUEST.fullmatch(rid):
            return {"ok": False, "error": "invalid_request"}
        try:
            candidate = self._read_approved(rid)
            report = self._probe(candidate)
            if (not isinstance(report, dict)
                    or report.get("status") != "candidate_preflight_ok"
                    or report.get("port") != 10003
                    or report.get("ssh_changed") is not False
                    or report.get("registry_changed") is not False):
                raise PermissionError("invalid preflight output")
        except (PermissionError, ValueError, KeyError, OSError,
                subprocess.SubprocessError, RuntimeError):
            return {"ok": False, "error": "candidate_unavailable"}
        return {
            "ok": True, "status": "preflight_only",
            "port": 10003, "access_mode": "restricted",
            "ssh_changed": False, "registry_changed": False,
        }


class _SocketServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def _handler(protocol: RootPreflightProtocol, *, allowed_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                _, uid, _ = struct.unpack(
                    "3i", self.request.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED,
                        struct.calcsize("3i")))
                if uid != allowed_uid:
                    self._reply({"ok": False, "error": "unauthorized_peer"})
                    return
                raw = self.rfile.readline(INPUT_LIMIT + 1)
                if len(raw) > INPUT_LIMIT or not raw.endswith(b"\n"):
                    self._reply({"ok": False, "error": "invalid_request"})
                    return
                try:
                    payload = json.loads(raw)
                except (UnicodeError, ValueError):
                    self._reply({"ok": False, "error": "invalid_request"})
                    return
                self._reply(protocol.dispatch(payload))
            except (BrokenPipeError, ConnectionResetError):
                return

        def _reply(self, payload):
            data = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            if len(data) > OUTPUT_LIMIT:
                raise ValueError("root preflight result too large")
            self.wfile.write(data)
    return Handler


def _create_socket(path: Path, protocol: RootPreflightProtocol, *,
                   allowed_uid: int, owner_uid: int, owner_gid: int,
                   directory_mode: int, socket_mode: int):
    parent = path.parent
    if path.exists() or path.is_symlink() or parent.is_symlink():
        raise PermissionError("refuse existing root preflight socket")
    p = parent.lstat()
    if (not stat.S_ISDIR(p.st_mode) or p.st_uid != owner_uid
            or p.st_gid != owner_gid
            or stat.S_IMODE(p.st_mode) != directory_mode):
        raise PermissionError("root preflight runtime directory is untrusted")
    if not isinstance(allowed_uid, int) or allowed_uid < 0:
        raise PermissionError("invalid trusted invoking UID")
    server = _SocketServer(
        str(path), _handler(protocol, allowed_uid=allowed_uid))
    os.chmod(path, socket_mode)
    return server


def create_root_preflight_server():
    """Only for operator-installed root service. Not enabled by repo commits."""
    if os.geteuid() != ROOT_UID:
        raise PermissionError("root-owned service required")
    caller = pwd.getpwnam("ai-lab-gateway")

    def read_approval(request_id: str) -> dict:
        result = inspect_candidate_over_unix(APPROVAL_SOCKET, request_id=request_id)
        if (not isinstance(result, dict) or result.get("ok") is not True
                or not isinstance(result.get("candidate"), dict)):
            raise PermissionError("approved handoff unavailable")
        return result["candidate"]

    def inspect_environment(candidate: dict) -> dict:
        effective = subprocess.run(
            _SSHD_PROBE, check=True, capture_output=True,
            text=True, timeout=7)
        return inspect_fixed_production_environment(
            candidate, effective_sshd=effective.stdout)

    protocol = RootPreflightProtocol(
        trusted_approval_reader=read_approval,
        trusted_environment_probe=inspect_environment)
    return _create_socket(
        ROOT_SOCKET, protocol, allowed_uid=caller.pw_uid, owner_uid=0,
        owner_gid=caller.pw_gid, directory_mode=0o750, socket_mode=0o660)


def create_lab_root_preflight_server(path: Path, protocol: RootPreflightProtocol,
                                    *, allowed_uid: int):
    """Same credential-check handler, but with nonroot local callbacks/files."""
    if os.geteuid() == 0:
        raise PermissionError("laboratory listener cannot run as root")
    path = Path(path)
    return _create_socket(
        path, protocol, allowed_uid=allowed_uid, owner_uid=os.geteuid(),
        owner_gid=os.getegid(), directory_mode=0o700, socket_mode=0o600)


def call_root_preflight(path: Path, *, request_id: str) -> dict:
    """Read-only RPC primitive; scope checks remain at authenticated MCP edge."""
    if not isinstance(request_id, str) or not REQUEST.fullmatch(request_id):
        raise ValueError("invalid request identifier")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(8)
        sock.connect(str(path))
        sock.sendall(json.dumps({
            "action": "preflight_wsl_candidate", "request_id": request_id
        }, separators=(",", ":")).encode() + b"\n")
        answer = bytearray()
        while not answer.endswith(b"\n"):
            chunk = sock.recv(256)
            if not chunk:
                raise ConnectionError("root preflight socket closed")
            answer.extend(chunk)
            if len(answer) > OUTPUT_LIMIT:
                raise ValueError("root preflight response too large")
    result = json.loads(answer)
    if not isinstance(result, dict):
        raise ValueError("malformed root preflight reply")
    return result
