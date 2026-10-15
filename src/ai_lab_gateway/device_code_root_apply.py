"""NOT DEPLOYED: narrowly scoped WSL candidate root SSH staging service.

This process installs ONLY candidate 10003 tunnel authorization and a
candidate known_hosts pin. It never changes registry, SSH daemon config,
active 10002 or 10001 credentials, target permissions, systemd or sudo.
Activation and cutover are separate, later supervised steps.

A production listener may be created ONLY as root with a separate
out-of-band root-owned marker (enforced by its standalone runner).
SO_PEERCRED restricts requests to the fixed ai-lab-gateway UID. The JSON
schema is EXACTLY {"action":"apply_wsl_candidate","request_id":"..."}.
No client-selected path, public key, port, approval, mode or command.

Before and inside the journal lock, independently approved immutable
identity is re-read from the pairing service's root-only Unix handoff,
trusted root-owned host/management files, protected device registry and
the effective tunnel sshd account. 127.0.0.1:10003 is reserved until
the two-file root transaction finishes; no listener is activated.
"""
from __future__ import annotations

from contextlib import contextmanager
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
from .device_code_root_transaction import (
    apply_candidate_root_transaction, production_paths,
)

ROOT_APPLY_SOCKET = Path("/run/ai-lab-device-code-root/apply.sock")
APPROVAL_SOCKET = Path("/run/ai-lab-device-code/approval.sock")
SSHD_PROBE = (
    "/usr/sbin/sshd", "-T", "-C",
    "user=tunnel,host=gateway.debasti.com,addr=127.0.0.1",
)
RID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")
INPUT_MAX = 384
OUTPUT_MAX = 512


@contextmanager
def reserved_wsl_candidate_port():
    """Hold the exact loopback bind, not an open service or a port scan."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        sock.bind(("127.0.0.1", 10003))
        yield sock


def _trusted_approved_candidate(request_id: str) -> dict:
    result = inspect_candidate_over_unix(APPROVAL_SOCKET, request_id=request_id)
    if (not isinstance(result, dict) or set(result) != {"ok", "candidate"}
            or result["ok"] is not True
            or not isinstance(result["candidate"], dict)
            or result["candidate"].get("request_id") != request_id):
        raise PermissionError("independent human-approved candidate unavailable")
    return result["candidate"]


def _verify_root_environment(candidate: dict, reservation: socket.socket) -> dict:
    result = subprocess.run(
        SSHD_PROBE, check=True, capture_output=True, text=True, timeout=7)
    return inspect_fixed_production_environment(
        candidate, effective_sshd=result.stdout,
        reserved_socket=reservation)


def apply_staged_wsl_candidate(request_id: str) -> dict:
    """Root-only, exact WSL candidate staging; no registry or service change."""
    if os.geteuid() != 0:
        raise PermissionError("root-only candidate SSH apply")
    if not isinstance(request_id, str) or not RID.fullmatch(request_id):
        raise PermissionError("invalid WSL candidate request")
    tunnel = pwd.getpwnam("tunnel")
    gateway = pwd.getpwnam("ai-lab-gateway")
    paths = production_paths(
        tunnel_uid=tunnel.pw_uid, tunnel_gid=tunnel.pw_gid,
        gateway_uid=gateway.pw_uid, gateway_gid=gateway.pw_gid)
    with reserved_wsl_candidate_port() as reservation:
        approved = _trusted_approved_candidate(request_id)
        before = _verify_root_environment(approved, reservation)
        if before != {
            "status": "candidate_preflight_ok", "device_id": "windows-wsl",
            "port": 10003, "access_mode": "restricted", "persistent": False,
            "registry_changed": False, "ssh_changed": False,
        }:
            raise PermissionError("untrusted root preflight result")

        def recheck_within_root_lock() -> bool:
            # A prior check or source-file value is not enough at commit.
            fresh = _trusted_approved_candidate(request_id)
            if fresh != approved:
                raise PermissionError("approval or SSH offer changed")
            if _verify_root_environment(fresh, reservation) != before:
                raise PermissionError("root SSH environment changed")
            return True

        applied = apply_candidate_root_transaction(
            paths, request_id=request_id,
            tunnel_key=approved["tunnel_public_key"],
            host_key=approved["host_public_key"],
            approval_check=recheck_within_root_lock)
    if applied["status"] != "candidate_ssh_staged":
        raise PermissionError("unverified root SSH apply result")
    return applied


class RootApplyProtocol:
    """Single action. A callback is injectable for isolated root CI tests."""

    def __init__(self, apply_verified_candidate):
        self._apply = apply_verified_candidate

    def dispatch(self, payload: object) -> dict:
        if not isinstance(payload, dict) or set(payload) != {"action", "request_id"}:
            return {"ok": False, "error": "invalid_request"}
        if payload["action"] != "apply_wsl_candidate":
            return {"ok": False, "error": "unsupported"}
        request_id = payload["request_id"]
        if not isinstance(request_id, str) or not RID.fullmatch(request_id):
            return {"ok": False, "error": "invalid_request"}
        try:
            result = self._apply(request_id)
            if (not isinstance(result, dict)
                    or result.get("status") != "candidate_ssh_staged"
                    or result.get("port") != 10003
                    or result.get("registry_changed") is not False
                    or result.get("sudo_granted") is not False):
                raise PermissionError("unsafe root apply status")
        except (OSError, PermissionError, ValueError, KeyError,
                RuntimeError, subprocess.SubprocessError):
            return {"ok": False, "error": "candidate_unavailable"}
        return {
            "ok": True, "status": "ssh_candidate_staged",
            "port": 10003, "registry_changed": False,
            "sudo_granted": False, "activated": False,
        }


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def _handler(protocol: RootApplyProtocol, *, gateway_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            _, uid, _ = struct.unpack(
                "3i", self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != gateway_uid:
                self._reply({"ok": False, "error": "unauthorized_peer"})
                return
            data = self.rfile.readline(INPUT_MAX + 1)
            if len(data) > INPUT_MAX or not data.endswith(b"\n"):
                self._reply({"ok": False, "error": "invalid_request"})
                return
            try:
                parsed = json.loads(data)
            except (ValueError, UnicodeError):
                self._reply({"ok": False, "error": "invalid_request"})
                return
            self._reply(protocol.dispatch(parsed))

        def _reply(self, payload):
            raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
            if len(raw) > OUTPUT_MAX:
                raise ValueError("root apply response too large")
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                return
    return Handler


def _open_socket(path: Path, protocol: RootApplyProtocol, *,
                 caller_uid: int, owner_uid: int, owner_gid: int,
                 directory_mode: int, socket_mode: int):
    if path.exists() or path.is_symlink() or path.parent.is_symlink():
        raise PermissionError("root apply socket already exists or unsafe path")
    info = path.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid
            or info.st_gid != owner_gid
            or stat.S_IMODE(info.st_mode) != directory_mode):
        raise PermissionError("root apply socket directory ownership mismatch")
    if type(caller_uid) is not int or caller_uid < 0:
        raise PermissionError("root apply requires a fixed, known caller UID")
    server = _Server(str(path), _handler(protocol, gateway_uid=caller_uid))
    try:
        os.chown(path, owner_uid, owner_gid)
        os.chmod(path, socket_mode)
    except BaseException:
        server.server_close()
        path.unlink(missing_ok=True)
        raise
    return server


def create_root_apply_server():
    """Disabled-by-default production factory; no service is deployed."""
    if os.geteuid() != 0:
        raise PermissionError("actual root required for candidate SSH apply")
    gateway = pwd.getpwnam("ai-lab-gateway")
    return _open_socket(
        ROOT_APPLY_SOCKET, RootApplyProtocol(apply_staged_wsl_candidate),
        caller_uid=gateway.pw_uid,
        owner_uid=0, owner_gid=gateway.pw_gid,
        directory_mode=0o750, socket_mode=0o660)
