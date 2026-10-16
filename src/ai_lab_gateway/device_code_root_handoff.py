"""Minimal root-only device-code provisioning handoff.

The anonymous HTTPS device service is never allowed to provision SSH.
Only UID 0 can inspect approved, unexpired pairing records or commit a
public SSH offer. The gateway MCP user and ai-maintenance have no access.

No shell, paths, sudoers, private keys, ports or client-defined operation
is executed by this module. Root alone is responsible for independently
verifying and installing SSH credentials before publishing an offer.
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

SOCKET = Path("/run/ai-lab-device-code/root-handoff.sock")
RID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z")
INPUT_MAX = 6144
OUTPUT_MAX = 8192


class ProvisionHandoff:
    def __init__(self, store):
        self.store = store

    def dispatch(self, msg: object) -> dict:
        if not isinstance(msg, dict) or not isinstance(msg.get("action"), str):
            return {"ok": False, "error": "invalid_request"}
        action = msg["action"]
        if action == "list_approved" and set(msg) == {"action"}:
            try:
                rows = self.store.list_approved_request_ids()
                return {"ok": True, "requests": rows}
            except (ValueError, PermissionError, OSError):
                return {"ok": False, "error": "candidate_unavailable"}
        rid = msg.get("request_id")
        if not isinstance(rid, str) or not RID.fullmatch(rid):
            return {"ok": False, "error": "invalid_request"}
        try:
            if action == "inspect_approved" and set(msg) == {"action", "request_id"}:
                return {"ok": True, "candidate": self.store.approved_root_snapshot(
                    request_id=rid)}
            if action == "publish_offer" and set(msg) == {
                    "action", "request_id", "offer", "gateway_ssh_host_key"}:
                if not isinstance(msg["offer"], dict):
                    return {"ok": False, "error": "invalid_request"}
                return {"ok": True, "result": self.store.stage_connection_offer(
                    request_id=rid, offer=msg["offer"],
                    trusted_gateway_host_public_key=msg["gateway_ssh_host_key"],
                    provisioner_verified=True)}
            if action == "mark_active" and set(msg) == {"action", "request_id"}:
                # Caller is root; it MUST have verified SSH using trusted
                # pinned host identity before asking for activation.
                snapshot = self.store.staged_candidate_snapshot(request_id=rid)
                if snapshot["device_id"] not in {
                        x["device_id"] for x in self.store.list_staged_candidates()}:
                    raise PermissionError("candidate no longer staged")
                return {"ok": True, "result": self.store.activate(
                    request_id=rid, provisioner_verified=True)}
        except (ValueError, PermissionError, OSError, TypeError, KeyError):
            return {"ok": False, "error": "candidate_unavailable"}
        return {"ok": False, "error": "unsupported"}


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def _handler(protocol: ProvisionHandoff, *, allowed_uid: int):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            _, uid, _ = struct.unpack(
                "3i", self.request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            if uid != allowed_uid:
                self.reply({"ok": False, "error": "unauthorized_peer"})
                return
            raw = self.rfile.readline(INPUT_MAX + 1)
            if len(raw) > INPUT_MAX or not raw.endswith(b"\n"):
                self.reply({"ok": False, "error": "invalid_request"})
                return
            try:
                payload = json.loads(raw)
            except (UnicodeError, ValueError):
                self.reply({"ok": False, "error": "invalid_request"})
                return
            self.reply(protocol.dispatch(payload))

        def reply(self, value: dict):
            raw = (json.dumps(value, separators=(",", ":")) + "\n").encode()
            if len(raw) > OUTPUT_MAX:
                raise ValueError("handoff response exceeds limit")
            try:
                self.wfile.write(raw)
            except (ConnectionResetError, BrokenPipeError):
                pass
    return Handler


def create_root_handoff(path: Path, store, *, root_uid: int = 0) -> _Server:
    """Owner-only socket beneath pairing-owned, non-writable runtime dir."""
    path = Path(path)
    parent = path.parent.lstat()
    if (path.exists() or path.is_symlink() or path.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or stat.S_IMODE(parent.st_mode) != 0o711):
        raise PermissionError("untrusted production root handoff directory")
    if type(root_uid) is not int or root_uid < 0:
        raise PermissionError("invalid root peer UID")
    server = _Server(str(path), _handler(ProvisionHandoff(store), allowed_uid=root_uid))
    try:
        os.chmod(path, 0o600)
    except BaseException:
        server.server_close()
        path.unlink(missing_ok=True)
        raise
    return server


def root_handoff_call(path: Path, payload: dict) -> dict:
    """Use only in separately installed, trusted root code."""
    if os.geteuid() != 0:
        raise PermissionError("only root may inspect provisioning approvals")
    raw = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    if len(raw) > INPUT_MAX:
        raise ValueError("oversized root request")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(5)
        conn.connect(str(path))
        conn.sendall(raw)
        data = bytearray()
        while not data.endswith(b"\n"):
            chunk = conn.recv(1024)
            if not chunk:
                raise ConnectionError("root handoff disconnected")
            data.extend(chunk)
            if len(data) > OUTPUT_MAX:
                raise ValueError("oversized root handoff reply")
    result = json.loads(data)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise PermissionError("root provisioning handoff denied")
    return result
