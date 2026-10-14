"""Client for the non-root, UID-isolated Linux pairing service Unix socket."""
from __future__ import annotations

import json
from pathlib import Path
import socket

SOCKET_PATH = Path("/run/ai-lab-pairing/mcp.sock")
MAX_REPLY = 65536


def pairing_call(action: str, subject: str, **args) -> dict:
    if not isinstance(action, str) or action not in {"invite", "list_mine", "status"}:
        raise ValueError("unknown or unauthorized pairing action")
    if not isinstance(subject, str) or not 1 <= len(subject) <= 256:
        raise ValueError("verified OAuth subject is required")
    payload = {"action": action, "subject": subject, **args}
    # Model-supplied keyword arguments cannot replace authorization fields.
    payload["action"] = action
    payload["subject"] = subject
    line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf8")
    if len(line) > 8192:
        raise ValueError("pairing request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(SOCKET_PATH))
        sock.sendall(line)
        chunks = bytearray()
        while not chunks.endswith(b"\n"):
            block = sock.recv(4096)
            if not block:
                raise ConnectionError("pairing service disconnected")
            chunks.extend(block)
            if len(chunks) > MAX_REPLY:
                raise ValueError("pairing service response too long")
    response = json.loads(chunks)
    if not isinstance(response, dict):
        raise ValueError("invalid pairing reply")
    return response
