"""Authenticated MCP-to-root-broker IPC.

Only the Gateway systemd service user may open the Unix socket. The caller's
subject must come from a token already verified by the Gateway, NEVER from a
user-provided tool parameter.
"""
import json
import socket

BROKER_SOCKET = "/run/ai-lab-privilege-broker/broker.sock"

def broker_call(action: str, subject: str, **fields) -> dict:
    request = {"action": action, "subject": subject, **fields}
    data = (json.dumps(request, separators=(",", ":")) + "\n").encode("utf8")
    if len(data) > 16384:
        raise ValueError("broker request too large")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(20)
        sock.connect(BROKER_SOCKET)
        sock.sendall(data)
        response = bytearray()
        while not response.endswith(b"\n"):
            block = sock.recv(4096)
            if not block:
                raise ConnectionError("broker closed connection")
            response.extend(block)
            if len(response) > 32768:
                raise ValueError("broker response too large")
    result = json.loads(response)
    if not isinstance(result, dict):
        raise ValueError("invalid broker response")
    return result
