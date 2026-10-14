"""Standalone *claim-only* localhost HTTP interface for Linux pairing v2.

Security boundary:
- Externally Caddy must terminate HTTPS; this server binds localhost only.
- A short-lived unguessable invite allows only REQUESTING enrollment.
- No endpoint creates invitations, approves requests, edits SSH credentials,
  writes the device registry, or grants root privileges.
- The operator/MCP and independent approver APIs are separate future
  channels; do not treat successful HTTP claim as enrollment activation.
"""
from __future__ import annotations

from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

from .enrollment import EnrollmentStore

MAX_BODY = 4096
MAX_CLAIMS_PER_MINUTE = 40
PUBLIC_HOST = "gateway.debasti.com"
LOCK = threading.Lock()
ATTEMPTS = deque(maxlen=MAX_CLAIMS_PER_MINUTE)


def claim_handler(store: EnrollmentStore, *, expected_host: str = PUBLIC_HOST):
    """Build a handler bound to a private enrollment DB; never return tokens."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "AI-Lab-Pairing"
        sys_version = ""

        def _send(self, status: int, data: dict):
            body = json.dumps(data, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Access-Control-Allow-Origin", "null")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/pairing/health":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            if self.path != "/pairing/claim":
                self._send(404, {"error": "not_found"})
                return
            if self.headers.get("Host") != expected_host:
                self._send(403, {"error": "host_not_allowed"})
                return
            # Authorization is the one-time pairing token in the request body.
            # No CORS support or unauthenticated admin endpoints.
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._send(415, {"error": "json_required"})
                return
            size = self.headers.get("Content-Length", "")
            if not size.isascii() or not size.isdigit() or not 1 <= int(size) <= MAX_BODY:
                self._send(413, {"error": "invalid_body_size"})
                return
            now = time.monotonic()
            with LOCK:
                while ATTEMPTS and ATTEMPTS[0] < now - 60:
                    ATTEMPTS.popleft()
                if len(ATTEMPTS) >= MAX_CLAIMS_PER_MINUTE:
                    self._send(429, {"error": "too_many_requests"})
                    return
                ATTEMPTS.append(now)
            try:
                payload = json.loads(self.rfile.read(int(size)))
                if not isinstance(payload, dict) or set(payload) != {
                    "token", "device_id", "device_name", "tunnel_public_key",
                    "ssh_host_public_key", "persistent"
                }:
                    raise ValueError("unexpected fields")
                result = store.claim(
                    payload["token"],
                    device_id=payload["device_id"],
                    device_name=payload["device_name"],
                    tunnel_public_key=payload["tunnel_public_key"],
                    ssh_host_public_key=payload["ssh_host_public_key"],
                    persistent=payload["persistent"],
                )
            except (ValueError, TypeError, PermissionError, KeyError):
                self._send(403, {"error": "invalid_or_expired_pairing"})
                return
            self._send(202, result)

        def log_message(self, fmt, *args):
            # Never log raw tokens or HTTP request payloads.
            return

    return Handler


def run_claim_server(store: EnrollmentStore, *, port: int = 8002):
    with ThreadingHTTPServer(("127.0.0.1", port), claim_handler(store)) as server:
        server.daemon_threads = True
        server.serve_forever(poll_interval=0.25)


if __name__ == "__main__":
    raise SystemExit(
        "This claim handler must be started by the dedicated enrollment "
        "service with its protected database; no public standalone CLI."
    )
