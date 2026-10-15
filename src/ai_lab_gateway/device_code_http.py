"""Loopback-only, device-side pairing HTTP protocol (ADR-029).

Experimental staging interface, NOT deployed on the public Gateway.
A target without any pre-existing SSH connection can start, prove its
Ed25519 tunnel key, and poll a pending request. Nothing here can approve a
user, provision SSH access, write the gateway registry, or grant sudo.

Separate Auth0-verified MCP endpoints will implement operator lookup; a
separate consent verifier must attest user confirmation before activation.

Bind only to 127.0.0.1. The first production proxy must additionally
supply *trusted* source-IP accounting / reverse-proxy abuse controls.
"""
from __future__ import annotations

from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

from .device_code import DeviceCodeStore

MAX_BODY = 4096
MAX_REQUESTS_PER_MINUTE = 30
MAX_STARTS_PER_HOUR_PER_PEER = 12
MAX_POLLS_PER_MINUTE_PER_PEER = 20


class PeerQuota:
    """In-process conservative quotas; not a replacement for proxy limits."""
    def __init__(self):
        self._lock = threading.Lock()
        self._requests: dict[tuple[str, str], deque] = defaultdict(deque)

    def allow(self, peer: str, route: str, *, now: float | None = None) -> bool:
        moment = time.monotonic() if now is None else now
        if route == "/pairing/device/start":
            window, maximum = 3600, MAX_STARTS_PER_HOUR_PER_PEER
        elif route == "/pairing/device/poll":
            window, maximum = 60, MAX_POLLS_PER_MINUTE_PER_PEER
        else:
            window, maximum = 60, MAX_REQUESTS_PER_MINUTE
        with self._lock:
            seen = self._requests[(peer, route)]
            while seen and seen[0] <= moment - window:
                seen.popleft()
            if len(seen) >= maximum:
                return False
            seen.append(moment)
            # Prevent unbounded memory growth from fake peers.
            if len(self._requests) > 4096:
                for key in list(self._requests)[:1024]:
                    if not self._requests[key] or self._requests[key][-1] < moment - 3600:
                        del self._requests[key]
            return True


def device_code_handler(store: DeviceCodeStore, *, quota: PeerQuota | None = None):
    limiter = quota if quota is not None else PeerQuota()
    routes = {
        "/pairing/device/start":
            frozenset({"device_id", "display_name",
                       "tunnel_public_key", "host_public_key", "persistent"}),
        "/pairing/device/prove":
            frozenset({"request_id", "device_secret", "signature_b64"}),
        "/pairing/device/poll":
            frozenset({"request_id", "device_secret"}),
    }

    class Handler(BaseHTTPRequestHandler):
        server_version = "AI-Lab-Device-Pairing"
        sys_version = ""
        protocol_version = "HTTP/1.0"

        def _send(self, status: int, payload: dict):
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/pairing/device/health":
                self._send(200, {"status": "ok"})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            fields = routes.get(self.path)
            if fields is None:
                self._send(404, {"error": "not_found"})
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                self._send(415, {"error": "json_required"})
                return
            length = self.headers.get("Content-Length", "")
            if not length.isascii() or not length.isdecimal() or not 1 <= int(length) <= MAX_BODY:
                self._send(413, {"error": "invalid_body_size"})
                return
            # Peer comes from the TCP connection, NEVER an untrusted header.
            # Reverse proxy must enforce its own client identity and quotas.
            peer = self.client_address[0]
            if not limiter.allow(peer, self.path):
                self._send(429, {"error": "rate_limited"})
                return
            try:
                data = json.loads(self.rfile.read(int(length)))
                if not isinstance(data, dict):
                    raise ValueError("unexpected payload")
                if self.path == "/pairing/device/prove":
                    # Both signatures are valid alternatives but must never
                    # coexist or introduce an unexpected request field.
                    accepted = (frozenset({"request_id","device_secret","signature_b64"}),
                                frozenset({"request_id","device_secret","sshsig"}))
                    if frozenset(data) not in accepted:
                        raise ValueError("invalid signature fields")
                elif set(data) != fields:
                    raise ValueError("unexpected fields")
                if self.path == "/pairing/device/start":
                    result = store.start(
                        device_id=data["device_id"],
                        display_name=data["display_name"],
                        tunnel_public_key=data["tunnel_public_key"],
                        host_public_key=data["host_public_key"],
                        persistent=data["persistent"],
                        source_id=peer)
                    self._send(201, result)
                elif self.path == "/pairing/device/prove":
                    result = store.prove(**data)
                    self._send(200, result)
                else:
                    result = store.poll(**data)
                    self._send(200, result)
            except (ValueError, TypeError, PermissionError, KeyError):
                # Do not reveal whether a code/session/device exists.
                self._send(403, {"error": "pairing_unavailable"})
            except Exception:
                # Fail closed and hide sensitive DB/implementation details.
                self._send(503, {"error": "temporarily_unavailable"})

        def log_message(self, *args):
            # Never log body/device secret, user code, or query parameters.
            return

    return Handler


def run_device_code_server(store: DeviceCodeStore, *,
                           host: str = "127.0.0.1", port: int = 0,
                           quota: PeerQuota | None = None):
    if host != "127.0.0.1":
        raise ValueError("device-code staging server must bind loopback only")
    server = ThreadingHTTPServer((host, port), device_code_handler(store, quota=quota))
    server.daemon_threads = True
    return server
