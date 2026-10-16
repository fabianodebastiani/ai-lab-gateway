#!/usr/bin/env python3
"""Run narrow device-code registration HTTP and Auth0-facing UNIX operator IPC.

Public HTTP may only create/prove/poll a pending session. User-authorized
approval happens through MCP+Auth0, not via anonymous HTTP. No SSH write,
root service, sudo or activation endpoint is exposed here.
"""
from __future__ import annotations

import os
from pathlib import Path
import pwd
import secrets
import signal
import stat
import threading

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import run_device_code_server
from ai_lab_gateway.device_code_operator import create_operator_socket

STATE = Path("/var/lib/ai-lab-pairing/device-code")
RUNTIME = Path("/run/ai-lab-device-code")
SOCKET = RUNTIME / "operator.sock"
PORT = 8003


def _state_directory() -> None:
    if STATE.is_symlink():
        raise PermissionError("invalid pairing state directory")
    STATE.mkdir(mode=0o700, exist_ok=True)
    info = STATE.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError("untrusted pairing state directory")


def _hmac_key() -> bytes:
    path = STATE / "hmac.key"
    if not path.exists() and not path.is_symlink():
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(secrets.token_bytes(32))
            output.flush()
            os.fsync(output.fileno())
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
        raise PermissionError("untrusted HMAC key")
    data = path.read_bytes()
    if len(data) != 32:
        raise PermissionError("invalid HMAC key length")
    return data


def main() -> None:
    if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != "ai-lab-pairing":
        raise PermissionError("production device pairing requires ai-lab-pairing, not root")
    os.umask(0o077)
    _state_directory()
    info = RUNTIME.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o711:
        raise PermissionError("invalid protected operator runtime directory")
    if SOCKET.exists() or SOCKET.is_symlink():
        raise PermissionError("existing operator socket requires independent recovery")
    store = DeviceCodeStore(STATE / "device-code.sqlite", hmac_key=_hmac_key())
    gw = pwd.getpwnam("ai-lab-gateway")
    with run_device_code_server(store, port=PORT) as http:
        with create_operator_socket(
                SOCKET, store, allowed_gateway_uid=gw.pw_uid,
                production_gateway_gid=gw.pw_gid) as operator:
            thread = threading.Thread(target=operator.serve_forever, daemon=True)
            thread.start()
            try:
                http.serve_forever(poll_interval=0.2)
            except KeyboardInterrupt:
                pass
            finally:
                operator.shutdown()
                thread.join(timeout=3)
                SOCKET.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
