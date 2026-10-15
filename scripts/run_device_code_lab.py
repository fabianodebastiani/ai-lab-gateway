#!/usr/bin/env python3
"""Run the device-code pairing lab API+operator socket as an unprivileged user.

NOT for Internet/public Caddy reverse proxy. This process cannot approve
a device, provision SSH, write to the registry or grant admin privileges.
Tests and lab experimentation ONLY. Requires python3-cryptography.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import signal
import stat
import sys
import threading

from ai_lab_gateway.device_code import DeviceCodeStore
from ai_lab_gateway.device_code_http import run_device_code_server
from ai_lab_gateway.device_code_operator import create_operator_socket


def private_dir(path: Path):
    if path.is_symlink():
        raise PermissionError("refusing symlink state path")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = path.lstat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or stat.S_IMODE(st.st_mode) != 0o700):
        raise PermissionError("staging state must be mode 0700")


def key_from_file(path: Path) -> bytes:
    """Generate once as 0600; never print secrets or regenerate silently."""
    if not path.exists() and not path.is_symlink():
        fd = os.open(str(path),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    if path.is_symlink() or not path.is_file():
        raise PermissionError("invalid staging HMAC key path")
    info = path.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
        raise PermissionError("HMAC key must be owner-only 0600")
    data = path.read_bytes()
    if len(data) != 32:
        raise ValueError("HMAC key must be exactly 32 bytes")
    return data


def main():
    parser = argparse.ArgumentParser(description="NONPRODUCTION loopback pairing lab")
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--lab-only", action="store_true", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("refusing to run as root")
    if args.port < 0 or args.port > 65535:
        parser.error("invalid port")
    os.umask(0o077)
    private_dir(args.state_dir)
    runtime = args.state_dir/"run"
    private_dir(runtime)
    key = key_from_file(args.state_dir/"hmac.key")
    store = DeviceCodeStore(args.state_dir/"device-code.sqlite",hmac_key=key)
    sock = runtime/"operator.sock"
    if sock.exists() or sock.is_symlink():
        # Fail safe instead of hijacking an existing operator socket.
        raise PermissionError("operator socket path already exists")
    with run_device_code_server(store, port=args.port) as http:
        with create_operator_socket(sock, store,allowed_gateway_uid=os.geteuid()) as op:
            thread=threading.Thread(target=op.serve_forever,daemon=True)
            thread.start()
            try:
                print("LAB_HTTP_URL=http://127.0.0.1:"+str(http.server_port),flush=True)
                print("LAB_OPERATOR_SOCKET="+str(sock),flush=True)
                print("LAB_ONLY: no Auth0 integration, public listener or approvals",flush=True)
                http.serve_forever(poll_interval=0.2)
            except KeyboardInterrupt:
                pass
            finally:
                op.shutdown()
                thread.join(timeout=3)
                sock.unlink(missing_ok=True)


if __name__=="__main__":
    main()
