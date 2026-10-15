#!/usr/bin/env python3
"""Manual, supervised entrypoint for *read-only* root candidate preflight.

NOT INSTALLED. This script provides no "apply", "activate", "shell", "sudo",
key enrollment, or SSH configuration write operation. Running as root will
require separate, out-of-band supervised installation and a protected
0400 root-owned enable marker. No ChatGPT/MCP command enables that marker.

The production caller must provide an already Auth0-authorized,
human-confirmed candidate through the separate approval handoff; absence
of that service, pinned identity, or required root-owned key fails closed.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat

from ai_lab_gateway.device_code_root_preflight_rpc import (
    create_root_preflight_server,
)

ENABLED = Path("/etc/ai-lab-gateway/device-code-root-preflight-enabled")


def check_opt_in() -> None:
    if os.geteuid() != 0:
        raise PermissionError("root-only read-only preflight server")
    st = ENABLED.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or stat.S_IMODE(st.st_mode) != 0o400
            or st.st_nlink != 1):
        raise PermissionError("supervised preflight enable marker unavailable")
    if ENABLED.read_text("ascii").strip() != "READ_ONLY_PREFLIGHT_V1":
        raise PermissionError("invalid root-owned preflight enable marker")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Disabled-by-default, read-only WSL candidate preflight")
    parser.add_argument("--serve-read-only", action="store_true")
    args = parser.parse_args()
    if not args.serve_read_only:
        parser.error("only --serve-read-only is supported")
    check_opt_in()
    with create_root_preflight_server() as server:
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
