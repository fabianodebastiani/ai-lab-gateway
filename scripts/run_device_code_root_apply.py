#!/usr/bin/env python3
"""Supervised, disabled-by-default root WSL 10003 SSH candidate staging.

NOT INSTALLED, NOT ENABLED. This is a standalone root-only service, separate
from the existing read-only preflight. It modifies ONLY the two narrowly
allowlisted candidate SSH files when a separate trusted approval exists.
It has NO sudo, systemd, registry switch, credential revocation or shell
commands. No MCP tool may create the root-owned enable marker.

Do not install until a privileged administrative review of paths, ownership,
journal recovery, SSH policy, operator consent and WSL actual sshd identity.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat

from ai_lab_gateway.device_code_root_apply import create_root_apply_server

MARKER = Path("/etc/ai-lab-gateway/device-code-root-apply-enabled")
EXACT_MARKER = "SSH_10003_CANDIDATE_ONLY_V1"


def check_supervised_enablement() -> None:
    if os.geteuid() != 0:
        raise PermissionError("actual root UID required")
    st = MARKER.lstat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0
            or st.st_nlink != 1 or stat.S_IMODE(st.st_mode) != 0o400):
        raise PermissionError("root-owned 0400 approval marker required")
    if MARKER.read_text(encoding="ascii").strip() != EXACT_MARKER:
        raise PermissionError("root apply not independently enabled")


def main() -> int:
    p = argparse.ArgumentParser(
        description="Supervised root staging of SSH candidate WSL 10003")
    p.add_argument("--serve-candidate-only", action="store_true")
    args = p.parse_args()
    if not args.serve_candidate_only:
        p.error("only --serve-candidate-only is supported")
    check_supervised_enablement()
    with create_root_apply_server() as server:
        server.serve_forever(poll_interval=0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
