#!/usr/bin/env python3
"""Operator-only crash recovery for fixed Gateway SSH candidate port 10003.

NOT DEPLOYED. Run manually as the Oracle root administrator after verifying
a pending crash journal, never via MCP or the candidate apply socket.
Destinations are FIXED and no paths, commands, device IDs, or credentials
are accepted from argv. Root-owned journal integrity and target file hashes
must match the prior transaction; unexpected edits block recovery.

This does NOT activate the device, touch registry or service accounts,
revoke the legacy WSL 10002 credentials, or grant sudo.
"""
from __future__ import annotations

import argparse
import os
import pwd

from ai_lab_gateway.device_code_root_transaction import (
    production_paths, recover_candidate_root_transaction,
)


def recover_supervised_candidate() -> bool:
    if os.geteuid() != 0:
        raise PermissionError("manual root authorization required")
    tunnel = pwd.getpwnam("tunnel")
    gateway = pwd.getpwnam("ai-lab-gateway")
    fixed_paths = production_paths(
        tunnel_uid=tunnel.pw_uid, tunnel_gid=tunnel.pw_gid,
        gateway_uid=gateway.pw_uid, gateway_gid=gateway.pw_gid)
    return recover_candidate_root_transaction(fixed_paths)


def main() -> int:
    parser = argparse.ArgumentParser(description="Root-only SSH 10003 recovery")
    parser.add_argument("--recover-wsl-10003", action="store_true")
    args = parser.parse_args()
    if not args.recover_wsl_10003:
        parser.error("only --recover-wsl-10003 is supported")
    restored = recover_supervised_candidate()
    print("SSH_CANDIDATE_RESTORED" if restored else "NO_PENDING_SSH_TRANSACTION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
