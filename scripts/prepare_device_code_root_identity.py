#!/usr/bin/env python3
"""One-off supervised root console preparation of WSL candidate identity.

NOT INSTALLED, NOT AN MCP TOOL. There is no HTTP/Unix endpoint and no root
service on the production Oracle for this. The administrator must separately
create/inspect the root-owned 0750 identity parent directory. No public
request can select arbitrary file paths, usernames, ports or key material.
"""
from __future__ import annotations

import argparse
import os
import pwd

from ai_lab_gateway.device_code_root_identity import (
    prepare_wsl_management_identity, verify_wsl_management_identity,
)


def run_supervised(mode: str) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("operator must be actual root")
    account = pwd.getpwnam("ai-lab-gateway")
    if mode == "prepare":
        return prepare_wsl_management_identity(
            group_gid=account.pw_gid, gateway_uid=account.pw_uid)
    if mode == "verify":
        public = verify_wsl_management_identity(
            group_gid=account.pw_gid, gateway_uid=account.pw_uid)
        return {"status": "root_candidate_identity_verified",
                "public_key": public, "ssh_activated": False}
    raise ValueError("unknown root operator operation")


def main() -> int:
    parser = argparse.ArgumentParser(description="Root-owned WSL 10003 key preparation")
    exclusive = parser.add_mutually_exclusive_group(required=True)
    exclusive.add_argument("--prepare-wsl-10003-identity", action="store_true")
    exclusive.add_argument("--verify-wsl-10003-identity", action="store_true")
    options = parser.parse_args()
    mode = "prepare" if options.prepare_wsl_10003_identity else "verify"
    result = run_supervised(mode)
    # Public key is safe to display; never print the private key.
    print(result["status"])
    print(result["public_key"])
    print("NO_TUNNEL_OR_REGISTRY_CHANGES")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
