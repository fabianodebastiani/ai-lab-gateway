#!/usr/bin/env python3
"""Supervised Oracle root-console SSH route inventory, READ ONLY.

This command intentionally cannot enable SSH, enroll devices, grant sudo,
read private key bytes, print tokens, install a service or update the device
registry. It is not an MCP action, not deployed and does not circumvent
independent human administration. Review provenance and source before use.
"""
from __future__ import annotations

import argparse

from ai_lab_gateway.device_code_root_inventory import (
    inspect_root_environment, report_to_json,
)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only privileged inventory before WSL 10003 staging")
    p.add_argument("--audit-paths-only", action="store_true")
    args = p.parse_args()
    if not args.audit_paths_only:
        p.error("only --audit-paths-only is supported")
    print(report_to_json(inspect_root_environment()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
