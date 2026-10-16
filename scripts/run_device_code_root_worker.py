#!/usr/bin/env python3
"""Fixed, unattended root worker for already-approved Linux pairing only.

No HTTP server, MCP tool, user arguments, arbitrary executable, or generic
sudo command. Runs as a systemd oneshot under a root-controlled timer.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

from ai_lab_gateway.device_code_root_generic_stage import stage_one_approved_generic_linux
from ai_lab_gateway.device_code_root_generic_finalize import finalize_one_staged_generic_linux


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise PermissionError("fixed root service only, without user parameters")
    staged = stage_one_approved_generic_linux()
    accepted = finalize_one_staged_generic_linux()
    # server.py reloads JSON registry and policy on EACH tool invocation:
    # no existing gateway/mcp session interruption or service restart needed.
    for result in (staged, accepted):
        if not isinstance(result, dict):
            raise TypeError("invalid worker result")
    print(json.dumps({"staging": staged["status"],
                      "verification": accepted["status"]},
                     sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PermissionError, ValueError, OSError, RuntimeError,
            TypeError, KeyError, subprocess.SubprocessError) as exc:
        print("DEVICE_CODE_ROOT_WORKER_DENIED: " + type(exc).__name__ +
              ": " + str(exc), file=sys.stderr)
        raise SystemExit(1)
