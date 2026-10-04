#!/usr/bin/env python3
"""Offline validation of registry and authorization configuration."""

import argparse

from ai_lab_gateway.authz import AuthorizationPolicy
from ai_lab_gateway.registry import DeviceRegistry


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--devices", required=True)
    parser.add_argument("--authorization", required=True)
    args = parser.parse_args()

    registry = DeviceRegistry.load(args.devices)
    AuthorizationPolicy.load(args.authorization)
    devices = registry.list_enabled()
    print(f"configuration valid: {len(devices)} enabled device(s)")
    for device in devices:
        print(f"- {device.id}: {device.tunnel_host}:{device.tunnel_port}")


if __name__ == "__main__":
    main()
