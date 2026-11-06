#!/usr/bin/env python3
"""Render an optional, localhost-only systemd SSH relay over WireGuard.

This tool writes text unit files only. It never modifies systemd, VPN routing,
the device registry, authentication policy, or production services.
"""
from __future__ import annotations

import argparse
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
import re

_ID = re.compile(r"[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?\Z")


def render_units(
    device_id: str,
    listen_port: int,
    peer_ip: str,
    vpn_subnet: str = "10.77.0.0/24",
) -> dict[str, str]:
    """Validate routing inputs and return root-reviewable systemd unit text."""
    if not _ID.fullmatch(device_id):
        raise ValueError("device_id must be a short lowercase DNS-safe identifier")
    if isinstance(listen_port, bool) or not isinstance(listen_port, int) or not 1024 <= listen_port <= 65535:
        raise ValueError("listen_port must be an unprivileged TCP port (1024-65535)")
    try:
        peer = ip_address(peer_ip)
        subnet = ip_network(vpn_subnet, strict=True)
    except ValueError as exc:
        raise ValueError("invalid peer IPv4 address or VPN subnet") from exc
    if not isinstance(peer, IPv4Address) or not isinstance(subnet, IPv4Network):
        raise ValueError("only IPv4 WireGuard peers are supported")
    if not subnet.is_private or peer not in subnet:
        raise ValueError("peer must belong to the explicitly selected private VPN subnet")
    if peer in (subnet.network_address, subnet.broadcast_address) or int(peer) == int(subnet.network_address) + 1:
        raise ValueError("peer must be a target host, not the gateway or subnet boundary")

    stem = f"ai-lab-wg-{device_id}"
    socket_name = f"{stem}.socket"
    service_name = f"{stem}.service"
    socket_unit = f"""[Unit]
Description=AI Lab SSH via WireGuard - {device_id} loopback socket

[Socket]
ListenStream=127.0.0.1:{listen_port}
NoDelay=true
Service={service_name}

[Install]
WantedBy=sockets.target
"""
    service_unit = f"""[Unit]
Description=AI Lab SSH via WireGuard - {device_id} TCP relay
Documentation=man:systemd-socket-proxyd(8)
Requires=wg-quick@wg0.service
After=wg-quick@wg0.service

[Service]
Type=notify
ExecStart=/usr/lib/systemd/systemd-socket-proxyd {peer}:22
User=ai-lab-gateway
Group=ai-lab-gateway
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_UNIX
CapabilityBoundingSet=
Restart=on-failure
RestartSec=3s
"""
    return {socket_name: socket_unit, service_name: service_unit}


def write_units(units: dict[str, str], output_dir: Path) -> list[Path]:
    """Write new files only; never overwrite existing unit drafts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = [output_dir / name for name in units]
    if any(path.exists() for path in paths):
        raise FileExistsError("unit file already exists; review before replacing")
    created: list[Path] = []
    try:
        for name, content in units.items():
            path = output_dir / name
            with path.open("x", encoding="utf-8") as file:
                file.write(content)
            created.append(path)
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True, help="stable target ID")
    parser.add_argument("--listen-port", type=int, required=True, help="unique gateway loopback port")
    parser.add_argument("--peer-ip", required=True, help="target's WireGuard IPv4 address")
    parser.add_argument("--vpn-subnet", default="10.77.0.0/24", help="reviewed private WireGuard subnet")
    parser.add_argument("--output-dir", type=Path, required=True, help="directory for reviewable unit drafts")
    args = parser.parse_args()
    try:
        units = render_units(args.device_id, args.listen_port, args.peer_ip, args.vpn_subnet)
        paths = write_units(units, args.output_dir)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    for path in paths:
        print(path)
    print("Rendered only; manually review, verify SSH identity, then install using systemd.")


if __name__ == "__main__":
    main()
