# AI Lab Gateway

Experimental gateway for giving AI clients controlled, auditable command-line access to remote Linux devices.

The project is intended for labs, development boards, Raspberry Pi-class systems, embedded Linux targets, and other machines that may sit behind NAT/CGNAT or restrictive firewalls.

## Core idea

```text
AI client / ChatGPT
        |
        | MCP over HTTPS
        v
AI Lab Gateway (public Linux VM)
        |
        | SSH / reverse SSH tunnels
        v
Remote Linux device(s)
```

Remote devices initiate outbound SSH connections to the gateway. This avoids requiring inbound connectivity at the device site. The AI interacts with the gateway through MCP; the gateway mediates access to registered devices.

## Design goals

- Generic Linux access rather than hardware-specific MCP implementations.
- Minimal software footprint on remote devices.
- Work through NAT/CGNAT using outbound connections.
- Separate authentication for AI clients, gateway administration, and devices.
- Support multiple users and multiple devices with explicit authorization mappings.
- Keep hardware-specific libraries, scripts and tools on the target device.
- Make actions observable and auditable.
- Start small and add semantic MCP tools only where they add value.

## Status

Prototype in progress. The public HTTPS MCP path has been validated end-to-end at `https://gateway.debasti.com/mcp`: TLS termination through Caddy, MCP initialization, tool discovery, and a real `gateway_status` tool call all succeeded.

No device-control or SSH execution tools are exposed yet. The next implementation milestones are service persistence/hardening, authenticated user access, and the first reverse-SSH device tunnel.

See [docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md), and [docs/build-log.md](docs/build-log.md).


## Implementation map

The live public MCP endpoint is intentionally status-only while authentication
is being completed. Repository-side work for device registry, authorization,
reverse SSH, audit and deployment is tracked in
[docs/implementation-status.md](docs/implementation-status.md).

Prepared runbooks:
- [Authentication](docs/authentication.md)
- [Device tunnels](docs/device-tunnels.md)
- [Device bootstrap](docs/bootstrap-device.md)
- [Security model](docs/security-model.md)
- [Deployment](docs/deployment.md)
