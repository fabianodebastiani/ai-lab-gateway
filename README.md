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

The transport foundation is live and validated. The public HTTPS MCP endpoint works, the first remote Linux device maintains a persistent reverse-SSH tunnel through NAT, and gateway-to-device command execution has passed the complete 11-item live acceptance checklist, including reboot recovery, credential-isolation negative tests, and application-level timeout.

The public MCP surface remains intentionally status-only. Remote execution will be exposed only after OAuth identity verification and deny-by-default subject/device/action authorization are enforced end-to-end.

See [docs/architecture.md](docs/architecture.md), [docs/decisions.md](docs/decisions.md), [docs/build-log.md](docs/build-log.md), and [docs/recovery.md](docs/recovery.md).


## Implementation map

The live public MCP endpoint is intentionally status-only while authentication
is being completed. Repository-side work for device registry, authorization,
reverse SSH, audit and deployment is tracked in
[docs/implementation-status.md](docs/implementation-status.md).

Prepared runbooks:
- [Recovery / rebuild from scratch](docs/recovery.md)
- [Authentication](docs/authentication.md)
- [Device tunnels](docs/device-tunnels.md)
- [Device bootstrap](docs/bootstrap-device.md)
- [Security model](docs/security-model.md)
- [Deployment](docs/deployment.md)
