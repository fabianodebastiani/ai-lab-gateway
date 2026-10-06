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

The v1 control path is live and validated end-to-end.

The public HTTPS MCP endpoint authenticates ChatGPT users through Auth0, verifies
OAuth tokens and scopes, applies deny-by-default subject/device/action policy,
and reaches registered Linux targets over per-device management SSH identities
through loopback-only reverse SSH tunnels.

The first live target passed the complete tunnel/credential/reboot/timeout
acceptance checklist. A fresh ChatGPT developer-mode app then validated all six
v1 tools through the real production path:

- `gateway_status`
- `list_devices`
- `device_status`
- `exec`
- `read_file`
- `write_file`

The final acceptance included real `uname -a` execution plus a temporary
remote file write/read/cleanup round trip.

See [docs/architecture.md](docs/architecture.md),
[docs/decisions.md](docs/decisions.md),
[docs/build-log.md](docs/build-log.md),
[docs/recovery.md](docs/recovery.md), and the detailed
[ChatGPT + Auth0 OAuth runbook](docs/chatgpt-auth0-oauth-runbook.md).


## Implementation map

Current live/repository state is tracked in
[docs/implementation-status.md](docs/implementation-status.md).

Prepared runbooks:
- [Recovery / rebuild from scratch](docs/recovery.md)
- [Authentication](docs/authentication.md)
- [ChatGPT + Auth0 OAuth runbook](docs/chatgpt-auth0-oauth-runbook.md)
- [Device tunnels](docs/device-tunnels.md)
- [Device bootstrap](docs/bootstrap-device.md)
- [Security model](docs/security-model.md)
- [Deployment](docs/deployment.md)
