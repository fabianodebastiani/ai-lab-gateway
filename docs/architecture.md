# Architecture

## Purpose

AI Lab Gateway is a control plane between an authenticated AI client and Linux devices that are not necessarily directly reachable from the Internet.

The gateway should allow an authorized AI client to perform normal development and laboratory work on a target Linux system: inspect files and logs, create or edit files, clone/pull repositories, build software, run programs and tests, inspect processes and services, and interact with locally installed hardware tools.

## Topology

```text
                     HTTPS / MCP
+----------------+   OAuth identity    +-------------------------+
| AI client      | ------------------> | AI Lab Gateway          |
| / ChatGPT      |                     | public Linux VM         |
+----------------+                     |                         |
                                       | authn -> authz          |
                                       | device registry         |
                                       | audit                   |
                                       +------------+------------+
                                                    |
                                             loopback SSH
                                         127.0.0.1:<device-port>
                                                    |
                                  reverse TCP forward carried
                                  inside device-initiated SSH
                                                    |
                                       +------------v------------+
                                       | Linux target            |
                                       | sshd :22                 |
                                       | Pi / embedded / server  |
                                       +-------------------------+
```

## Identity planes

Three identity planes remain separate:

1. **Platform identity.** OAuth/MCP establishes a human/client subject. The application maps that subject to allowed devices/actions. Platform users are not gateway Unix users.
2. **Tunnel identity.** Each device has a unique SSH key used only to authenticate its outbound reverse-tunnel session to the gateway.
3. **Target management identity.** The gateway authenticates to the target sshd, through the reverse forward, with a separate per-device management key.

The cloud administrator SSH identity is a fourth operational credential and is not used by normal MCP requests.

## Gateway request path

A live execution request follows this order:

```text
authenticated subject
       |
       v
authorization check ---- deny by default
       |
       v
device registry lookup
       |
       v
SSH to loopback:<assigned-port>
       |
       v
target sshd authentication
       |
       v
bounded command
       |
       v
stdout / stderr / exit code
       |
       +---- audit metadata
```

The SSH backend is reached only through the authenticated control plane after
OAuth scope checks, private authorization, registry lookup, and per-device SSH
identity selection succeed.

## Device registry

The prototype uses a small JSON registry. A device record contains routing and non-secret metadata:

- stable device ID and display name;
- target SSH user;
- loopback tunnel host and assigned port;
- path to the per-device management identity;
- enabled/disabled state.

Private key material is never stored in the registry or repository. Duplicate device IDs/ports are rejected and non-loopback tunnel hosts are rejected.

## Authorization

The prototype policy maps an authenticated subject to explicit device/action grants. Missing subjects, devices and actions are denied.

Initial action vocabulary can include:

- `status`
- `exec`
- `read_file`
- `write_file`

This policy format is intentionally replaceable by a database later.

## Reverse SSH lifecycle

The target device starts and maintains an outbound SSH session to the gateway using systemd. The session requests a reverse forward such as:

```text
gateway 127.0.0.1:10001 -> target 127.0.0.1:22
```

The reverse listener is internal to the gateway. It is not exposed on a public interface. See `docs/device-tunnels.md`.

## MCP surface

The stable v1 public MCP surface is:

- `gateway_status()`
- `list_devices()`
- `device_status(device)`
- `exec(device, command, timeout)`
- `read_file(device, path)`
- `write_file(device, path, content)`

`gateway:read` is the global authenticated boundary. `exec` and
`write_file` additionally require `gateway:control`, and every device
operation is also checked against the private subject/device/action policy.

The OAuth resource metadata and step-up behavior are documented in
`docs/chatgpt-auth0-oauth-runbook.md`.

Higher-level semantic tools can be added later without changing the transport
architecture.

## Audit

Security-relevant remote status, command, file-read and file-write actions
produce append-only JSONL audit metadata for subject, device, action, result,
duration and exit code. Command text, file contents, stdout and stderr are not
retained by default because they may contain secrets or personal data.

## Service boundaries

The intended public surface is HTTPS/MCP on TCP 443. Caddy terminates TLS and proxies to Uvicorn on loopback port 8000. Administrative SSH remains separate.

The MCP process should run as a dedicated unprivileged systemd service. Reverse-forward ports remain loopback-only. Target access defaults to a non-root `ai-gateway` account with narrowly scoped sudo only when justified.

## Out of scope for the first prototype

- Full network overlay/VPN.
- Kubernetes or other orchestration platforms.
- A heavyweight database before scale requires it.
- Hardware-specific behavior embedded into the MCP protocol.
- One Linux account per human platform user.
- Publicly exposed reverse-forward ports.
- Unrestricted root shell as the normal execution model.
