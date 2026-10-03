# Architecture

## Purpose

AI Lab Gateway is a control plane between an AI client and Linux devices that are not necessarily directly reachable from the Internet.

The gateway should allow an authorized AI client to perform normal development and laboratory work on a target Linux system: inspect files and logs, create or edit files, clone/pull repositories, build software, run programs and tests, inspect processes and services, and interact with locally installed hardware tools.

## Initial topology

```text
                 HTTPS / MCP
+-------------+  authenticated  +--------------------+
| AI client   | --------------> | AI Lab Gateway     |
| / ChatGPT   |                 | public Linux VM    |
+-------------+                 +----------+---------+
                                           ^
                                           |
                                           | SSH / reverse SSH
                                           | device initiates connection
                                           |
                                +----------+---------+
                                | Linux device       |
                                | Pi / embedded box  |
                                +--------------------+
```

## Gateway responsibilities

The gateway is expected to provide:

1. An authenticated MCP endpoint over HTTPS.
2. A device registry.
3. User-to-device authorization.
4. SSH session/tunnel management.
5. A small set of generic tools, initially centered on command execution and file operations.
6. Audit information such as user/device, command, timestamp, exit code, duration, stdout and stderr where appropriate.

A possible minimal MCP surface is:

- `exec(device, command, cwd, timeout)`
- `read_file(device, path)`
- `write_file(device, path, content)`
- process/service status operations

This is deliberately generic. Higher-level semantic tools can be added later.

## Device side

The initial design avoids a heavy proprietary agent. A device needs Linux, SSH and a persistent outbound connection mechanism such as systemd-managed SSH/autossh.

Hardware-specific knowledge remains on the device. For example, a target may contain radio libraries, GPIO/SPI utilities, build systems, test scripts or vendor command-line tools. The AI can discover and operate those through documentation plus generic gateway capabilities.

## Security boundaries

Credentials should be separated by purpose:

- cloud VM administration key;
- per-device SSH/tunnel credentials;
- MCP client/user authentication.

A single shared SSH credential across all devices/users is explicitly not the intended model.

Target access should begin with a non-root Linux account. Privileged operations, when needed, should be exposed deliberately through restricted sudo policy rather than unrestricted root access.

The public surface should converge on HTTPS/MCP (typically TCP 443). Administrative SSH is separate and should be hardened.

## Multi-user / multi-device direction

The intended authorization relationship is conceptually:

```text
user -> permissions -> device
```

Each device has its own identity. The gateway resolves which devices a user may access before executing an operation.

## Out of scope for the first prototype

- Full network overlay/VPN.
- Kubernetes or other orchestration platforms.
- A heavyweight database unless demonstrated necessary.
- Hardware-specific behavior embedded into the MCP protocol.
- Unrestricted root shell as the normal execution model.
