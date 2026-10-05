# Build Log

Chronological record of the prototype environment and significant setup actions.

## 2026-10-03 — Initial cloud gateway

Created the first gateway instance:

- hostname: `ai-lab-gateway-01`
- platform: Oracle Cloud Infrastructure
- region: Brazil Southeast (Vinhedo)
- OS: Canonical Ubuntu 24.04 Minimal
- reported release after boot: Ubuntu 24.04.5 LTS
- architecture: x86_64
- kernel at first login: `6.17.0-1020-oracle`
- memory observed: 954 MiB
- root filesystem: 45 GiB, about 1.1 GiB used at first inspection
- swap: none

### Networking

A VCN and subnet were created during instance provisioning. The instance initially had only its private IPv4 address.

The VCN already had an Internet Gateway and appropriate route table. OCI's quick action was used to create/attach a Network Security Group and configure Internet connectivity. An ephemeral public IPv4 was then assigned to the primary private IP.

Administrative SSH connectivity from the Internet was successfully established on TCP 22.

### SSH administration

OCI-generated private key was stored locally by the administrator. Windows OpenSSH initially rejected the key because its ACL allowed another local group to read it. The ACL was restricted to the administrator account, after which public-key SSH login as `ubuntu` succeeded.

Private keys and other credentials must never be committed to this repository.

### Base system

Initial validation commands:

```text
uname -a
free -h
df -h /
```

confirmed x86_64 architecture, roughly 1 GiB RAM and a 45 GiB root volume.

The base Ubuntu package indexes and installed packages were then updated with `apt update` and `apt upgrade`.

## 2026-10-03 — Local MCP milestone validated

The first Python MCP service was validated end-to-end on the OCI gateway VM.

Environment:
- Ubuntu 24.04 LTS, x86_64
- Python 3.12.3
- MCP Python SDK 2.3.0
- MCP transport: Streamable HTTP
- Local endpoint: `http://127.0.0.1:8000/mcp`

Validation:
- MCP server started successfully under Uvicorn.
- A separate MCP client session initialized successfully.
- `tools/list` discovered `gateway_status`.
- `tools/call` executed `gateway_status` successfully.
- The response returned structured content with `status: ok`, hostname `ai-lab-gateway-01`, Python 3.12.3, and x86_64 architecture.
- No device-control or SSH execution tools are exposed yet.

Implementation note:
- The initial skeleton used the MCP 1.x `FastMCP` API. Since the installed SDK is MCP 2.3.0, it was migrated to `MCPServer` and the project dependency was constrained to `mcp>=2,<3`.

## 2026-10-03 — Public HTTPS MCP milestone validated

The gateway was published at `gateway.debasti.com` with Cloudflare DNS in DNS-only mode. Caddy terminates public TLS on TCP 443 and reverse-proxies to the MCP service on `127.0.0.1:8000`; port 8000 remains private to the VM.

During TLS bring-up, OCI network rules alone were not sufficient: the Ubuntu image's INPUT chain contained a final reject rule with only SSH allowed ahead of it. TCP 80 and 443 were inserted before that reject rule.

The first public MCP attempt reached the application but returned HTTP 421 because MCP transport security rejected the public Host header. `gateway.debasti.com` was then explicitly added to `TransportSecuritySettings.allowed_hosts`.

Final public validation succeeded against:

```text
https://gateway.debasti.com/mcp
```

The external MCP client:
- completed MCP initialization over public HTTPS;
- discovered `gateway_status` with `tools/list`;
- called `gateway_status` successfully;
- received structured `status: ok` from `ai-lab-gateway-01`.

This validates the path:

```text
MCP client -> Internet -> TLS/Caddy -> localhost MCP server -> tool call
```

Security observation: Internet scanners began reaching the public web endpoint shortly after TCP 80/443 were opened. Device-control tools must not be exposed before authentication/authorization is in place.

## 2026-10-05 — Gateway hardening and production service

The repository-side implementation was validated on the OCI VM with Python
3.12.3, MCP SDK 2.3.0 and pytest 8.4.2. All 16 tests passed.

The MCP application was installed under `/opt/ai-lab-gateway` with a production
virtualenv and runs as the dedicated `ai-lab-gateway` system user. The
`ai-lab-gateway.service` unit is enabled and active. The application listens
only on `127.0.0.1:8000`, with Caddy providing the public HTTPS boundary.

The public MCP path was revalidated with a protocol client: initialization,
`tools/list`, and `gateway_status` all succeeded through public HTTPS.

### Firewall persistence

The intended live INPUT policy was reduced to established traffic, required
ICMP/loopback, SSH, HTTP, HTTPS, followed by reject. TCP 80/443 were also added
to `/etc/iptables/rules.v4` so they survive reboot.

The OCI image configures `netfilter-persistent` with
`IPTABLES_RESTORE_NOFLUSH=yes` and the IPv6 equivalent. A manual
`netfilter-persistent reload` therefore duplicated rules in the live chain
instead of replacing it. The duplicates were removed and the live chain was
verified clean. Do not use routine reloads as if they were flush-and-replace;
the persisted rules should be validated at the next planned reboot.

### rpcbind

`rpcbind` was listening globally on TCP/UDP 111, but `rpcinfo` showed no
dependent RPC services. Both `rpcbind.service` and `rpcbind.socket` were
disabled/stopped. Port 111 was verified to have no remaining listeners.

## 2026-10-05 — First managed Linux device validated

The first target, `raspberry-lab`, is an ARM64 Ubuntu 24.04 Linux system. A
dedicated non-root `ai-gateway` account was created on the target without sudo
privileges.

Two independent ED25519 credential roles were created:

- a device-held tunnel identity authenticates the target to the gateway's
  `tunnel` account;
- a gateway-held management identity authenticates the gateway to the target's
  `ai-gateway` account.

Private keys remain on their respective originating side and were not copied
into the repository.

### Gateway tunnel account

A dedicated `tunnel` account was created with `/usr/sbin/nologin`. The
effective OpenSSH Match policy was validated before reloading sshd:

```text
PubkeyAuthentication yes
PasswordAuthentication no
X11Forwarding no
PermitTTY no
GatewayPorts no
AllowTcpForwarding remote
AllowAgentForwarding no
```

The first device's public key is further constrained with
`permitlisten="127.0.0.1:10001"` plus no-agent-forwarding, no-X11-forwarding,
no-pty and no-user-rc key options.

### Host identity and reverse forwarding

Before the first device trusted the gateway, the ED25519 fingerprint presented
over the network was compared with the gateway's own host public key. The
management direction was similarly checked by comparing the target's host-key
fingerprint with the key learned through the reverse tunnel.

The target successfully created:

```text
gateway 127.0.0.1:10001 -> reverse SSH tunnel -> target 127.0.0.1:22
```

The listener was verified to bind only to gateway loopback. From the gateway,
SSH through port 10001 authenticated with the separate management key and
executed commands as the target's non-root `ai-gateway` account.

### Persistence and failure recovery

After manual validation, the target tunnel was installed as
`ai-lab-reverse-tunnel.service`, enabled at boot, and configured with strict
host-key checking, SSH keepalives, `ExitOnForwardFailure=yes`, and automatic
restart.

The tunnel SSH process was deliberately killed. systemd scheduled a restart,
created a new SSH process, the reverse listener reappeared, and a subsequent
gateway-to-target command returned successfully. This validates automatic
recovery from a tunnel-process failure without operator intervention.

### Safety state after the milestone

The live transport path can now reach the first target, but it is not exposed
as a public MCP control tool. The public MCP server remains status-only until
OAuth identity verification and deny-by-default application authorization are
enforced end-to-end.

Remaining operational work includes final defense-in-depth restrictions for
the tunnel account, a real target reboot test, OAuth/provider integration,
application wiring of the device registry/control plane, audit retention, and
stable public-IP/DNS planning.
