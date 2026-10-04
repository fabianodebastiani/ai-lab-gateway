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

During TLS bring-up, OCI network rules alone were not sufficient: the Ubuntu image's INPUT chain contained a final reject rule with only SSH allowed ahead of it. TCP 80 and 443 were inserted before that reject rule. These runtime iptables changes still need to be made persistent and reviewed as part of hardening.

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

### Remaining operational work

- Run the MCP service under systemd rather than an interactive SSH shell.
- Make the intended firewall policy persistent and remove accidental/unneeded exposure.
- Review the globally listening rpcbind service (TCP/UDP 111) and disable it if unused.
- Implement OAuth/user authentication before device-control tools.
- Establish the first reverse-SSH tunnel from a Linux target.
- Add device registry, user-to-device authorization, and audit logging.
- Consider a reserved/stable public IP; the current public IPv4 was provisioned as ephemeral.
