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

## Next

Prepare a minimal development/runtime environment, decide the first MCP implementation, and establish the first controlled device tunnel.


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

Next milestone:
- Publish the MCP endpoint through HTTPS while keeping Uvicorn bound to localhost.
- Add authentication before exposing device-control capabilities.
