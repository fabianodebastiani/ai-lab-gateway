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
