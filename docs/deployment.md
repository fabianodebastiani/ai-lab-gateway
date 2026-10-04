# Gateway deployment plan

These steps are prepared for the next VM maintenance session. They are not
executed automatically by the repository.

## MCP service

The prototype currently runs from an interactive shell. The target deployment
uses a dedicated unprivileged service account and systemd. A unit template is
provided at `deploy/ai-lab-gateway.service`.

Intended layout:

```text
/opt/ai-lab-gateway/              application checkout + virtualenv
/var/lib/ai-lab-gateway/          runtime state
/var/lib/ai-lab-gateway/keys/     per-device management keys
/etc/ai-lab-gateway/              non-secret configuration
```

Private key directories must be readable only by the gateway service identity.

## Firewall

The prototype added TCP 80 and 443 to the running iptables INPUT chain ahead
of the image's final reject rule. Runtime insertion is not sufficient for a
reboot-safe deployment.

During hardening:
- preserve administrative SSH access;
- persist only the intended public ports;
- keep MCP/Uvicorn on loopback port 8000;
- keep reverse-tunnel listen ports on loopback only;
- review rpcbind on port 111 and disable it if unused;
- verify rules after reboot before declaring the gateway persistent.

## Authentication gate

The SSH execution backend may be developed and tested locally, but it must not
be registered as a public MCP tool until MCP user authentication and
user-to-device authorization are enforced.

## First device acceptance test

After a target Linux device is available:

1. create a dedicated `ai-gateway` account on the target;
2. create a unique tunnel key for device -> gateway authentication;
3. create a separate management key for gateway -> device authentication;
4. install the tunnel public key with restrictive gateway-side policy;
5. install the management public key in the target `ai-gateway` account;
6. start the reverse-tunnel systemd service;
7. confirm the assigned loopback port exists on the gateway;
8. SSH from the gateway through that port and run a harmless command;
9. test reconnect after network interruption/reboot;
10. only then connect the SSH backend to an authenticated MCP tool.
