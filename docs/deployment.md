# Gateway deployment and rebuild runbook

This runbook describes the validated reference deployment and the requirements
for reproducing it on a fresh public Linux VM. OCI was used for the prototype,
but the architecture does not depend on OCI.

For a cold start after a long hiatus, begin with `docs/recovery.md`.

## Reference stack

Validated prototype:

- Ubuntu 24.04-class public Linux VM;
- Python 3.12;
- MCP Python SDK 2.x;
- OpenSSH;
- systemd;
- Caddy for public TLS/reverse proxy;
- application bound to `127.0.0.1:8000`;
- HTTPS/MCP exposed through the public DNS name.

The first OCI VM was deliberately small (approximately 1 GiB RAM) to prove
that the gateway does not require a heavyweight platform.

## Filesystem and service identities

Reference layout:

```text
/opt/ai-lab-gateway/              application checkout + virtualenv
/var/lib/ai-lab-gateway/          runtime state owned by service account
/var/lib/ai-lab-gateway/keys/     per-device management private keys
/etc/ai-lab-gateway/              deployment configuration
```

The MCP application runs as the dedicated unprivileged
`ai-lab-gateway` system account. Private key directories must be readable only
by that identity. Use the unit template at `deploy/ai-lab-gateway.service`.

Do not run normal MCP requests as root.

## Application installation on a fresh VM

The exact package-manager commands may vary by distribution, but the resulting
state should be equivalent to:

1. install Python 3.12, venv support, Git, OpenSSH server/client and Caddy;
2. clone this repository;
3. create the `ai-lab-gateway` system identity and protected directories;
4. copy/install the application under `/opt/ai-lab-gateway`;
5. create a virtualenv and install this package plus its locked/declared
   dependencies;
6. install and enable the systemd application unit;
7. verify the application listens only on `127.0.0.1:8000`;
8. configure the HTTPS reverse proxy;
9. run the repository tests and a protocol-level MCP initialization/tool test.

Do not copy old private keys into a new installation merely to make tests pass.
Restore them only from an intentional secure backup; otherwise rotate/re-enroll.

## DNS and TLS

The reference deployment uses `gateway.debasti.com`. The DNS record points to
the public gateway VM and Caddy terminates TLS before proxying to
`127.0.0.1:8000`.

If the hostname changes, review all hostname-sensitive configuration:

- DNS;
- Caddy/TLS;
- MCP transport allowed hosts;
- OAuth resource identifier/audience and protected-resource metadata;
- device-side SSH destination and pinned host identity;
- any deployment environment values.

Never expose TCP 8000 directly to the Internet.

## Firewall

The intended public surface is small:

- administrative SSH;
- TCP 80 where required for HTTP/TLS handling;
- TCP 443 for HTTPS/MCP.

Reverse-tunnel ports such as 10001 are loopback-only and require no public
firewall rule.

The reference OCI Ubuntu image had a final INPUT reject rule and used
`netfilter-persistent` with no-flush restore behavior. During the first
deployment, blindly reloading persistent rules duplicated live INPUT entries.
The duplicates were removed and the intended 80/443 rules were persisted.

Therefore on any rebuilt VM:

- inspect the distribution/cloud image's existing firewall before modifying it;
- preserve administrative SSH while changing rules;
- keep Uvicorn/MCP on loopback;
- never add public rules for reverse-device ports;
- verify the actual live rules and listeners after changes;
- validate persistence after a planned reboot.

Unused `rpcbind` was disabled on the reference VM because it unnecessarily
listened on port 111.

## Gateway tunnel account

Create a dedicated `tunnel` account for device-initiated reverse SSH. It is
not a human or management account.

The validated OpenSSH Match policy is documented in
`docs/device-tunnels.md` and includes public-key-only authentication,
remote-TCP-forwarding-only behavior, `GatewayPorts no`, `MaxSessions 0`, and
no TTY, agent, X11, stream-local, user-RC, or TUN/TAP capability.

Each device public key must additionally carry its own loopback
`permitlisten` restriction. Do not replace this with a shared unrestricted
device key.

## Device enrollment

Use `docs/bootstrap-device.md` as the authoritative enrollment/acceptance
runbook. The device creates the outbound tunnel; the gateway never relies on
Internet-initiated SSH to the device site.

The first validated mapping was:

```text
raspberry-lab -> gateway 127.0.0.1:10001 -> target sshd :22
```

Tunnel and target-management SSH identities are separate.

## Authentication gate

The SSH execution backend already exists and has been validated against a real
target, including application timeout. It must not be registered as a public
MCP control tool until all of these occur in the same request path:

```text
cryptographically valid OAuth token
AND required OAuth scope
AND explicit subject -> device/action authorization
AND enabled registry entry
AND valid target-management SSH credential
```

See `docs/authentication.md` and `docs/security-model.md`.

## Rebuild acceptance

A new VM is not equivalent to the validated reference merely because the
service starts. Before declaring it operational:

1. run repository tests;
2. validate public HTTPS MCP initialization and harmless status call;
3. inspect listeners/firewall and confirm internal ports are loopback-only;
4. enroll a target using the bootstrap runbook and pass all 11 device tests;
5. after OAuth integration exists, prove both authorized success and
   unauthorized fail-closed behavior through the real MCP path;
6. reboot the VM during a planned maintenance window and verify service,
   firewall, Caddy, MCP, and target connectivity return correctly.

The chronological evidence and troubleshooting history behind these
requirements is in `docs/build-log.md`.
