# Recovery and rebuild guide

## Purpose

This document is the cold-start entry point for a future operator or AI that
has only this repository and must understand, rebuild, validate, or continue
AI Lab Gateway after a long period of inactivity.

Do not treat the current cloud VM as the source of truth. The repository is the
design and implementation record; runtime secrets and private keys deliberately
do not belong in Git and must be recreated or restored securely.

## What the project is

AI Lab Gateway gives an authenticated AI client controlled command-line access
to registered Linux devices, including devices behind NAT/CGNAT. The Linux
target can then act as the bridge to local development tools and hardware such
as USB, serial, SPI, I2C, GPIO, radios, sensors, SDRs, and other peripherals.

The intended development loop is:

```text
human -> AI client -> GitHub / source control
                  -> MCP over HTTPS -> gateway
                                      -> authorized command
                                      -> Linux target
                                      -> local hardware/tools
```

The gateway is generic. Hardware-specific code belongs on the target, not in
the MCP transport layer.

## Architecture invariants

Preserve these unless a later ADR explicitly replaces them:

1. The AI-facing interface is remote MCP over HTTPS.
2. Remote Linux devices initiate outbound reverse SSH; no inbound SSH exposure
   is required at the device site.
3. Reverse listeners bind to gateway loopback only.
4. Platform/OAuth identity, tunnel identity, target-management identity, and
   cloud-administrator identity are separate security planes.
5. Each device has its own tunnel key and management key.
6. Tunnel credentials may maintain their assigned reverse forward but may not
   open gateway sessions or commands.
7. Target management uses a dedicated non-root account by default.
8. Application authorization is deny-by-default and requires both an OAuth
   scope and an explicit subject -> device/action grant.
9. The public MCP must not expose exec/write/control capabilities until
   authentication and authorization are enforced in the same request path.
10. Private keys, tokens, authorized_keys, known_hosts, and OAuth secrets never
    belong in Git.

Read `docs/architecture.md`, `docs/security-model.md`, and
`docs/decisions.md` before changing these boundaries.

## Current validated reference implementation

The prototype was validated on Ubuntu 24.04 with Python 3.12, OpenSSH, Caddy,
systemd, and MCP Python SDK 2.x. OCI was used for the first public VM, but OCI
is not an architectural requirement: any suitably reachable Linux VM can host
the gateway.

The reference public name is `gateway.debasti.com`; deployments may use
another DNS name, but OAuth audience/resource metadata, Caddy, MCP allowed
hosts, device host trust, and documentation/configuration must then be updated
consistently.

The first reference device is `raspberry-lab`, assigned gateway loopback port
10001. Fixed unique ports are a prototype choice; dynamic allocation is not yet
required.

## Rebuild order on a fresh VM

A future rebuild should proceed in this order:

1. Provision an Ubuntu-class public Linux VM and retain a safe administrative
   access path.
2. Point DNS at the VM and establish HTTPS/TLS.
3. Clone this repository and install Python 3.12 plus the project dependencies.
4. Create the dedicated `ai-lab-gateway` service identity and protected
   runtime/configuration directories described in `docs/deployment.md`.
5. Install the application under `/opt/ai-lab-gateway` and run it under
   systemd, listening only on `127.0.0.1:8000`.
6. Put Caddy (or an equivalent TLS reverse proxy) in front of the MCP service.
   Only the intended HTTPS/web ports and administrative SSH should be public.
7. Create and harden the gateway `tunnel` account exactly as described in
   `docs/device-tunnels.md`; reverse forwarding is allowed, session channels
   are not.
8. For every target, follow `docs/bootstrap-device.md`: generate a unique
   target-held tunnel key, a separate gateway-held management key, deliberately
   pin host identities, assign a unique loopback port, install the target
   systemd tunnel, and add the device registry entry.
9. Run the full 11-item device acceptance checklist before making a device
   eligible for MCP control.
10. Configure Auth0/OAuth according to `docs/authentication.md` and the
    detailed `docs/chatgpt-auth0-oauth-runbook.md`: exact `/mcp` resource
    audience, CIMD client import, both v1 scopes, Google/domain-level login
    connection, cryptographic token verification, protected-resource metadata,
    and deny-by-default authorization.
11. Verify the public metadata and unauthenticated 401 challenge before creating
    a ChatGPT developer-mode app. If a materially changed tool catalog or OAuth
    discovery state is not reflected after reconnect, create one fresh
    developer-mode app rather than assuming old app state will refresh.
12. Validate all six v1 tools through the real ChatGPT path, including a harmless
    command and a temporary write/read/cleanup round trip.
13. Re-run repository tests plus real MCP and device-path acceptance tests.

The historical commands, incidents, firewall nuances, and first-device
validation evidence are recorded in `docs/build-log.md`.

## Runtime state that cannot be recovered from Git

A fresh installation must recreate or securely restore:

- cloud administrator credentials;
- TLS/DNS provider credentials where applicable;
- OAuth provider/client secrets and signing/trust configuration;
- each target's private tunnel key (normally generated and retained on target);
- each gateway-held per-device management private key;
- SSH host-trust state established during enrollment;
- gateway tunnel-account authorized_keys entries containing target public keys;
- production environment/secrets;
- authorization assignments for real platform subjects;
- audit data if historical retention is required.

If the old VM or target is lost and its private credential cannot be recovered,
create a new key pair and re-enroll/re-authorize it. Never reconstruct a private
key from documentation or commit it for convenience.

## Validation before declaring a rebuilt gateway operational

At minimum verify:

- repository unit tests pass;
- MCP initializes through the public HTTPS endpoint;
- harmless status tool discovery/call succeeds;
- application service runs non-root and listens on loopback;
- reverse device port is loopback-only;
- legitimate device tunnel survives process failure and real target reboot;
- tunnel key cannot execute a gateway command or allocate another listener;
- wrong management key is rejected by the target;
- correct management key executes as the intended non-root target user;
- application-level execution timeout is enforced;
- OAuth token signature/issuer/audience/lifetime/scope are validated;
- an unauthorized subject/device/action request fails closed;
- an authorized request can traverse MCP -> authorization -> SSH -> target;
- no private device-control endpoint is accidentally Internet-facing.

## Documentation map for a future AI

Read in this order:

- `README.md` — purpose, status, and navigation.
- `docs/recovery.md` — cold-start/rebuild instructions (this document).
- `docs/architecture.md` — topology, identity planes, request path.
- `docs/decisions.md` — ADRs and rationale; do not silently reverse them.
- `docs/security-model.md` — security invariants and execution gate.
- `docs/deployment.md` — gateway runtime/deployment layout.
- `docs/device-tunnels.md` — reverse SSH design and hardening.
- `docs/bootstrap-device.md` — repeatable device enrollment and acceptance.
- `docs/authentication.md` — OAuth resource-server design.
- `docs/chatgpt-auth0-oauth-runbook.md` — exact ChatGPT/Auth0 reconstruction,
  scope-step-up behavior, token cutoff, product-state pitfalls, diagnostics and
  final acceptance sequence.
- `docs/implementation-status.md` — what is actually implemented/live versus
  deliberately pending.
- `docs/build-log.md` — chronological evidence, troubleshooting details, and
  operational lessons.

Then inspect `src/`, `deploy/`, `scripts/`, `config/`, tests, and the
Git history before modifying production behavior.

## Current post-v1 work

Identity-to-execution integration is complete and has been validated through the
real ChatGPT product path:

```text
AI client
  -> OAuth-authenticated MCP request
  -> scope check
  -> explicit subject/device/action authorization
  -> registry lookup
  -> bounded SSH execution
  -> target
  -> audit metadata
```

The public v1 surface now includes status, device discovery/status, command
execution, text-file read and text-file write. The remaining work is operational
hardening and scale rather than completion of the basic control path:

- validate/deploy any repository commits newer than the last live acceptance;
- finalize audit rotation/retention;
- replace prototype JSON registry/authorization if scale requires a database;
- define narrow sudo only for concrete privileged target operations;
- remove stale ChatGPT development apps and old Auth0 rollback objects after
  the rollback window;
- use owned Google OAuth credentials for a long-lived production deployment;
- consider a deterministic deployment helper and reserved/stable public IP.

Before continuing after a long hiatus, recheck current MCP/OpenAI/Auth0 behavior
rather than assuming the October 2026 developer-mode UI and snapshot behavior
remain unchanged.
