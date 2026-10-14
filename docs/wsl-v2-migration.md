# WSL migration pilot — new enrollment v2, restricted by default

Status: **planning and environment preflight** (2026-10-14 UTC).
Do not treat this file as proof the v2 pairing API is already deployed.

## Selected pilot

- Existing registered device: `windows-wsl` (Ubuntu 24.04 WSL on the user's Windows PC).
- Device management SSH account: `ai-gateway` (unprivileged).
- Existing reverse SSH listener: gateway `127.0.0.1:10002`.
- Existing tunnel unit on WSL: `ai-lab-wsl-tunnel.service`.
- Existing use pattern: **on demand**, via the Windows shortcuts `Conectar AI Lab.bat`
  and `Desconectar AI Lab.bat`. Preserve this behavior.
- Existing configuration is deliberately considered *replaceable*, but it
  must not be deleted until the new version passes its acceptance tests.
- `raspberry-lab` uses port 10001 and must remain completely unaffected.
- At 2026-10-14 02:45 UTC neither 10002 nor 10003 was listening on the
  Oracle gateway, consistent with an on-demand WSL tunnel currently off.
  Gateway, human-approval web and privileged broker services remained active.

## Live WSL connection verified — 2026-10-14 02:56 UTC

After the operator restarted the existing `ai-lab-wsl-tunnel.service` on
Ubuntu WSL, the authorized MCP `device_status("windows-wsl")` returned
**online** with hostname `LAPTOP-5RJJ0KBM`; the Oracle Gateway listened
on loopback port **10002**, and its other services remained active.
Remote management SSH returned non-root `ai-gateway`.

The current service is `ActiveState=active`, `UnitFileState=disabled`,
`Restart=on-failure`, `User=ai-gateway`. The systemd unit includes strict
SSH host-key checking, connection keepalives and
`ExitOnForwardFailure=yes`. The WSL Linux has `systemd=true`.
This is the intended **On-demand** configuration: starting the service
connects, stopping disconnects, and an ssh failure while running restarts
it; there is **no** Linux auto-start on next WSL boot.

The first reusable v2 local management helper was published at
`scripts/device-connection.sh` and copied to
`/home/ai-gateway/device-connection-v2.sh` solely for non-destructive
WSL tests. Bash syntax validation and read-only status succeeded:

```text
unit=ai-lab-wsl-tunnel.service
mode=on-demand
active=active
systemd-enabled=disabled
```

An invalid unit `ssh.service` was rejected, exit 2. The helper was
**not installed as a privileged system command**, and no WSL keys, sudo
grants, systemd configuration or old tunnel were changed. The current
production listener still uses port 10002; the v2 candidate port 10003
is not yet enrolled. We will preserve On-demand behavior during cutover.

**Connection mode != permission mode:** future pairing defaults Restricted,
while connection mode is chosen separately (On-demand for WSL laptops;
Persistent for always-on Linux/servers).

## Product decision

**Pairing always produces a Restricted device.** Only later may the operator
separately select Restricted, Unrestricted or Partial with a duration dropdown.
Do not ask for administrative privileges during pairing or give the new
management account implicit sudo access.

## Safe replacement procedure (intended v2 behavior)

1. **Preflight:** user starts the existing `Conectar AI Lab.bat` shortcut.
   Through the existing authorized MCP connection we inspect WSL systemd,
   sshd, existing tunnel, and the non-privileged `ai-gateway` account.
   We do not copy, display or rotate secrets yet.
2. **Prepare in parallel:** implement/test HTTPS one-time pairing, device
   identity verification, operator approval and transactional registry
   update. Reserve the *candidate* reverse port 10003 only after confirming
   it is free. Generate a **fresh** target-side tunnel key on WSL and a
   **fresh** gateway-side management key in the gateway's protected storage.
   Keep each private key on its originating system.
3. **Stage:** place a new WSL tunnel service next to the old one, preserving
   the on-demand behavior. Limit the candidate tunnel credential to
   `permitlisten="127.0.0.1:10003"`. Pin the SSH host keys in both
   directions. The temporary candidate remains **pending/inactive** in the
   device registry; the registered `windows-wsl` continues to use old
   working credentials and port 10002.
4. **Verify:** over port 10003, test correct target identity, key mismatch
   refusal, non-root status, failure of unexpected sudo, file read/write,
   command timeouts and reconnect. Confirm user approval of **device
   pairing**, not privileges. The enforced initial profile is Restricted.
5. **Cut over atomically:** change the `windows-wsl` registry/policy to use
   the new port and management key; confirm normal ChatGPT `device_status`
   and `exec` work. Old SSH keys and old tunnel service remain available
   only as short-lived recovery during cutover and are then explicitly
   revoked/removed; no persistent duplicate device.
6. **Verify revocation:** try the old tunnel credential and management
   credential and confirm both are rejected. Check on-demand start/stop,
   restart behavior, and confirm other devices are unaffected.
7. **Only after successful enrollment:** test a separately requested
   Partial access grant and expiry. Do not mix initial identity pairing
   with admin permission grants.

## Deployment prerequisite

The Oracle `ai-maintenance` user's temporary root/sudo bootstrap has
already expired; `sudo -n` is no longer available via ordinary MCP `exec`.
Installing a root-owned pairing service, changing the gateway tunnel account's
authorized keys or editing protected runtime registry requires a **distinct,
human-authorized administrative deployment** (via the `ubuntu` Oracle
recovery account, or an explicitly whitelisted deployment mechanism).
Never try to reintroduce general passwordless sudo or use MCP operational
commands to bypass this boundary.

## Next steps

1. Implement a pairing API and target installer that support independent
   On-demand/Persistent connection mode and enforce Restricted access on
   enrollment.
2. Stage a fresh, separately generated SSH identity on an unused loopback
   port (proposed 10003), without touching the old functioning SSH keys.
3. Arrange a narrowly authorized Oracle administrative deployment to
   provision the protected device registry, SSH tunnel allowlist and
   management key. Do not reinstate general passwordless sudo.
4. Validate the new candidate tunnel (host identity, non-root user,
   rejection of unauthorized sudo, reconnect tests, on-demand start/stop).
5. Switch `windows-wsl` to the new connection and revoke old credentials
   only after verified successful cutover. Retain the existing Windows
   connect/disconnect shortcuts or replace them with equivalent
   one-click controls.

**No immediate manual action is required** while code and tests are
prepared. Keep the current WSL connection running for development.
