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

## Current user action

The next *non-destructive* step is to use the existing Windows desktop
shortcut **`Conectar AI Lab.bat`** to bring the old WSL tunnel online.
Then the assistant can inspect and prepare the new enrollment against the
live WSL, without needing the user to reveal keys or passwords.

If the shortcut fails, use a Windows terminal to start the Ubuntu WSL
distribution and inspect the existing service, then troubleshoot before
changing credentials. Do **not** delete old service, keys or Gateway entries
to force a reconnection.
