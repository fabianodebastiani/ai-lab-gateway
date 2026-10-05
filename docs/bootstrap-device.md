# Device bootstrap runbook

This runbook captures the enrollment pattern validated with the first live
device. Do not execute it blindly: assign a unique device ID/port and verify
host identities during every enrollment.

Example assignment:

```text
device id: raspberry-lab
reverse port: 10001
target user: ai-gateway
```

## Credential model

Two different key pairs are mandatory.

### Tunnel key

Generated on the target device. Its private half never leaves the target.
The public half is installed on the gateway's `tunnel` landing account with a
per-device `permitlisten` restriction.

Purpose:

```text
target -> gateway authentication and assigned reverse forwarding only
```

The gateway-side tunnel account is not a management shell account. The
validated policy permits remote TCP forwarding but disables session channels
with `MaxSessions 0` and disables stream-local, TUN/TAP, agent, X11, TTY and
user-RC capabilities.

### Management key

Generated/stored on the gateway. Its private half never leaves the gateway.
The public half is installed in the target `ai-gateway` account.

Purpose:

```text
gateway -> target sshd authentication through reverse tunnel
```

## Target preparation

The target needs:

- OpenSSH client and server, with sshd reachable locally on port 22;
- a dedicated non-root `ai-gateway` account with no sudo grant by default;
- `~ai-gateway/.ssh` mode 700;
- a device-local `tunnel_ed25519` private key mode 600;
- the gateway management public key in `authorized_keys`;
- the gateway host identity deliberately pinned in `known_hosts`;
- the reverse-tunnel systemd unit enabled.

`scripts/enroll-device.sh` performs only the safe local preparation and key
creation. It deliberately stops before trust is established or a tunnel is
started.

Do not disable normal SSH host-key checking and do not copy the tunnel private
key to the gateway.

## Gateway preparation

The gateway needs:

- the hardened `tunnel` landing account;
- one distinct tunnel public key per device;
- a unique loopback reverse port per device;
- an `authorized_keys` entry restricting that key to its assigned listener,
  for example
  `permitlisten="127.0.0.1:10001",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc`;
- a distinct management private key under the `ai-lab-gateway` service's
  protected runtime key directory;
- the corresponding management public key installed on the target;
- the target host identity pinned for the loopback/port alias used by SSH;
- a matching device-registry entry.

Never store actual private keys, `authorized_keys`, `known_hosts`, OAuth
secrets or access tokens in this repository.

## Reverse-tunnel service

Copy `deploy/device/reverse-tunnel.service` to the target and replace the
example reverse port if the device is not assigned 10001. The validated service
runs as `ai-gateway`, uses `IdentitiesOnly=yes`,
`StrictHostKeyChecking=yes`, `ExitOnForwardFailure=yes`, 30-second
keepalives, `Restart=always`, and `RestartSec=5`.

The reverse listener must always use an explicit loopback bind:

```text
-R 127.0.0.1:<assigned-port>:127.0.0.1:22
```

## Acceptance test

A device is not considered enrolled until all of these succeed:

1. a fresh tunnel connection establishes under the hardened gateway policy;
2. reverse listener appears only on gateway loopback;
3. gateway authenticates through the listener with the separate management
   identity;
4. `hostname`, `id` and `uname -a` identify the intended target;
5. killing the tunnel SSH process causes systemd to recreate it;
6. tunnel returns after a real target reboot;
7. the tunnel credential cannot open a session or execute a remote command;
8. the tunnel credential cannot allocate a listener other than its assigned
   `permitlisten` endpoint;
9. a wrong management key cannot log in;
10. gateway execution timeout works;
11. target account has no unintended sudo/root capability.

Only after these checks should the device be eligible for MCP control.

For the first live device, items 1-5, 7-8 and 11 have been validated. The real
target reboot, explicit wrong-management-key test, and application-level
execution-timeout acceptance test remain to be completed.
