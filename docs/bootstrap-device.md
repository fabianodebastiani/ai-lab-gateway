# First device bootstrap plan

This document is a prepared runbook. It is not intended to be executed blindly;
replace the example device ID/port and verify each step during enrollment.

Example assignment:

```text
device id: raspberry-lab
reverse port: 10001
target user: ai-gateway
```

## Credential model

Two different key pairs are used.

### Tunnel key

Generated on the target device. Its private half never leaves the target.
The public half is installed on the gateway's tunnel landing account with
restrictions.

Purpose:

```text
target -> gateway authentication
```

### Management key

Generated/stored on the gateway. Its private half never leaves the gateway.
The public half is installed in the target `ai-gateway` account.

Purpose:

```text
gateway -> target sshd authentication through reverse tunnel
```

## Target preparation

The target will need:

- OpenSSH client;
- OpenSSH server listening locally on port 22;
- a dedicated non-root `ai-gateway` account;
- the management public key in that account's `authorized_keys`;
- a tunnel private key readable only by the tunnel service identity;
- the gateway host key pinned in `known_hosts`;
- the reverse-tunnel systemd unit enabled.

Do not disable normal SSH host-key checking.

## Gateway preparation

The gateway will need:

- a locked-down tunnel landing account;
- one restricted authorized tunnel public key per device;
- a unique loopback reverse port per device;
- the device management private key under the gateway service's protected key
  directory;
- the target host key pinned for the loopback/port alias used by SSH;
- a matching device-registry entry.

## Acceptance test

A device is not considered enrolled until all of these succeed:

1. reverse listener appears only on loopback;
2. gateway can authenticate through the listener to the target;
3. `hostname`, `id` and `uname -a` return from the intended target;
4. tunnel reconnects after its SSH process is killed;
5. tunnel returns after target reboot;
6. a wrong management key cannot log in;
7. another device's tunnel key cannot claim this device's assigned forwarding
   capability;
8. gateway execution timeout works;
9. target account has no unintended sudo/root capability.

Only after these checks should the device be eligible for MCP control.
