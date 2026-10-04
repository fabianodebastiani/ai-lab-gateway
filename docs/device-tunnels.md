# Device tunnels

## Why reverse SSH

A managed Linux device may be behind NAT or CGNAT and therefore cannot accept
an Internet-initiated SSH connection. The device instead opens an outbound SSH
connection to the public gateway and requests a reverse TCP forward.

Example for a device assigned port 10001:

```text
device:sshd :22
     ^
     | forwarded TCP inside the device->gateway SSH connection
     |
gateway 127.0.0.1:10001
```

The gateway can then reach the device's SSH daemon through
`127.0.0.1:10001`. The forwarded port must remain bound to loopback; it is
not intended to be an Internet-facing SSH port.

## Is this "SSH inside SSH"?

There are two SSH authentication contexts, but the second connection is not a
new Internet path.

1. **Tunnel session, device -> gateway.** The device authenticates to the
   gateway with a device-specific tunnel key. This session exists to maintain
   the reverse TCP forward.
2. **Management session, gateway -> device.** The gateway connects to
   `127.0.0.1:<assigned-port>`. Those TCP bytes travel through the existing
   tunnel and arrive at the device's sshd on port 22. The gateway then
   authenticates to that sshd with a separate management key.

So an interactive shell is possible:

```text
gateway$ ssh -p 10001 -i <device-management-key> ai-gateway@127.0.0.1
ai-gateway@device$
```

For MCP operation, an interactive prompt is usually unnecessary. The gateway
can execute a bounded command and collect stdout, stderr and exit status.

## Identity separation

Human/platform users are application identities, not Linux accounts on the
gateway. A user such as Alice may be authorized for devices A and B while Bob
may only access B. That authorization belongs in the application layer.

SSH identities have different purposes:

- gateway administrator identity: administers the cloud VM;
- per-device tunnel identity: device authenticates to gateway;
- per-device management identity: gateway authenticates to target sshd.

A prototype may use one locked-down Unix account named `tunnel` as the
landing account for reverse tunnels while retaining a unique public key per
device. Human users do not log into this account.

## Tunnel account restrictions

The tunnel landing account should have no useful shell and no general-purpose
SSH capabilities. Each device key should be restricted in
`authorized_keys` to the minimum forwarding capability and its assigned
listen endpoint. Exact OpenSSH options must be validated on the deployed
server before automation because supported restrictions depend on the server
version/configuration.

The intended invariant is:

```text
device key A -> may create only its assigned loopback reverse forward
device key B -> may create only its assigned loopback reverse forward
```

Never expose reverse-forward ports on `0.0.0.0`.

## Persistence

The device-side tunnel is managed by systemd with SSH keepalives and
`ExitOnForwardFailure=yes`. A sample unit is in
`deploy/device/reverse-tunnel.service`.

The initial prototype can use fixed, registry-assigned ports (for example
10001, 10002, ...). Dynamic allocation can be added later if scale warrants
it.
