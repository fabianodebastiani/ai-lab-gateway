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

The prototype uses one locked-down Unix account named `tunnel` as the
gateway landing account for reverse tunnels while retaining a unique public key
per device. Human users do not log into this account.

## Validated tunnel-account restrictions

The live gateway runs OpenSSH 9.6. The `tunnel` account has been validated
with these effective restrictions:

```text
PasswordAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding remote
GatewayPorts no
X11Forwarding no
AllowAgentForwarding no
PermitTTY no
```

The account uses `/usr/sbin/nologin` as its shell.

Each device key is additionally constrained in `authorized_keys`. The first
device, `raspberry-lab`, is limited to its assigned listener with:

```text
permitlisten="127.0.0.1:10001",no-agent-forwarding,no-X11-forwarding,no-pty,no-user-rc
```

followed by that device's public key. Do not store the actual key material in
this repository.

This establishes the prototype invariant:

```text
device key A -> may create only its assigned loopback reverse forward
device key B -> may create only its assigned loopback reverse forward
```

Never expose reverse-forward ports on `0.0.0.0`.

A final defense-in-depth review is still planned for restrictions such as
session creation and stream-local forwarding. Any additional restriction must
be tested against a live `ssh -N` reverse tunnel before rollout.

## Management identity

The gateway stores a distinct private management key for each target under
runtime state owned by the `ai-lab-gateway` service account. Only the public
half is installed in the target account's `authorized_keys`.

The first target uses a non-root `ai-gateway` account. It has no sudo grant by
default. The gateway connects to the target through the assigned loopback port
with `IdentitiesOnly=yes` and `StrictHostKeyChecking=yes`.

## Host-key verification

The first enrollment verified the gateway's ED25519 host-key fingerprint on
the gateway itself before the device trusted it. In the reverse direction, the
target's ED25519 host-key fingerprint was compared with the key learned by the
gateway through the reverse tunnel.

Production operation uses `StrictHostKeyChecking=yes`. Initial trust must
therefore be established deliberately during enrollment rather than with a
permanent `accept-new` policy.

## Persistence and reconnect

The device-side tunnel is managed by systemd with:

- `ExitOnForwardFailure=yes`;
- `ServerAliveInterval=30`;
- `ServerAliveCountMax=3`;
- `Restart=always`;
- `RestartSec=5`;
- `StrictHostKeyChecking=yes`.

A sample unit is in `deploy/device/reverse-tunnel.service`.

For `raspberry-lab`, the manually validated tunnel was replaced by the
systemd-managed service and enabled at boot. The SSH process was then
deliberately killed. systemd started a new process, the device recreated the
reverse listener, and gateway-to-device SSH command execution succeeded again
without manual intervention.

The initial prototype uses fixed, registry-assigned ports (10001, 10002, ...).
Dynamic allocation can be added later if scale warrants it.
