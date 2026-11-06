# Optional WireGuard SSH transport (on demand)

**Status:** validated experimental transport, 2026-11-06. Opt-in feature; not
a replacement for reverse SSH, secure enrollment or device authorization.

## Why it exists

The normal AI Lab Gateway transport is a device-initiated reverse SSH tunnel.
For an enrolled Linux target whose outbound reverse SSH transport is unsuitable,
a standard WireGuard VPN can instead carry an ordinary gateway-to-device SSH
connection. The MCP server still sees a loopback SSH endpoint:

```text
Authenticated AI client -> OAuth / MCP policy and audit -> device registry
    -> gateway 127.0.0.1:<unique-port> [systemd socket]
    -> non-root systemd-socket-proxyd -> WireGuard IP <target>:22
    -> target sshd, management SSH key, non-root ai-gateway account
```

No new MCP endpoint, direct device public SSH port, or non-loopback registry
entry is required. The existing authorization and management SSH identity stay
unchanged. This is a **transport adaptation**, not device onboarding.

## Default lifecycle: VPN OFF on device

Device administrators must explicitly choose when the AI Lab can reach them.
On the device, `wg-quick@wg0` is **disabled at boot**. Start it only for an
authorized session, and stop it when done:

```bash
# Initial setup / verify that it will NOT autostart:
sudo systemctl disable wg-quick@wg0
systemctl is-enabled wg-quick@wg0  # should say disabled

# Make the device available on the VPN, without changing boot policy:
sudo systemctl start wg-quick@wg0
systemctl is-active wg-quick@wg0
sudo wg show
ping -c 3 10.77.0.1

# At the end of the session, close the VPN:
sudo systemctl stop wg-quick@wg0
systemctl is-active wg-quick@wg0  # should say inactive
systemctl is-enabled wg-quick@wg0 # should still say disabled
```

**Do not** run `systemctl enable` or configure `Restart=always` for the
client-side WireGuard service when on-demand mode is intended. When the client
is offline the gateway cannot bring it back through this path; the local
administrator must start the VPN. An enabled gateway-side socket is not
equivalent to a persistent device-side connection.

These actions require a permitted local administrator, not permanent target
sudo for `ai-gateway`.

## Provisioning prerequisites (operator-reviewed)

1. Confirm the target is authorized to use the network and that outbound UDP
   to the gateway port (example: 51820) is permitted. Do not bypass corporate
   firewall or VPN restrictions.
2. Install `wireguard-tools` and create a distinct WireGuard keypair on the
   target, protected under `/etc/wireguard` with mode 0600. Only the public
   key crosses machines; never put the private key in Git or conversation logs.
3. Register that peer public key on the gateway server with a single /32
   `AllowedIPs` entry (example: `10.77.0.4/32`). Save the change to the
   root-owned server configuration **and** update the live `wg` peer. Check
   for existing assignments before making changes. Avoid global firewall
   reloads, restarting the MCP, or disrupting existing peers.
4. Configure the target's `/etc/wireguard/wg0.conf`, mode 0600, e.g.:

```ini
[Interface]
Address = 10.77.0.4/32
MTU = 1280
PrivateKey = <generated-and-stored-locally-on-target>

[Peer]
PublicKey = <gateway-WireGuard-public-key>
Endpoint = vpn.example.net:51820
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
```

These are **examples only**, not complete key material or a provisioning
script. The client `AllowedIPs` is limited to the gateway's VPN /32, so the
VPN does not become the default internet route or a gateway to other peers.
Leave IP forwarding disabled unless a separately reviewed use case requires
it. Keep an existing corporate VPN and its routes untouched.

On the gateway the WireGuard interface is independently enabled so it can
receive authorized client connections. Restrict the public ingress rule to
UDP on its chosen listen port. A WireGuard handshake authenticates its peer,
but does not by itself grant MCP device access.

## Gateway relay: loopback-only, one per device

The registry enforces `tunnel_host=127.0.0.1` (or another loopback literal).
Keep this invariant. A per-device systemd socket takes the already assigned
port and forwards **only** to the peer's SSH server over WireGuard.

The repository contains a **renderer only**. It produces reviewable unit
drafts and performs **no installation or network changes**:

```bash
python3 scripts/render_wireguard_ssh_bridge.py \
  --device-id lab-node-03 \
  --listen-port 11002 \
  --peer-ip 10.77.0.4 \
  --vpn-subnet 10.77.0.0/24 \
  --output-dir /tmp/wg-lab-node-03
```

Inspect both generated files and verify: correct authorized peer address,
unique allocated port, `ListenStream=127.0.0.1:11002`, correct non-root
service user, no collisions with existing reverse tunnels, and an already
running WireGuard interface on the gateway. The generated service requires
`wg-quick@wg0.service`, but does not install, start, or enable WireGuard on
the remote device.

After an administrator has reviewed the generated units, install them on
the **gateway only**:

```bash
sudo install -o root -g root -m 0644 \
  /tmp/wg-lab-node-03/ai-lab-wg-lab-node-03.socket \
  /etc/systemd/system/ai-lab-wg-lab-node-03.socket
sudo install -o root -g root -m 0644 \
  /tmp/wg-lab-node-03/ai-lab-wg-lab-node-03.service \
  /etc/systemd/system/ai-lab-wg-lab-node-03.service
sudo systemd-analyze verify \
  /etc/systemd/system/ai-lab-wg-lab-node-03.socket \
  /etc/systemd/system/ai-lab-wg-lab-node-03.service
sudo systemctl daemon-reload
sudo systemctl enable --now ai-lab-wg-lab-node-03.socket
ss -lnt '( sport = :11002 )'
```

The socket is intended to stay available on **gateway loopback**. Its
systemd-activated proxy connects to the device over the VPN only when the MCP
uses it; an offline client is expected to fail closed. It cannot wake or
start a remote device VPN.

**Port ownership:** an existing reverse SSH listener and a WireGuard relay
socket cannot both own the same gateway loopback port. Choose one transport
per port, or allocate a different port in a separately reviewed registry
migration. Do not disable other devices' tunnels or modify their listeners.

## SSH authentication and host-key trust

Use the **existing per-device management SSH private key** stored privately
on the gateway and the non-root target `ai-gateway` account. It must be
explicitly authorized in the target's `authorized_keys`. A VPN public key
is not an SSH login credential.

The gateway's SSH client must have a previously verified target host key
for `[127.0.0.1]:<assigned-port>` in its dedicated `known_hosts`. If the
target has never been reached before, compare the key fingerprint through
an independent trusted channel before pinning it. Do **not** automatically
accept a new or changed host key or disable StrictHostKeyChecking to make
the connection work. A device still requires approved enrollment and
existing user/device/action authorization to be reachable by MCP.

## Validation checklist

- The device-side `wg-quick@wg0` is **disabled** (boot policy), even when
  temporarily active.
- A recent WireGuard handshake and bidirectional peer transfer exist.
- Device ping to gateway VPN address succeeds, with corporate default route
  unchanged.
- Gateway TCP connection to `<peer-ip>:22` succeeds and SSH host key
  matches the independently verified fingerprint.
- Gateway management SSH authenticates as non-root `ai-gateway`; on an
  authenticated SSH session, `SSH_CONNECTION` shows the VPN addresses.
- MCP `device_status` and a harmless `exec` succeed through the per-device
  localhost relay. The existing OAuth scopes, authorization and audit remain.
- Stop the device VPN: SSH and MCP device access fail closed, while other
  devices and the gateway MCP remain healthy.
- Restore access by a local administrator starting WireGuard again. Recheck
  peer handshake and device status.
- For rollback, stop/disable **only that device's gateway proxy socket** and
  service. Do not flush the gateway firewall or remove unrelated registry,
  OAuth, or SSH configuration.

## Live proof and important limitations

On 2026-11-06 an experimental Linux device completed WireGuard handshake,
4/4 ping to the gateway, TCP SSH negotiation, management-key authentication,
and MCP `device_status` / `exec` through a localhost systemd socket proxy.
The existing corporate VPN on that Linux and the gateway's other devices
remained operational. No MCP source patch was necessary.

The cloud interface initially selected MTU 8920 (cloud underlay 9000),
which caused large SSH key exchange packets to stall across the VPN.
Setting the gateway WireGuard MTU to **1280** fixed the default SSH handshake;
the same MTU is now configured persistently on the gateway. This is an
observed safe pilot value, not a universal performance optimum.

**Not yet implemented:** automatic secure WireGuard peer provisioning,
automatic VPN onboarding, an MCP transport selector, an MCP-controlled way to
start a disconnected remote VPN, and unattended deployment to unknown Linux
targets. Production code may have unmerged capabilities; reconcile before
any application deployment. These improvements require separate review.

See [ADR-030](decisions.md#adr-030--optional-on-demand-wireguard-ssh-transport)
and the existing [reverse SSH guide](device-tunnels.md).
