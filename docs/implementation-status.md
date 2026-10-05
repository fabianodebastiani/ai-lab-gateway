# Implementation status

## Validated on the live gateway

- Public DNS for `gateway.debasti.com`.
- TLS termination with Caddy.
- Reverse proxy to MCP on `127.0.0.1:8000`; TCP 8000 is not public.
- MCP Streamable HTTP initialization.
- `tools/list`.
- `gateway_status` tool invocation over public HTTPS.
- Full repository unit test suite: 16 tests passed on the OCI gateway.
- Production MCP service installed under systemd as the non-root
  `ai-lab-gateway` account and enabled at boot.
- Host firewall permits the intended public services and persists TCP 80/443
  rules in `/etc/iptables/rules.v4`; OCI's no-flush restore behavior is
  documented in the build log.
- Unused `rpcbind` service/socket disabled; TCP/UDP 111 no longer listen.
- Restricted `tunnel` landing account created on the gateway.
- First Linux target enrolled as `raspberry-lab`.
- Reverse SSH listener validated on gateway loopback at
  `127.0.0.1:10001`.
- Separate per-device tunnel and management SSH identities validated
  end-to-end.
- SSH host identities verified in both directions before/after trust was
  recorded.
- Device reverse tunnel installed as an enabled systemd service with
  keepalives and automatic restart.
- Forced tunnel-process failure and automatic reconnect validated; management
  SSH succeeded again after the tunnel was rebuilt.
- Gateway-to-device command execution validated through the reverse tunnel as
  the non-root `ai-gateway` target account.
- Final gateway-side tunnel-account hardening validated live: public-key-only
  authentication, no session channels (`MaxSessions 0`), no stream-local
  forwarding, no user RC, and no TUN/TAP forwarding.
- Negative tests validated fail-closed behavior: the tunnel credential could
  not execute a remote command (SSH exit 255) and could not allocate an
  unauthorized reverse listener on port 10002; the legitimate loopback-only
  listener on `127.0.0.1:10001` remained active.
- Real target reboot validated: the enabled reverse-tunnel service started
  automatically during boot, recreated the gateway listener, and management
  SSH from the OCI gateway again executed successfully on the target without
  operator intervention.

## Implemented in repository; application integration still pending

- device registry with loopback-only tunnel validation;
- deny-by-default subject/device/action authorization;
- OAuth resource-server configuration primitives;
- protected-resource metadata model;
- OAuth scope/subject normalization;
- control-plane orchestration;
- SSH command backend with bounded timeout and strict host-key checking;
- append-only audit metadata;
- gateway systemd unit;
- device reverse-tunnel systemd template;
- device enrollment/bootstrap helper;
- unit tests for registry, authorization, OAuth helpers, audit, control plane
  and SSH invocation.

The first device tunnel is live, but the deployed MCP server remains
status-only. The repository control-plane modules have not yet been wired into
public MCP tools.

## Deliberately not enabled

- public MCP `exec` or file-write tools;
- OAuth token cryptographic verification before a provider is selected;
- automatic sudo grants on targets;
- public binding of reverse-forward ports.

## Remaining work

- configure the chosen OAuth provider and cryptographic token verifier;
- publish protected-resource metadata/challenges in the live service;
- connect the live device registry/authorization/control plane to MCP;
- define narrow sudo policy only where a managed-device use case requires it;
- choose audit-log storage/retention;
- validate real ChatGPT product connection after OAuth is complete;
- consider reserving the gateway public IP or automating DNS updates.

## Safety gate

The repository may contain the machinery for remote execution before deployment,
but the public server remains status-only until authenticated identity and
authorization are enforced end-to-end.
