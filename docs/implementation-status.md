# Implementation status

## Current v1 state

AI Lab Gateway v1 has passed the complete live ChatGPT-to-device acceptance
path.

The validated request chain is:

```text
ChatGPT developer-mode app
  -> Auth0 OAuth
  -> public HTTPS MCP endpoint
  -> JWT verification
  -> OAuth scope enforcement
  -> deny-by-default subject/device/action authorization
  -> registered device lookup
  -> per-device management SSH key
  -> gateway loopback reverse-SSH listener
  -> non-root Linux target
```

## Validated on the live gateway

### Public gateway and service boundary

- Public DNS for `gateway.debasti.com`.
- TLS termination with Caddy.
- Reverse proxy to MCP on `127.0.0.1:8000`; TCP 8000 is not public.
- MCP Streamable HTTP initialization.
- `tools/list`.
- Production MCP service installed under systemd as the non-root
  `ai-lab-gateway` account and enabled at boot.
- Host firewall permits the intended public services and persists TCP 80/443
  rules; the OCI no-flush iptables restore behavior is documented.
- Unused `rpcbind` service/socket disabled; TCP/UDP 111 no longer listen.

### Managed-device transport

- Restricted `tunnel` landing account created on the gateway.
- First Linux target enrolled as `raspberry-lab`.
- Reverse SSH listener validated on gateway loopback at
  `127.0.0.1:10001`.
- Separate per-device tunnel and management SSH identities validated
  end-to-end.
- SSH host identities verified in both directions before trust was recorded.
- Device reverse tunnel installed as an enabled systemd service with
  keepalives, `ExitOnForwardFailure=yes`, and automatic restart.
- Forced tunnel-process failure and automatic reconnect validated.
- Gateway-to-device command execution validated through the reverse tunnel as
  the non-root `ai-gateway` target account.
- Final tunnel-account hardening validated: public-key-only authentication,
  remote forwarding only, no session channels, no stream-local forwarding, no
  user RC, no TUN/TAP forwarding, no agent/X11/TTY.
- Negative tests validated fail-closed behavior:
  - tunnel credential could not execute a remote command;
  - tunnel credential could not allocate an unauthorized reverse listener;
  - wrong management key reached the target sshd but was rejected.
- Real target reboot validated: systemd recreated the reverse tunnel
  automatically and management SSH succeeded afterward.
- Application-level execution timeout validated with a remote sleep exceeding
  the configured timeout.

### OAuth/Auth0 integration

- Auth0 selected and configured as the authorization server.
- Canonical OAuth resource/audience:
  `https://gateway.debasti.com/mcp`.
- RFC 9728 protected-resource metadata is publicly served at:
  `https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp`.
- Public metadata advertises both:
  - `gateway:read`;
  - `gateway:control`.
- Missing/invalid credentials receive HTTP 401 with a
  `WWW-Authenticate` challenge pointing to the correct resource metadata.
- Auth0 RS256 tokens are validated for signature, issuer, audience, time claims,
  subject and scopes.
- Auth0 Resource Parameter Compatibility Profile enabled for the MCP resource
  parameter.
- ChatGPT CIMD client imported from
  `https://chatgpt.com/oauth/client.json`.
- DCR intentionally left disabled for the validated setup.
- Google social authentication validated after making the connection available
  at the required domain/tenant level for the third-party CIMD application.
- Auth0 User-Delegated Access for ChatGPT grants both v1 permissions.
- Optional token issuance cutoff `AI_LAB_OAUTH_MIN_IAT` implemented and tested
  to force pre-cutoff JWTs to reauthorize.

### MCP SDK/Auth scope behavior

- MCP Python SDK 2.3 global-scope/metadata coupling was identified and handled
  without modifying `site-packages`.
- Global MCP middleware requires only `gateway:read`.
- Repository-owned protected-resource metadata override advertises both read and
  control as supported scopes.
- Transport-level scope step-up for `exec` and `write_file` returns HTTP 403
  `insufficient_scope` with `scope="gateway:control"` when necessary.
- Control plane independently checks the same required scope before SSH
  execution.

### ChatGPT developer-mode acceptance

Empirical product behavior showed that old developer-mode apps can retain stale
tool or OAuth discovery state. A fresh app created after the corrected v1
server state was live passed the full acceptance sequence.

Validated through the real ChatGPT integration:

1. `gateway_status`;
2. `list_devices`;
3. `device_status("raspberry-lab")`;
4. `exec("raspberry-lab", "uname -a")`;
5. `write_file` to a temporary target path;
6. `read_file` returning exactly the written content;
7. cleanup through `exec`.

The successful control command returned the live target's ARM64 Linux
`uname -a` output. The file round trip returned the exact test content and
cleanup exited successfully.

## Repository test state

The repository reached 31 passing unit tests after adding:

- Auth0 token cryptographic verification;
- metadata-path derivation tests;
- token issuance cutoff tests;
- protected-resource metadata override tests;
- transport-level scope-step-up tests;
- v1 control/file authorization tests.

Subsequent repository changes also extended audit coverage to remote file read
and write operations; run the full test suite before each deployment.

## v1 public MCP surface

The stable v1 tool surface is:

| Tool | Scope | Device policy |
| --- | --- | --- |
| `gateway_status` | `gateway:read` global boundary | authenticated gateway status |
| `list_devices` | `gateway:read` | visible if any device grant exists |
| `device_status` | `gateway:read` | `status` |
| `exec` | `gateway:control` | `exec` |
| `read_file` | `gateway:read` | `read_file` |
| `write_file` | `gateway:control` | `write_file` |

## Audit state

The repository appends JSONL audit metadata for remote:

- device status;
- command execution;
- file read;
- file write.

Default audit events intentionally exclude command text, file contents, stdout
and stderr.

Audit retention/rotation remains an operational decision.

## Known v1 limitations

- `write_file` is intended for small UTF-8 text. It base64-encodes content into
  a remote shell command; large/binary transfer needs a dedicated mechanism.
- Device registry and authorization policy remain JSON prototype files.
- The target account is non-root by default; narrow sudo policy has not yet been
  designed for privileged hardware/service operations.
- Audit log storage is append-only JSONL; rotation/retention is not finalized.
- The reference cloud public IP is still an operational concern unless reserved
  or DNS updates are automated.
- ChatGPT developer-mode app refresh behavior is product-specific and must be
  revalidated after major product changes.

## Remaining work after v1 acceptance

- deploy and validate any repository changes made after the last live
  acceptance before relying on them in production;
- verify live audit records for all four remote action classes;
- remove obsolete ChatGPT developer-mode test apps only after the known-good app
  remains stable;
- retire the old Auth0 API/audience after the rollback window;
- replace Auth0 development Google credentials with owned credentials for a
  long-lived production deployment;
- define audit rotation/retention;
- define narrow sudo policy only for concrete target use cases;
- consider database-backed registry/authorization when scale justifies it;
- add a deterministic deployment helper to reduce repeated manual rsync/pip
  steps.

## Reference documentation

For reconstruction and troubleshooting, read:

- `docs/recovery.md`;
- `docs/authentication.md`;
- `docs/chatgpt-auth0-oauth-runbook.md`;
- `docs/deployment.md`;
- `docs/build-log.md`;
- `docs/decisions.md`.
