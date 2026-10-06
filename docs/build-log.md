# Build Log

Chronological record of the prototype environment and significant setup actions.

## 2026-10-03 — Initial cloud gateway

Created the first gateway instance:

- hostname: `ai-lab-gateway-01`
- platform: Oracle Cloud Infrastructure
- region: Brazil Southeast (Vinhedo)
- OS: Canonical Ubuntu 24.04 Minimal
- reported release after boot: Ubuntu 24.04.5 LTS
- architecture: x86_64
- kernel at first login: `6.17.0-1020-oracle`
- memory observed: 954 MiB
- root filesystem: 45 GiB, about 1.1 GiB used at first inspection
- swap: none

### Networking

A VCN and subnet were created during instance provisioning. The instance initially had only its private IPv4 address.

The VCN already had an Internet Gateway and appropriate route table. OCI's quick action was used to create/attach a Network Security Group and configure Internet connectivity. An ephemeral public IPv4 was then assigned to the primary private IP.

Administrative SSH connectivity from the Internet was successfully established on TCP 22.

### SSH administration

OCI-generated private key was stored locally by the administrator. Windows OpenSSH initially rejected the key because its ACL allowed another local group to read it. The ACL was restricted to the administrator account, after which public-key SSH login as `ubuntu` succeeded.

Private keys and other credentials must never be committed to this repository.

### Base system

Initial validation commands:

```text
uname -a
free -h
df -h /
```

confirmed x86_64 architecture, roughly 1 GiB RAM and a 45 GiB root volume.

The base Ubuntu package indexes and installed packages were then updated with `apt update` and `apt upgrade`.

## 2026-10-03 — Local MCP milestone validated

The first Python MCP service was validated end-to-end on the OCI gateway VM.

Environment:
- Ubuntu 24.04 LTS, x86_64
- Python 3.12.3
- MCP Python SDK 2.3.0
- MCP transport: Streamable HTTP
- Local endpoint: `http://127.0.0.1:8000/mcp`

Validation:
- MCP server started successfully under Uvicorn.
- A separate MCP client session initialized successfully.
- `tools/list` discovered `gateway_status`.
- `tools/call` executed `gateway_status` successfully.
- The response returned structured content with `status: ok`, hostname `ai-lab-gateway-01`, Python 3.12.3, and x86_64 architecture.
- No device-control or SSH execution tools are exposed yet.

Implementation note:
- The initial skeleton used the MCP 1.x `FastMCP` API. Since the installed SDK is MCP 2.3.0, it was migrated to `MCPServer` and the project dependency was constrained to `mcp>=2,<3`.

## 2026-10-03 — Public HTTPS MCP milestone validated

The gateway was published at `gateway.debasti.com` with Cloudflare DNS in DNS-only mode. Caddy terminates public TLS on TCP 443 and reverse-proxies to the MCP service on `127.0.0.1:8000`; port 8000 remains private to the VM.

During TLS bring-up, OCI network rules alone were not sufficient: the Ubuntu image's INPUT chain contained a final reject rule with only SSH allowed ahead of it. TCP 80 and 443 were inserted before that reject rule.

The first public MCP attempt reached the application but returned HTTP 421 because MCP transport security rejected the public Host header. `gateway.debasti.com` was then explicitly added to `TransportSecuritySettings.allowed_hosts`.

Final public validation succeeded against:

```text
https://gateway.debasti.com/mcp
```

The external MCP client:
- completed MCP initialization over public HTTPS;
- discovered `gateway_status` with `tools/list`;
- called `gateway_status` successfully;
- received structured `status: ok` from `ai-lab-gateway-01`.

This validates the path:

```text
MCP client -> Internet -> TLS/Caddy -> localhost MCP server -> tool call
```

Security observation: Internet scanners began reaching the public web endpoint shortly after TCP 80/443 were opened. Device-control tools must not be exposed before authentication/authorization is in place.

## 2026-10-05 — Gateway hardening and production service

The repository-side implementation was validated on the OCI VM with Python
3.12.3, MCP SDK 2.3.0 and pytest 8.4.2. All 16 tests passed.

The MCP application was installed under `/opt/ai-lab-gateway` with a production
virtualenv and runs as the dedicated `ai-lab-gateway` system user. The
`ai-lab-gateway.service` unit is enabled and active. The application listens
only on `127.0.0.1:8000`, with Caddy providing the public HTTPS boundary.

The public MCP path was revalidated with a protocol client: initialization,
`tools/list`, and `gateway_status` all succeeded through public HTTPS.

### Firewall persistence

The intended live INPUT policy was reduced to established traffic, required
ICMP/loopback, SSH, HTTP, HTTPS, followed by reject. TCP 80/443 were also added
to `/etc/iptables/rules.v4` so they survive reboot.

The OCI image configures `netfilter-persistent` with
`IPTABLES_RESTORE_NOFLUSH=yes` and the IPv6 equivalent. A manual
`netfilter-persistent reload` therefore duplicated rules in the live chain
instead of replacing it. The duplicates were removed and the live chain was
verified clean. Do not use routine reloads as if they were flush-and-replace;
the persisted rules should be validated at the next planned reboot.

### rpcbind

`rpcbind` was listening globally on TCP/UDP 111, but `rpcinfo` showed no
dependent RPC services. Both `rpcbind.service` and `rpcbind.socket` were
disabled/stopped. Port 111 was verified to have no remaining listeners.

## 2026-10-05 — First managed Linux device validated

The first target, `raspberry-lab`, is an ARM64 Ubuntu 24.04 Linux system. A
dedicated non-root `ai-gateway` account was created on the target without sudo
privileges.

Two independent ED25519 credential roles were created:

- a device-held tunnel identity authenticates the target to the gateway's
  `tunnel` account;
- a gateway-held management identity authenticates the gateway to the target's
  `ai-gateway` account.

Private keys remain on their respective originating side and were not copied
into the repository.

### Gateway tunnel account

A dedicated `tunnel` account was created with `/usr/sbin/nologin`. The
effective OpenSSH Match policy was validated before reloading sshd:

```text
PubkeyAuthentication yes
PasswordAuthentication no
X11Forwarding no
PermitTTY no
GatewayPorts no
AllowTcpForwarding remote
AllowAgentForwarding no
```

The first device's public key is further constrained with
`permitlisten="127.0.0.1:10001"` plus no-agent-forwarding, no-X11-forwarding,
no-pty and no-user-rc key options.

### Host identity and reverse forwarding

Before the first device trusted the gateway, the ED25519 fingerprint presented
over the network was compared with the gateway's own host public key. The
management direction was similarly checked by comparing the target's host-key
fingerprint with the key learned through the reverse tunnel.

The target successfully created:

```text
gateway 127.0.0.1:10001 -> reverse SSH tunnel -> target 127.0.0.1:22
```

The listener was verified to bind only to gateway loopback. From the gateway,
SSH through port 10001 authenticated with the separate management key and
executed commands as the target's non-root `ai-gateway` account.

### Persistence and failure recovery

After manual validation, the target tunnel was installed as
`ai-lab-reverse-tunnel.service`, enabled at boot, and configured with strict
host-key checking, SSH keepalives, `ExitOnForwardFailure=yes`, and automatic
restart.

The tunnel SSH process was deliberately killed. systemd scheduled a restart,
created a new SSH process, the reverse listener reappeared, and a subsequent
gateway-to-target command returned successfully. This validates automatic
recovery from a tunnel-process failure without operator intervention.

### Safety state after the milestone

The live transport path can now reach the first target, but it is not exposed
as a public MCP control tool. The public MCP server remains status-only until
OAuth identity verification and deny-by-default application authorization are
enforced end-to-end.

### Final tunnel-account hardening

The gateway-side `tunnel` Match policy was tightened and validated with the
live device. Its effective policy now includes public-key-only authentication,
`AllowTcpForwarding remote`, `AllowStreamLocalForwarding no`, `PermitUserRC no`,
`PermitTunnel no`, and `MaxSessions 0`, in addition to the previously validated
no-password, no-keyboard-interactive, no-X11, no-agent-forwarding, no-TTY and
`GatewayPorts no` restrictions.

After reloading sshd, the target's systemd tunnel service was restarted so the
connection was established under the new policy. The legitimate reverse
listener reappeared only on `127.0.0.1:10001`, and gateway-to-target command
execution with the separate management identity still succeeded as non-root
`ai-gateway`.

Two negative tests then validated fail-closed behavior. Using the device tunnel
credential to request remote command execution failed with SSH exit status 255.
Using the same credential to request `127.0.0.1:10002` failed with remote port
forwarding denied because the key is constrained by `permitlisten` to port
10001. A final listener check showed 10001 active on loopback and no listener
on 10002.

### Real target reboot validation

The first target was then rebooted normally. On the next boot,
`ai-lab-reverse-tunnel.service` started automatically at 11:35:55 local time
without operator intervention. The service was enabled and active with a fresh
SSH process and the target was running the post-reboot kernel.

From the OCI gateway, the separate management identity successfully traversed
the automatically recreated listener on port 10001 and executed `id`,
`hostname`, and `uptime` on the target. The command returned the expected
non-root `ai-gateway` identity and target hostname. This validates the complete
reboot path: target boot -> systemd -> reverse SSH -> gateway loopback listener
-> management SSH -> target command execution.

### Final device acceptance tests

The explicit wrong-management-key test used a temporary ED25519 key that was
not authorized on the target. With the normal `ai-lab-gateway` host-trust
context preserved, the connection traversed port 10001 to the target sshd and
was rejected with `Permission denied`. The temporary key was then deleted.

The live SSH execution backend was also tested directly rather than only by a
unit test. `ssh_exec.execute()` sent `sleep 10` to `raspberry-lab` with a
2-second application timeout. The backend raised the expected `TimeoutError`
after 2.00 seconds. This completes all 11 acceptance checks in the device
bootstrap runbook for the first live device.

Remaining operational work includes OAuth/provider integration, application
wiring of the device registry/control plane, audit retention, and stable
public-IP/DNS planning.


## 2026-10-05 — Auth0 resource API created

Auth0 was selected as the prototype OAuth authorization server. A Development
tenant in the US region was created manually through the Auth0 dashboard.

A Custom API representing the MCP resource server was created:

```text
Name: AI Lab Gateway
Identifier / audience: https://gateway.debasti.com
JWT profile: Auth0
JWT signing algorithm: RS256
User-delegated application access: Per-app authorization
Client access: Per-app authorization
```

The Auth0 API Quickstart confirmed the expected audience
`https://gateway.debasti.com`. No Auth0 secrets or tokens were committed.

An Auth0 ChatGPT plugin was investigated as a possible administration path. In
the available session it provided Auth0 integration guidance/skills but did not
provide authenticated tenant Management API access, so tenant configuration
continued manually. This is an operational convenience limitation, not an
architecture change.

Next Auth0 work is to define the coarse Gateway API scopes, then configure the
OAuth client/login path and implement/validate cryptographic JWT verification
in the MCP request path.


### Auth0 scopes created

The Custom API Permissions tab was configured with exactly two coarse OAuth
permissions:

- `gateway:read` — `Read permitted devices and gateway status`
- `gateway:control` — `Execute permitted operations on authorized devices`

No Authorization Details Types were created. Fine-grained device/action
authorization remains the responsibility of the gateway's deny-by-default
policy; these OAuth scopes are intentionally coarse.


### Auth0 application-access nuance

The Auth0 Custom API's `Application Access -> Add Application` flow was
inspected and deliberately NOT used. In the current Auth0 UI this flow is
"Add an API as an application": it makes the resource API itself act as a
client of other APIs (for Token Vault / on-behalf-of scenarios) and explicitly
does not support interactive login/session management. It must not be used as
a stand-in for the ChatGPT OAuth client.

For the ChatGPT MCP integration, client discovery/registration must follow the
OAuth/MCP interoperability supported by the client and authorization server
(e.g. current metadata/CIMD or supported fallback), rather than inventing a
manual Auth0 application through that API-as-application flow.


### Google social-login smoke test

The built-in Auth0 `google-oauth2` social connection was tested with Auth0's
`Try Connection` flow. Interactive Google authentication completed
successfully and Auth0 returned a user profile, confirming the isolated path:

```text
browser -> Auth0 -> Google authentication -> Auth0 user identity
```

The connection was still using Auth0 development keys at this milestone. Those
keys are acceptable for prototype testing but are not the intended production
configuration. No Gmail, Drive, Calendar, Sheets, offline-access, Token Vault,
or other Google API scopes were enabled for the test; the connection purpose
remained Authentication.

The stable Auth0/Google subject returned by the test is sensitive account
metadata and is intentionally not recorded in this repository.


### Auth0 MCP client-discovery compatibility

Auth0 tenant settings were verified for MCP client interoperability:

- Resource Parameter Compatibility Profile: enabled (it was already enabled).
- Client ID Metadata Document (CIMD) Registration: enabled.
- Dynamic Client Registration (DCR): remains disabled.

This preserves the preferred CIMD path for compatible MCP clients while
avoiding the broader unauthenticated DCR surface. No secrets are involved in
these tenant feature flags.


### Production OAuth environment scaffold

The production VM was prepared for provider configuration without embedding
tenant values in the systemd unit:

- `/etc/ai-lab-gateway/` created as `root:ai-lab-gateway`, mode `0750`.
- `/etc/ai-lab-gateway/gateway.env` created as `root:ai-lab-gateway`, mode `0640`.
- systemd drop-in `10-environment.conf` adds
  `EnvironmentFile=/etc/ai-lab-gateway/gateway.env`.
- Public Auth0 resource-server settings (issuer, API audience and JWKS URL)
  were placed in the environment file. No client secret, access token, private
  key, or other credential is required or stored there.
- `systemctl daemon-reload` was performed, but the service was intentionally
  not restarted yet; the currently deployed server does not consume the OAuth
  settings.
- Existing production process remained active after this preparation.

Implementation note: current MCP Python SDK 2.x can enforce bearer
authentication and publish RFC 9728 protected-resource metadata directly using
`TokenVerifier` plus `AuthSettings`. JWT verification must still validate
Auth0 signature, issuer, audience, time constraints, and scopes. The public MCP
control surface must remain closed until these checks and deny-by-default
device authorization are tested.


### Auth0 JWT resource-server implementation

The gateway source now implements Auth0 RS256 access-token verification and
MCP SDK 2.x resource-server authentication. The verifier checks the JWKS
signature, issuer, API audience, required time claims and stable subject before
returning an MCP AccessToken. The HTTP MCP transport now requires
`gateway:read`; SSH/device-control tools remain unexposed.

PyJWT crypto support and unit tests were added for a valid RS256 token and
rejection of wrong audience, wrong issuer and expired tokens. Production has
not been restarted by these source changes; deployment remains an explicit
operator step after tests pass on the VM.


## 2026-10-05/06 — OAuth, stable v1 tools, and real ChatGPT control acceptance

This milestone completed the identity-to-execution path and exposed the stable
six-tool v1 surface through a real ChatGPT developer-mode app.

### Stable v1 MCP tool surface

The server now exposes:

```text
gateway_status
list_devices
device_status
exec
read_file
write_file
```

Scope mapping:

```text
gateway:read
  -> gateway_status
  -> list_devices
  -> device_status
  -> read_file

gateway:control
  -> exec
  -> write_file
```

The private deny-by-default policy independently maps the verified OAuth subject
to explicit per-device actions.

### Auth0 API and ChatGPT CIMD

A replacement Auth0 Custom API was created with the exact MCP resource
identifier:

```text
https://gateway.debasti.com/mcp
```

The earlier root-only API was retained temporarily as rollback state.

Auth0 tenant settings used for the successful flow:

- Resource Parameter Compatibility Profile: enabled;
- Client ID Metadata Document Registration: enabled;
- Dynamic Client Registration: intentionally disabled.

The ChatGPT client was imported from:

```text
https://chatgpt.com/oauth/client.json
```

Observed OAuth bring-up failures and fixes:

1. `Unknown client: https://chatgpt.com/oauth/client.json`
   - fixed by importing the ChatGPT CIMD application after enabling CIMD.
2. `Service not found: https://gateway.debasti.com/mcp`
   - fixed by making the Auth0 API identifier exactly match the MCP resource.
3. Google/social login reported no connection enabled for the third-party
   client.
   - fixed by making the Google connection available at the required
     domain/tenant level.

The Auth0 API permissions are:

- `gateway:read` — read permitted devices and gateway status;
- `gateway:control` — execute commands and modify files on permitted devices.

ChatGPT User-Delegated Access was ultimately configured for both permissions,
with **Always grant all permissions** enabled.

No real OAuth subject, token, secret or private policy entry is recorded in the
public repository.

### First live OAuth success

After the Auth0 audience and runtime configuration were corrected, ChatGPT
successfully called read-only device operations through the public MCP endpoint.

A live `device_status` call reached the first target and returned its real
hostname over the managed reverse SSH path.

### Control-scope failure revealed MCP SDK metadata coupling

The first real `exec("uname -a")` attempt failed inside the control plane with:

```text
PermissionError: missing OAuth scope(s): gateway:control
```

The MCP request itself returned HTTP 200 because the exception was represented
as a tool error.

Public RFC 9728 metadata at that time advertised only:

```text
gateway:read
```

Source inspection of MCP Python SDK 2.3.0 showed that the SDK uses
`AuthSettings.required_scopes` for both:

- global `RequireAuthMiddleware` enforcement;
- generated RFC 9728 `scopes_supported`.

Setting both read and control there would incorrectly require control for every
read-only request.

### Protected-resource metadata override

A repository-owned ASGI wrapper was added so the gateway can:

- keep global middleware at `gateway:read`;
- advertise both `gateway:read` and `gateway:control`;
- preserve the SDK bearer middleware and `WWW-Authenticate` behavior.

The public metadata was then validated:

```json
{
  "resource": "https://gateway.debasti.com/mcp",
  "scopes_supported": [
    "gateway:read",
    "gateway:control"
  ]
}
```

The unauthenticated endpoint was also validated to return 401 with:

```text
resource_metadata="https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp"
```

### Revoking Auth0 grant did not kill the old JWT immediately

The user's ChatGPT Authorized Application grant was revoked in Auth0, but a
previously issued JWT remained valid until its normal expiry and still carried
only `gateway:read`.

The gateway therefore gained optional
`AI_LAB_OAUTH_MIN_IAT=<unix timestamp>` support. After setting the cutoff and
restarting, the old token produced 401, proving the pre-cutoff token was
rejected.

This is an operational reauthorization epoch, not a replacement for provider
token lifetime or normal revocation.

### Why control step-up moved to the HTTP boundary

An in-tool scope exception is not enough for OAuth step-up because MCP returns
it inside HTTP 200.

A transport wrapper was therefore added for `tools/call` requests to
`exec` and `write_file`. When a valid token lacks
`gateway:control`, the gateway returns HTTP 403 with:

```text
error="insufficient_scope"
scope="gateway:control"
resource_metadata="..."
```

The control plane keeps its independent `gateway:control` check as
defense-in-depth.

### Protected-resource path bug found and fixed

The custom 403 challenge initially referenced the stale root-only metadata URL:

```text
https://gateway.debasti.com/.well-known/oauth-protected-resource
```

while the resource is `https://gateway.debasti.com/mcp`.

The correct URL is:

```text
https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp
```

The application now derives the metadata URL from the configured audience
instead of hard-coding the root path. A regression test covers this case.

### ChatGPT developer-mode app snapshot behavior

Multiple development apps were created during the integration sequence.

Empirical behavior:

- an older app did not automatically acquire MCP tools added after it was
  created;
- a later app created after the six v1 tools were deployed discovered all six;
- that app remained stuck in the earlier read-only OAuth discovery behavior
  despite repeated reconnect attempts and server corrections;
- the reconnect modal recognized 403/401 flows but did not reliably replace the
  old app's authorization/discovery state;
- a fresh developer-mode app created only after all metadata/scope fixes were
  live immediately passed control authorization.

Operational conclusion: after material tool-catalog or OAuth-discovery changes,
reconnect first, but create one new developer-mode app if the old one behaves
like a stale snapshot. Remove obsolete apps only after the replacement passes.

### Final ChatGPT end-to-end acceptance

The fresh post-fix developer-mode app successfully executed:

```text
list_devices()
device_status("raspberry-lab")
exec("raspberry-lab", "uname -a")
```

The `uname -a` response came from the real ARM64 target over:

```text
ChatGPT
 -> Auth0
 -> MCP/HTTPS
 -> OAuth scope
 -> private authorization policy
 -> gateway management SSH
 -> reverse SSH tunnel
 -> non-root target
```

A file-operation round trip then succeeded:

1. `write_file` wrote a temporary UTF-8 text file under `/tmp`;
2. `read_file` returned the exact content;
3. `exec("rm -f ...")` removed the temporary file with exit code 0.

This validated all six v1 tools through the real production client path.

### Test progression

The repository test suite progressed during this work:

```text
23 passing
25 passing after metadata override coverage
27 passing after token issuance cutoff coverage
30 passing after scope-step-up coverage
31 passing after resource-metadata path derivation coverage
```

A subsequent repository update extended audit metadata to file read/write
attempts as well.

### Documentation rule established

The OAuth integration produced enough product- and SDK-specific learning that
it must not live only in conversational history.

The detailed reconstruction and troubleshooting source of truth is now:

```text
docs/chatgpt-auth0-oauth-runbook.md
```

Future rebuilds should follow that runbook before creating a ChatGPT
developer-mode app.


## 2026-10-06 — Live audit coverage validated after final v1 deployment

After deploying the repository changes that added audit coverage to remote file
operations, the production service was restarted and the known-good ChatGPT
developer-mode app executed a final live sequence against the registered target:

```text
device_status
write_file
read_file
exec (temporary-file cleanup)
```

The private production JSONL audit log recorded all four actions successfully:

```text
status
write_file
read_file
exec
```

Each event contained the expected metadata fields (timestamp, authenticated
subject, device ID, action, success, duration, exit code) while omitting command
text, file contents, stdout and stderr.

This closes the v1 audit acceptance gap. The real OAuth subject remains private
runtime data and is intentionally not copied into the public repository.


## 2026-10-06 — Final v1 audit validation and stale app cleanup

After the final deployment, the known-good ChatGPT developer-mode app exercised
`device_status`, `write_file`, `read_file`, and `exec` against the live
target. The private production JSONL audit log recorded all four action classes
successfully with timestamp, authenticated subject, device ID, action, result,
duration, and exit code, while omitting command text, file contents, stdout, and
stderr.

Obsolete ChatGPT developer-mode snapshots were then cleaned up. Apps 03, 04,
and 05 were uninstalled; 01 and 02 were already absent. The known-good app 06
was intentionally retained because it was the first app created after the final
OAuth metadata/scope corrections and had passed the complete v1 acceptance.


## 2026-10-06 — Auth0 rollback API removed

After AI Lab Gateway 06 passed the complete v1 acceptance and the stale
developer-mode apps were removed, the obsolete Auth0 API whose identifier was
the root URL without `/mcp` was deleted.

The remaining canonical Auth0 API/resource identifier is:

```text
https://gateway.debasti.com/mcp
```

A post-cleanup live check through the known-good ChatGPT app still succeeded for
both device discovery and a real control command, confirming that removal of
the old rollback API did not affect the active OAuth/MCP path.


## 2026-10-06 — Temporary OAuth token cutoff removed after acceptance

The temporary production `AI_LAB_OAUTH_MIN_IAT` value used during OAuth
reauthorization testing was removed from the private runtime environment after
the known-good ChatGPT app and canonical Auth0 API had passed acceptance.

The feature remains implemented in the codebase as an operational tool for
future forced-reauthorization events, but it is no longer active in the normal
production runtime.

After restarting the gateway without the cutoff, the known-good ChatGPT app
successfully completed both a live `device_status` call and a real
`exec("uname -m")` control call against the registered target. This confirms
normal JWT expiry/validation behavior is sufficient for the steady state.
