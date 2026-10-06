# ChatGPT + Auth0 + MCP OAuth runbook

## Purpose

This runbook records the complete OAuth/MCP integration path that was validated
for AI Lab Gateway in October 2026. It exists so a future operator or AI does
not have to rediscover the same Auth0, MCP SDK, ChatGPT developer-mode, token
lifecycle, and scope-step-up behavior from scratch.

This document intentionally contains no real user subject, access token, private
key, client secret, or other private runtime value.

The validated end-to-end path is:

```text
ChatGPT
  -> OAuth authorization through Auth0
  -> HTTPS / MCP
  -> gateway token verification
  -> OAuth scope check
  -> deny-by-default subject/device/action policy
  -> per-device management SSH key
  -> reverse SSH listener on gateway loopback
  -> non-root Linux target
```

The first complete live acceptance reached a registered Raspberry Pi-class
target and validated all six v1 MCP tools, including real command execution and
remote file write/read.

## Canonical public values

The reference deployment uses:

```text
MCP endpoint / OAuth resource:
https://gateway.debasti.com/mcp

RFC 9728 protected-resource metadata:
https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp
```

The `/mcp` suffix in the resource identifier matters. RFC 9728 metadata for a
resource with a path is published at
`/.well-known/oauth-protected-resource/<resource-path>`; therefore the
correct metadata path ends in `/mcp`.

Do not use the older root-only path
`https://gateway.debasti.com/.well-known/oauth-protected-resource` for this
resource.

## OAuth scope model

The v1 scope model is deliberately coarse:

- `gateway:read` — discover permitted devices, read gateway/device status,
  and read permitted files.
- `gateway:control` — execute commands and modify permitted files.

OAuth scope is never sufficient by itself. A request must also pass the
gateway's private deny-by-default authorization policy:

```text
valid OAuth identity
AND required OAuth scope
AND subject -> device/action grant
AND enabled device registry entry
AND valid per-device management SSH credential
```

The global MCP authentication boundary requires `gateway:read`. Privileged
tools additionally require `gateway:control`.

The v1 tool mapping is:

| Tool | Required OAuth scope | Private policy action |
| --- | --- | --- |
| `gateway_status` | `gateway:read` via global MCP boundary | none beyond authenticated MCP boundary |
| `list_devices` | `gateway:read` | any visible device grant |
| `device_status` | `gateway:read` | `status` |
| `read_file` | `gateway:read` | `read_file` |
| `exec` | `gateway:control` | `exec` |
| `write_file` | `gateway:control` | `write_file` |

## Auth0 tenant settings required for ChatGPT MCP

The reference tenant is a Development tenant. The exact tenant hostname belongs
in private runtime configuration, not in this public runbook.

Under **Tenant Settings -> Advanced**:

1. Enable **Resource Parameter Compatibility Profile**.
2. Enable **Client ID Metadata Document (CIMD) Registration**.
3. Keep **Dynamic Client Registration (DCR)** disabled unless there is a
   deliberate reason to use it.

The Resource Parameter Compatibility Profile is important because MCP clients
identify the target resource using the OAuth `resource` parameter. The
resource must resolve to the same API identifier/audience used by the gateway.

CIMD is preferred for the ChatGPT developer-mode client because the ChatGPT
client metadata is published at a stable URL and Auth0 can import it explicitly.
Do not enable DCR merely to work around an incomplete CIMD setup; DCR broadens
who can register clients in the tenant.

## Import the ChatGPT CIMD application

Auth0 must know the ChatGPT third-party client.

Use:

1. **Applications -> Applications -> Create Application**.
2. Choose **Import from URL**.
3. Import:

   ```text
   https://chatgpt.com/oauth/client.json
   ```

4. Preview and create the imported third-party application.

The imported application is expected to use ChatGPT's metadata document as its
external client identity and includes the callback used by the ChatGPT connector
platform.

Observed failure before this step:

```text
invalid_request: Unknown client: https://chatgpt.com/oauth/client.json
```

If that error returns after a rebuild, first verify CIMD registration is enabled
and that the metadata document has actually been imported. Enabling CIMD support
alone is not enough.

## Create the Auth0 resource API

Create a Custom API with:

```text
Name: AI Lab Gateway MCP
Identifier / audience: https://gateway.debasti.com/mcp
JWT profile: Auth0
Signing algorithm: RS256
User-delegated access: Per-app authorization
Client access: Per-app authorization
```

Add these permissions:

```text
gateway:read
Read permitted devices and gateway status

gateway:control
Execute commands and modify files on permitted devices
```

The API identifier must exactly match the MCP resource. An earlier API used the
root URL without `/mcp`; ChatGPT then discovered the `/mcp` resource and
Auth0 returned:

```text
access_denied: Service not found: https://gateway.debasti.com/mcp
```

The fix was to create the API using the exact MCP resource identifier. Keep an
old API only as a temporary rollback object; do not treat two different
audiences as interchangeable.

## Grant ChatGPT user-delegated access

In the API's **Application Access** view, edit the `ChatGPT` application under
**User-Delegated Access**.

For the validated v1 state:

- both `gateway:read` and `gateway:control` are granted;
- **Always grant all permissions** is enabled.

Important nuance: this setting allows the application to request all granted
permissions. It does not magically add a scope that a particular authorization
request did not ask for, and it does not retrofit old access tokens or old
ChatGPT developer-mode app snapshots.

Do not grant machine-to-machine Client Access merely for the interactive
ChatGPT user flow.

### Auth0 UI quirk observed

During one edit, the **Save** button did not become active after changing the
permission selection. Toggling **Always grant all permissions** on and back off
caused the UI to recognize the change, after which Save succeeded.

Treat this as a dashboard/UI quirk, not as an OAuth design requirement. Verify
the final displayed state after saving.

## Google social connection requirement

The human login used Google through Auth0.

A third-party CIMD application may require the social connection to be enabled
at the domain/tenant level rather than only for a conventional first-party app.
Before that was corrected, Auth0 returned a no-connections-enabled failure.

For a prototype, Auth0 development Google credentials can be sufficient. For a
long-lived production deployment, configure owned Google OAuth credentials and
document their rotation separately.

## Private gateway runtime configuration

The production environment file lives outside Git. The reference deployment
uses:

```text
AI_LAB_OAUTH_ISSUER=<Auth0 issuer URL, trailing slash preserved>
AI_LAB_OAUTH_AUDIENCE=https://gateway.debasti.com/mcp
AI_LAB_OAUTH_JWKS_URL=<Auth0 tenant>/.well-known/jwks.json
```

Optional values:

```text
AI_LAB_OAUTH_RESOURCE_METADATA_URL=...
AI_LAB_OAUTH_MIN_IAT=<Unix timestamp>
```

The application now derives the protected-resource metadata URL from the
audience when `AI_LAB_OAUTH_RESOURCE_METADATA_URL` is omitted. Prefer that
behavior unless a deployment has a specific reason to override the URL.

Never commit:

- the real Auth0 user `sub`;
- access/refresh tokens;
- private keys;
- client secrets;
- private authorization assignments;
- production environment files.

The real subject-to-device/action mapping belongs in the private runtime policy
under `/etc/ai-lab-gateway`.

## MCP Python SDK 2.3 scope coupling

A critical implementation detail was discovered in MCP Python SDK 2.3.0.

The SDK uses `AuthSettings.required_scopes` for two separate concepts:

1. scopes globally required by `RequireAuthMiddleware`; and
2. `scopes_supported` in generated RFC 9728 protected-resource metadata.

Those concepts are not equivalent for this gateway.

If the gateway set:

```python
required_scopes=["gateway:read", "gateway:control"]
```

the metadata would correctly advertise both scopes, but every read-only MCP
request would also require control permission. That violates least privilege.

If it set only:

```python
required_scopes=["gateway:read"]
```

read-only behavior is correct, but the SDK-generated metadata advertises only
`gateway:read`, so a client cannot discover `gateway:control`.

### Implemented solution

Keep the SDK global boundary at:

```text
required_scopes = gateway:read
```

and wrap the SDK ASGI application with
`ProtectedResourceMetadataOverride`.

The wrapper intercepts only the RFC 9728 metadata path and advertises all
supported scopes:

```json
{
  "resource": "https://gateway.debasti.com/mcp",
  "authorization_servers": ["<Auth0 issuer>"],
  "scopes_supported": ["gateway:read", "gateway:control"]
}
```

All other requests, including MCP traffic, bearer middleware, lifespan, and
`WWW-Authenticate` behavior, remain delegated to the SDK.

Do not patch `site-packages`. The wrapper exists specifically to keep this
behavior versioned and testable in the repository.

## Why control-scope failure must happen at HTTP transport level

The control plane independently checks `gateway:control` for `exec` and
`write_file`. That check remains an important defense-in-depth boundary.

However, when the only failure occurs inside a tool function, MCP converts the
exception into a tool error inside an HTTP 200 response. The OAuth client then
sees a normal MCP response, not an OAuth `insufficient_scope` challenge, and
cannot know it should request more authorization.

The observed symptom was:

```text
PermissionError: missing OAuth scope(s): gateway:control
POST /mcp ... 200 OK
```

### Implemented scope step-up

`OAuthScopeStepUp` runs before the MCP SDK application for POST requests to
`/mcp`.

For JSON-RPC `tools/call` requests to `exec` or `write_file`:

1. read the bearer token;
2. verify it with the same Auth0 token verifier;
3. if the token lacks `gateway:control`, return HTTP 403;
4. include:

   ```text
   error="insufficient_scope"
   scope="gateway:control"
   resource_metadata="https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp"
   ```

5. otherwise replay the buffered request unchanged to the SDK.

Read-only tools bypass this additional transport check.

This preserves two checks for privileged tools:

- transport-level OAuth step-up signal for capable clients;
- control-plane `gateway:control` enforcement before SSH execution.

## The protected-resource metadata path bug

An early helper default still pointed to:

```text
https://gateway.debasti.com/.well-known/oauth-protected-resource
```

while the actual resource is:

```text
https://gateway.debasti.com/mcp
```

The SDK-generated 401 challenge used the correct `/mcp` metadata path, but the
custom 403 scope-step-up challenge initially used the stale root-only URL.

That inconsistency caused confusing reconnect behavior.

The fix was to derive the metadata URL from the configured audience with the SDK
helper rather than hard-code the root path. A regression test now asserts:

```text
audience https://gateway.example/mcp
-> https://gateway.example/.well-known/oauth-protected-resource/mcp
```

If the resource path changes in the future, update the audience and let the
metadata URL derive from it.

## Revoking an Auth0 grant does not instantly invalidate issued JWTs

Another important operational lesson: revoking the user's Authorized
Application grant removes consent/refresh capability, but an already issued
self-contained access token can remain cryptographically valid until its
`exp`.

After revoking the ChatGPT grant, the gateway still accepted the old token and
the control plane still saw only `gateway:read`.

### Token issuance cutoff

The gateway therefore supports an optional minimum issuance time:

```text
AI_LAB_OAUTH_MIN_IAT=<Unix timestamp>
```

When configured, any token with `iat` earlier than the cutoff is rejected.

This is useful when an operator needs to force all pre-cutoff access tokens to
reauthorize immediately rather than waiting for expiry.

Operational pattern:

1. revoke the relevant Auth0 user grant;
2. set `AI_LAB_OAUTH_MIN_IAT` to the current Unix time;
3. restart the gateway service;
4. verify old requests now receive 401;
5. allow the client to complete a new OAuth flow.

The cutoff is an authentication epoch, not a substitute for normal token
expiry or provider-side revocation. Record why it was changed.

## ChatGPT developer-mode app snapshot behavior

A major empirical lesson was that ChatGPT developer-mode apps behaved like
snapshots of some server-discovered state.

Observed behavior:

- an older developer-mode app did not automatically gain MCP tools added later;
- a newly created app after the six v1 tools were deployed discovered all six;
- a developer-mode app created while OAuth discovery effectively exposed only
  `gateway:read` remained stuck in the old authorization behavior even after
  server metadata was corrected and the app was reconnected repeatedly;
- creating a fresh developer-mode app after the OAuth fixes produced a working
  token and immediately passed `exec`, `write_file`, and `read_file`.

The final successful developer-mode app in the validation sequence was the
first one created after the corrected metadata/scope behavior was fully live.

### Reference debugging sequence

During the October 2026 validation, the developer-mode app named
`AI Lab Gateway 05` was created after the six v1 tools existed, so it exposed
all six tools, but it retained the earlier read-only OAuth discovery state.
Repeated reconnect/revoke/reauthorize attempts did not make its control calls
work reliably.

The next fresh app, `AI Lab Gateway 06`, was created only after the corrected
protected-resource metadata, control scope, scope-step-up behavior, and Auth0
grant were all live. It immediately passed `list_devices`,
`device_status`, `exec`, `write_file`, and `read_file`.

The numeric names are not architectural identifiers; they are preserved here
only as historical evidence that a fresh ChatGPT app snapshot resolved the
stale-client problem.

### Practical rule

After a material change to either:

- the MCP tool catalog/schema; or
- OAuth discovery/resource/scope metadata;

do not assume an existing ChatGPT developer-mode app will refresh itself.

First try a reconnect. If the old app continues to behave as if it has the old
catalog or scope discovery, create one new developer-mode app against the same
MCP URL and retest. Once the new app passes acceptance, remove stale development
apps.

This is observed product behavior, not a permanent protocol guarantee. Recheck
current ChatGPT behavior after long periods or major product changes.

## ChatGPT reconnect behavior observed during scope testing

When the gateway returned HTTP 403 `insufficient_scope`, ChatGPT displayed a
Reconnect flow.

The modal's **Continue in AI Lab Gateway ...** button did not always visibly
open Auth0. Repeatedly clicking it did not fix a stale developer-mode app.

A useful diagnostic sequence in the gateway journal was:

```text
POST /mcp -> 403
POST /mcp -> 401
GET /.well-known/oauth-protected-resource/mcp -> 200
```

That sequence shows the client recognized an auth problem and rediscovered
resource metadata. It does not by itself prove the resulting token contains the
new scope.

The authoritative end-to-end test is a real control call plus server logs.

## Common failure signatures and what they mean

### Unknown client

```text
invalid_request: Unknown client: https://chatgpt.com/oauth/client.json
```

Likely causes:

- CIMD tenant support not enabled; or
- ChatGPT client metadata document not imported.

### Service not found

```text
access_denied: Service not found: https://gateway.debasti.com/mcp
```

Cause observed: Auth0 API identifier did not exactly match the MCP resource.

### No connections enabled

Cause observed: Google social login was not available to the third-party CIMD
application at the required domain/tenant level.

### 401 followed by metadata GET

Typical OAuth discovery/retry behavior. Inspect the referenced metadata and the
next authorization step before treating it as a server failure.

### Tool error with HTTP 200 and missing gateway:control

If logs show:

```text
PermissionError: missing OAuth scope(s): gateway:control
POST /mcp ... 200 OK
```

the request reached the tool without a control token. Ensure the transport-level
step-up wrapper is deployed and that the client/app was created after corrected
scope metadata was live.

### Reconnect modal loops without reaching Auth0

For an old ChatGPT developer-mode app, this was a stale/snapshot symptom.
Creating one new app after the corrected server state resolved the issue.

### Generic ChatGPT tool error

ChatGPT may hide the underlying exception. Inspect:

```bash
sudo journalctl -u ai-lab-gateway --since "5 minutes ago" --no-pager -n 120
```

The gateway journal was essential for distinguishing:

- invalid/old token;
- missing OAuth scope;
- OAuth discovery;
- actual MCP tool exceptions.

## Production deployment sequence after code changes

The validated deployment pattern is:

```bash
cd ~/ai-lab-gateway
git pull --ff-only
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
```

Only after tests pass:

```bash
sudo rsync -a --delete \
  --exclude='.git' \
  --exclude='.venv' \
  --exclude='.pytest_cache' \
  --exclude='*.egg-info' \
  ~/ai-lab-gateway/ /opt/ai-lab-gateway/

sudo chown -R root:ai-lab-gateway /opt/ai-lab-gateway
sudo /opt/ai-lab-gateway/.venv/bin/pip install /opt/ai-lab-gateway
sudo systemctl restart ai-lab-gateway
```

Then verify:

```bash
sudo systemctl show ai-lab-gateway \
  --property=ActiveState,SubState,MainPID
```

Expected:

```text
ActiveState=active
SubState=running
```

## OAuth public acceptance checks

### Protected-resource metadata

```bash
curl -sS \
  https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp \
  | python3 -m json.tool
```

Must include:

```json
"scopes_supported": [
  "gateway:read",
  "gateway:control"
]
```

### Unauthenticated MCP challenge

```bash
curl -sS -D - -o /dev/null https://gateway.debasti.com/mcp
```

Expected:

```text
HTTP/... 401
WWW-Authenticate: Bearer ... resource_metadata="https://gateway.debasti.com/.well-known/oauth-protected-resource/mcp"
```

If either check is wrong, do not troubleshoot ChatGPT first. Fix the resource
server discovery/challenge before creating another client app.

## Final v1 ChatGPT acceptance

A fresh ChatGPT developer-mode app created after all OAuth fixes successfully
completed the full path.

Validated calls:

1. `list_devices()`
   - returned the explicitly authorized Linux device.
2. `device_status("raspberry-lab")`
   - returned online status and the target hostname.
3. `exec("raspberry-lab", "uname -a")`
   - returned Linux kernel/architecture output from the remote target.
4. `write_file(..., "/tmp/ai-lab-gateway-v1-final.txt", ...)`
   - returned success.
5. `read_file(...)`
   - returned exactly the content written.
6. cleanup through `exec("rm -f ...")`
   - returned exit code 0.

Together with `gateway_status`, this validates all six v1 tools through the
real ChatGPT -> OAuth -> MCP -> policy -> reverse SSH -> target path.

## File-operation limitation in v1

`write_file` is intended for small UTF-8 text files.

The implementation base64-encodes content locally and embeds the encoded payload
in the remote shell command before decoding it on the target. This is simple and
safe from shell quoting problems, but very large files can hit command-line
length limits.

For large/binary transfer, add a separate streaming/file-transfer mechanism
rather than silently stretching the v1 primitive.

## Audit expectations

Remote status, command execution, file read, and file write attempts are
recorded as append-only audit metadata.

The default event intentionally records metadata rather than content:

- UTC timestamp;
- authenticated subject;
- device ID;
- action;
- success/failure;
- duration;
- remote exit code where applicable.

Do not log command text, file contents, stdout, or stderr by default without an
explicit retention/privacy decision.

## Private data hygiene

The public repository must be sufficient to reconstruct the architecture
without containing live identities or credentials.

Do not commit:

- real OAuth subjects;
- authorized-user policy files;
- production `.env` files;
- access or refresh tokens;
- Auth0/Google secrets;
- device private keys;
- gateway management private keys;
- private `authorized_keys` or private host-trust state.

Use templates/examples with fictional subjects and device IDs where needed.

## Cleanup after successful acceptance

After a fresh developer-mode app has passed the complete acceptance test:

1. remove obsolete ChatGPT development apps/connections that were created only
   during debugging;
2. keep the known-good app until a replacement has independently passed;
3. keep an old Auth0 API only through an intentional rollback window, then
   remove it if no client uses its old audience;
4. retain the current production environment backup only according to the
   operator's secure backup policy;
5. verify the active Auth0 User-Delegated grant still shows the intended two
   permissions;
6. record the acceptance milestone and current test count in the build log.

## Rebuild checklist

For a future clean implementation, use this order:

1. create the Auth0 resource API with the exact `/mcp` audience;
2. define both read and control scopes;
3. enable Resource Parameter Compatibility Profile;
4. enable CIMD registration and import ChatGPT's metadata document;
5. configure the Google/domain-level social connection;
6. grant ChatGPT user-delegated access to both scopes;
7. configure gateway issuer/audience/JWKS privately;
8. deploy and verify metadata shows both scopes;
9. verify unauthenticated `/mcp` returns a 401 challenge pointing to the
   `/mcp` metadata URL;
10. deploy the scope-step-up wrapper;
11. create a fresh ChatGPT developer-mode app only after the server discovery
    state is correct;
12. complete Google/Auth0 authorization;
13. validate all six v1 tools end-to-end;
14. inspect the audit log;
15. remove stale test apps only after the replacement passes.

If any step behaves differently in a future product version, preserve the
architecture invariants and re-verify current MCP/OpenAI/Auth0 behavior rather
than assuming October 2026 UI behavior is permanent.
