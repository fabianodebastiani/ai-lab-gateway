# Architecture Decision Log

This document records decisions and important working assumptions. They may be revised as the prototype teaches us more.

## ADR-001 — Public gateway with outbound device connections

**Decision:** use a public cloud Linux VM as the rendezvous/control point. Remote devices initiate outbound SSH/reverse-SSH connections to it.

**Reasoning:** lab and field devices commonly sit behind NAT, CGNAT, or firewalls. An outbound connection avoids requiring port forwarding or inbound reachability at every device location.

**Status:** accepted for prototype.

## ADR-002 — MCP on the AI-facing side

**Decision:** expose gateway capabilities to AI clients through MCP over authenticated HTTPS.

**Reasoning:** MCP provides a structured tool interface while keeping network/device mechanics behind the gateway.

**Status:** accepted direction; exact MCP implementation and authentication mechanism still to be selected.

## ADR-003 — Keep the device side thin

**Decision:** do not begin with a custom heavyweight device agent. Prefer standard SSH plus a persistent outbound tunnel managed by standard Linux facilities.

**Reasoning:** reduces installation complexity and keeps the solution portable across ordinary Linux and embedded Linux targets.

**Status:** accepted for prototype.

## ADR-004 — Generic MCP primitives first

**Decision:** begin with generic command/file/process primitives instead of encoding individual laboratory peripherals into MCP.

**Reasoning:** once the AI has controlled Linux CLI access, device-specific libraries and utilities can remain local to the target. This keeps the gateway reusable.

**Status:** accepted.

## ADR-005 — Hardware-specific software belongs on the target

**Decision:** radio, SPI, GPIO, AT-command and similar hardware interfaces should normally be represented by libraries, tools or scripts installed on the target Linux system.

**Reasoning:** separates transport/control-plane concerns from hardware behavior and allows the same gateway to control very different devices.

**Status:** accepted.

## ADR-006 — Separate identities and credentials

**Decision:** do not reuse the gateway administrator SSH key as a device identity, and do not use one shared device key for every target.

**Reasoning:** limits blast radius and enables device revocation, user/device authorization and useful auditing.

**Status:** accepted.

## ADR-007 — Non-root target access by default

**Decision:** AI-controlled sessions should normally run as a non-root user. Additional privileges can be granted narrowly with sudo policy.

**Reasoning:** arbitrary root access is unnecessary for most development tasks and greatly increases impact of mistakes or compromise.

**Status:** accepted.

## ADR-008 — Tailscale/VPN is optional, not a prototype dependency

**Decision:** do not require a network overlay initially.

**Reasoning:** SSH already supplies encrypted authenticated transport and reverse tunnels solve the immediate NAT/CGNAT problem. A VPN remains an option if later requirements justify it.

**Status:** accepted for prototype.

## ADR-009 — Avoid unnecessary infrastructure

**Decision:** do not introduce Docker, a heavy database, or additional platform components merely by default.

**Reasoning:** the initial gateway VM is small and the core problem can be validated with a lightweight stack. Complexity should be earned by requirements.

**Status:** accepted for prototype.

## ADR-010 — Cloud VM platform and initial shape

**Decision:** the first gateway is an Oracle Cloud Infrastructure VM in Brazil Southeast (Vinhedo), using Canonical Ubuntu 24.04 Minimal on x86_64.

Observed initial resources:

- approximately 1 GiB RAM;
- 45 GiB root filesystem;
- no swap initially;
- public IPv4 attached after provisioning.

**Reasoning:** sufficient for an initial lightweight gateway and immediately available during the prototype setup.

**Status:** implemented.

## Open decisions

- OAuth provider/integration details for the MCP authentication layer.
- Audit-log storage and retention.
- Exact sudo policy for managed devices.
- When the JSON prototype registry/authorization files should move to a database.

## ADR-011 — Use the standard remote MCP model and OAuth 2.1

**Decision:** implement the AI-facing interface as a standards-based remote MCP server over HTTPS using Streamable HTTP. Authentication should follow the MCP OAuth 2.1 authorization model rather than relying on a static Bearer token as the long-term design.

**Reasoning:** current OpenAI MCP/plugin documentation supports remote MCP servers and recommends OAuth 2.1 for authenticated user-specific or write-capable services. An earlier prototype also implemented this pattern successfully enough to establish the architecture: protected-resource metadata, an OAuth authorization server, Authorization Code + PKCE, and bearer access-token validation at the MCP resource server.

The Lab Gateway should preserve separation between:
- MCP/user authentication;
- gateway administrative SSH;
- per-device SSH/tunnel identities.

**Implementation note:** the first local prototype may temporarily use simpler authentication for isolated testing, but the public design target is OAuth 2.1.

**Status:** accepted direction.

## ADR-012 — Python is the preferred initial MCP server stack

**Decision:** use Python 3.12 and the official MCP Python SDK for the first Lab Gateway server implementation.

**Reasoning:** the gateway VM already provides Python 3.12; the official MCP SDK supports Streamable HTTP; Python keeps the service lightweight on the approximately 1 GiB VM; and the gateway's main work is orchestration of SSH, authorization and structured tools rather than a browser UI.

An earlier MCP implementation used TypeScript/Next.js and demonstrated the protocol/authentication pattern, but its serverless/web-application constraints do not apply to this persistent Linux gateway.

**Status:** accepted for prototype.

## ADR-013 — ChatGPT Go compatibility is a product requirement

**Decision:** the gateway/client integration must be designed and tested with ChatGPT Go as a required target. Compatibility with ChatGPT Free is a desirable additional target when the ChatGPT app/plugin distribution surface permits it.

**Reasoning:** the intended product experience is not limited to developer-only MCP configuration. Prior experimentation established a useful precedent for exposing a remote authenticated MCP to a ChatGPT Go user. The Lab Gateway should therefore keep its MCP implementation standards-based and avoid dependencies on a single developer-only client path.

**Validation:** protocol-level MCP success is necessary but not sufficient. A milestone is only complete after the relevant ChatGPT product surface can actually connect and invoke the gateway.

**Status:** accepted.

## ADR-014 — Platform users are not Linux users

**Decision:** human/client identities belong to the application authentication layer. Do not create one gateway Unix account per platform user as the normal authorization model.

**Reasoning:** MCP authentication establishes who is making a request; application authorization then decides which devices and actions that subject may use. Unix identities serve service, tunnel and target-isolation purposes and should not be conflated with product users.

**Status:** accepted.

## ADR-015 — Reverse tunnel and target login use separate SSH identities

**Decision:** each managed device has a device-specific identity for opening its outbound reverse tunnel, while the gateway uses a separate management identity to authenticate to the target sshd through that tunnel.

**Reasoning:** a reverse SSH forward carries TCP traffic but does not authenticate the later management session to the target sshd. Separating the two credentials gives independent revocation and avoids treating a tunnel credential as a shell credential.

**Status:** accepted and validated with the first live target.

## ADR-016 — Reverse-forward endpoints are loopback-only with fixed prototype ports

**Decision:** reverse SSH listeners bind only to gateway loopback. The prototype registry assigns a unique fixed port to each device. Each tunnel public key is restricted to its assigned loopback listener with OpenSSH `permitlisten`.

**Reasoning:** the reverse ports are an internal transport detail and must not become another Internet-facing SSH surface. Fixed ports make the first implementation easy to inspect and debug; dynamic allocation can be introduced later if scale requires it. Per-key listener restrictions prevent a device credential from selecting another prototype device's assigned reverse port.

**Status:** accepted and validated with the first live target on port 10001.

## ADR-017 — Deny-by-default application authorization

**Decision:** user-to-device/action authorization is explicit and deny-by-default. A subject must have a grant for both the target device and requested action.

**Reasoning:** device access is potentially equivalent to code execution. Missing users, missing devices and missing actions must therefore fail closed.

**Status:** accepted.

## ADR-018 — Persistent device tunnels are systemd-managed and fail-recovering

**Decision:** Linux targets maintain the outbound reverse SSH tunnel with a systemd service using strict host-key checking, keepalives, `ExitOnForwardFailure=yes`, and automatic restart.

**Reasoning:** the gateway must not depend on an interactive terminal or manual reconnection after transient failures. Standard Linux service management keeps the device side thin while providing boot persistence and process supervision.

**Validation:** on the first live target, the tunnel process was deliberately killed. systemd restarted it, the reverse listener was recreated, and gateway-to-target command execution succeeded again.

**Status:** accepted and validated for the prototype.

## ADR-019 — Tunnel identities may forward but may not open SSH sessions

**Decision:** the shared gateway landing account for device tunnels is restricted
to public-key authentication and remote TCP forwarding only. Session channels
are disabled with `MaxSessions 0`; stream-local forwarding, user RC, TUN/TAP,
agent forwarding, X11 forwarding and TTY allocation are disabled. Per-device
`permitlisten` remains the listener-level authorization boundary.

**Reasoning:** a device tunnel credential exists only to maintain its assigned
reverse transport. It must not become a shell or command-execution credential
on the public gateway, and it must not be able to claim another device's
listener port.

**Validation:** with the first live target, a fresh systemd-managed
`ssh -NT -R` tunnel successfully recreated `127.0.0.1:10001` under the hardened
policy and management SSH still worked end-to-end. A remote-command attempt
using the tunnel credential failed with SSH exit 255. An attempted reverse
forward on port 10002 was denied, while 10001 remained active and 10002 had no
listener.

**Status:** accepted and validated for the prototype.


## ADR-020 — Private developer-mode distribution first

**Decision:** during the prototype and internal-development phase, connect
authorized ChatGPT clients directly to the remote MCP endpoint using the
available developer-mode/private connection workflow. Do not make publication
in the public Plugin Directory a prerequisite for the MVP.

**Reasoning:** the immediate goal is to validate secure authenticated control
of private Linux lab devices, not to distribute the service publicly. The MCP
endpoint must be Internet-reachable for the remote client, but reachability
does not imply authorization: OAuth authentication plus deny-by-default
subject/device/action policy remains mandatory.

A future public or workspace distribution package can be added without changing
the gateway transport architecture.

**Status:** accepted for the current development phase.


## ADR-021 — Auth0 + CIMD with exact MCP resource audience

**Decision:** use Auth0 as the prototype authorization server and register
ChatGPT through its Client ID Metadata Document. The Auth0 Custom API identifier
must exactly equal the MCP resource URL:

```text
https://gateway.debasti.com/mcp
```

Enable Auth0 Resource Parameter Compatibility Profile and CIMD Registration.
Keep DCR disabled unless deliberately required.

**Reasoning:** ChatGPT's MCP OAuth flow discovers and requests the resource using
the standards-based resource identifier. An earlier root-only Auth0 API
identifier did not match the `/mcp` resource and caused a service-not-found
authorization failure. Exact resource/audience alignment avoids
provider-specific rewrites.

**Status:** accepted and validated end-to-end.

## ADR-022 — Separate globally required scope from supported control scope

**Decision:** globally require only `gateway:read`, advertise both
`gateway:read` and `gateway:control` in RFC 9728 metadata, and require
`gateway:control` only for privileged tools.

**Reasoning:** MCP Python SDK 2.3.0 couples
`AuthSettings.required_scopes` to both middleware enforcement and generated
`scopes_supported`. Setting both scopes there would force control permission
onto read-only operations. Setting only read would hide the supported control
scope from OAuth discovery.

The gateway therefore uses a repository-owned ASGI metadata override instead of
patching the installed SDK.

**Status:** accepted and implemented.

## ADR-023 — Emit OAuth insufficient-scope at transport level for privileged tools

**Decision:** for `exec` and `write_file`, perform an additional
transport-level scope check and return HTTP 403
`error="insufficient_scope"` with `scope="gateway:control"` and the RFC 9728
metadata URL when a valid token lacks control scope.

The control plane still independently enforces `gateway:control` before SSH
execution.

**Reasoning:** an exception raised only inside an MCP tool becomes a tool error
inside HTTP 200, which does not provide the OAuth client a standards-level
signal to request stronger authorization. The transport-level 403 preserves
OAuth step-up semantics while defense-in-depth remains in the control plane.

**Status:** accepted and implemented.

## ADR-024 — Support a minimum token issuance epoch

**Decision:** support optional `AI_LAB_OAUTH_MIN_IAT` runtime configuration.
Tokens issued before that Unix timestamp are rejected.

**Reasoning:** revoking an Auth0 Authorized Application grant removes
consent/refresh state but does not necessarily invalidate already-issued
self-contained access JWTs before their normal expiry. A local issuance cutoff
provides an explicit emergency/maintenance reauthorization epoch without
rotating signing keys.

**Status:** accepted as an operational control; use intentionally and document
changes.

## ADR-025 — Treat ChatGPT developer-mode app discovery as refreshable but not guaranteed

**Decision:** reconnect an existing developer-mode app first after server
changes, but if it continues to expose a stale MCP tool catalog or OAuth
discovery state, create one fresh app against the same MCP URL and validate it
before removing the old one.

**Reasoning:** during live validation, older development apps did not reliably
pick up newly added tools or corrected OAuth scope discovery. A fresh app
created after the corrected v1 server state immediately passed control and file
operations. This is empirical product behavior rather than a protocol
invariant.

**Status:** accepted operational guidance; revalidate after major ChatGPT
product changes.

## ADR-026 — Stable v1 MCP surface is six generic Linux primitives

**Decision:** the v1 public MCP surface is:

- `gateway_status`;
- `list_devices`;
- `device_status`;
- `exec`;
- `read_file`;
- `write_file`.

**Reasoning:** these generic primitives are sufficient for AI-driven Linux lab
work while keeping hardware-specific behavior on the target. They also provide
a small surface that can be authorized, tested and audited clearly.

**Status:** accepted and validated through the real ChatGPT -> OAuth -> MCP ->
policy -> reverse SSH -> target path.
