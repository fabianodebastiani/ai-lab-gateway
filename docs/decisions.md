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

## ADR-027 — Enroll restricted; elevate Linux device access on demand

**Date:** 2026-10-14. **Status:** accepted product decision, implementation pending.

**Decision:** registering and pairing a new Linux device is separate from
authorizing elevated execution privileges. A new device is **always enrolled
as Restricted** (non-root management user, no general-purpose sudo). Enrollment
asks only for confirmation of the new device's identity and secure pairing;
it does NOT display the access-mode selector or grant admin privileges.

Once paired, the operator can request administrative access to an individual
device, in the normal work context, using **exactly three radio controls**:

1. **Restricted** — normal access; no administrative elevation.
2. **Unrestricted** — deliberately grant broad administrative access to that
   device until revoked, with a clear high-risk warning.
3. **Partial** — grant administrative access during a limited interval.
   **Only Partial** exposes a duration dropdown, initially 15, 30, 60,
   120, 240, 480, or 1440 minutes. After expiration, the device enforcer
   refuses new privileged commands and the effective mode returns to
   Restricted. The dropdown defaults to 30 minutes when opened.

Grant approval must be traceable to the authenticated human and may use a
supported host-native confirmation or a separate approval channel.
Neither a model-generated UI button nor conversational text is sufficient
evidence of authorization. Google Authenticator is NOT required for normal
device enrollment or for each command during an existing privileged window;
it may remain as optional step-up for higher-risk decisions.

**Reasoning:** device identity/trust can last indefinitely, whereas sudo
capabilities should be changed only as needed and often be short-lived.
Separating these events reduces enrollment friction, prevents accidental
default root privileges, and avoids binding sudo lifetime to SSH lifecycle.

**Enforcement:** the Restricted default and all subsequent grants must be
implemented by the gateway and device-side security boundary, not just a
visible UI selection. Partial TTL must be validated per privileged command
and expire without a browser, ChatGPT session or Internet access.
Full root access may make persistent changes; timed expiry cannot undo them.

**Migration:** preserve existing Raspberry Pi, WSL and Oracle configurations
until a fresh Linux test target passes the onboarding and permission
acceptance tests.

**Design and implementation checklist:** [v2 enrollment and access
specification](v2-device-onboarding-access.md).

### ADR-027 addendum — one-use command is independent of access profiles (2026-10-16)

**Correction / preservation of an earlier accepted requirement:** ADR-027's
exactly three **persistent access profiles** do not replace or remove the
separately authorized **one-time exact-command administrative execution**
previously agreed in issue #2 and the privilege-broker discussions. While
Restricted, an approved operation may execute **exactly once**, with its
exact argv/inputs bound to a consent artifact, and then becomes unusable.
Temporary and indefinite approvals remain separate alternatives. Device
`ai-gateway` must still have no general sudo; a device-local, root-owned
executor checks authorizations. Do not mistake the broker on Oracle for
this still-pending per-target feature.

**User workflow retained:** one public installer, one code, Restricted SSH,
a locally installed `ailab` CLI for connect/disconnect/status/persistence,
and an independently consented administrative executor prepared only by
the original *local* sudo-authorized installer. See the
[canonical cross-feature contract](device-lifecycle-and-privileged-execution.md),
which explicitly records retained, superseded and still-incomplete elements.
No privilege is granted merely by pairing or by displaying an approval UI.

## ADR-028 — Connection persistence is a per-device boolean, configurable by MCP

**Date:** 2026-10-14. **Status:** accepted. Implementation in progress.

**Decision:** Every managed Linux device, without device-type exceptions,
supports a **boolean connection preference**: `persistent=true` or
`persistent=false`. It is independent of the Restricted / Partial /
Unrestricted authorization profile and independent of whether SSH is
*connected at this instant*. The UI represents the preference as a single
on/off switch labeled "Manter conexão persistente".

- `persistent=true`: enable the dedicated systemd reverse-SSH tunnel unit
  so it starts on subsequent Linux boots and automatically retries failed
  sessions while active.
- `persistent=false`: disable automatic startup. The device can be
  manually connected or disconnected; toggling this flag does **not**
  immediately disconnect an existing working session.

Both options apply equally to **all** Linux targets, whether a laptop,
Raspberry Pi, VM, embedded Linux board, or Oracle instance. The installer
may **suggest** true for unattended servers and false for laptops, but must
allow either choice. Hardware category never overrides an explicit flag.

**MCP controls:** the Gateway should expose:
1. `device_connection_status(device_id)`: authorized read, reports live
   connectivity and actual target-side systemd persistence when reachable.
2. `set_device_persistent(device_id, persistent: bool)`: independently
   authorized, audited write operation that changes only the per-device
   startup flag. It requires OAuth `gateway:control`, an explicit
   `connection_manage` device grant and a narrowly configured, root-owned
   device-side helper. `exec` alone must NOT grant the right to toggle it.

An unconfigured old device is not silently assumed to be On-demand: its
specific systemd unit must be registered before the MCP setter operates.
The target systemd enablement is the source of truth, not a cosmetic
registry value. Offline responses report `persistent=null` (unknown live
state), not `false`.

**Connected vs Persistent are independent:**
- Connected + persistent=false is valid (WSL on-demand active).
- Disconnected + persistent=true is valid (persistent device powered off).
- An MCP command can set persistence only **while the reverse tunnel is
  reachable**. After manually disconnecting the **only** tunnel, the same
  MCP cannot reconnect it. Reconnection needs a local start, a persistent
  service boot, or an independently engineered out-of-band mechanism.
- Stopping the tunnel via remote MCP needs a carefully designed delayed
  stop/acknowledgement; a local Connect/Disconnect action is preferred
  until that is tested.

**WSL semantics:** Even with persistent=true, systemd only starts when
the WSL Linux distribution starts; it cannot wake the laptop or guarantee
Windows launches WSL at boot.

**Source (not yet in production):**
`src/ai_lab_gateway/connection_control.py`,
`scripts/ai-lab-device-connectionctl`,
`scripts/device-connection.sh`,
and `tests/test_connection_control.py`.
The next production deployment must install the target helper through
a trusted local sudo setup (not permanent general MCP sudo), configure
the `connection_unit` in the protected device registry and authorize
`connection_manage` per subject/device. A successful unit test is
not evidence of deployed operation.


## ADR-029 — Pairing by device-displayed code through authenticated MCP

**Date:** 2026-10-15. **Status:** accepted product decision; implementation pending.

**Decision:** The default onboarding experience for a previously unknown Linux
device is **device-initiated, code-based enrollment**, with **explicit,
authenticated confirmation in the existing ChatGPT/MCP conversation**.
Do not require a second login, a memorized admin-panel password, access to
the device from the ChatGPT computer, or preexisting SSH connectivity.
Keep the old browser approver as optional admin/recovery fallback only;
do not remove the legacy approval path until the new path has passed live
security/functional acceptance.

**User experience:** A user on any computer or phone asks ChatGPT how to add
a Linux device. ChatGPT provides a **stable, public, nonsensitive download
command** for a small, integrity-verified installer. The Linux target may
also initiate the process independently. The installer, in the target's
terminal, connects to the gateway over outbound HTTPS, generates a new
local Ed25519 tunnel identity and required management/host identity proof,
requests a pairing session, and displays a short **human-typeable** code
(e.g. `K7M2-P9Q4`, illustrative only). The user types that code into
ChatGPT, which resolves it via Auth0-authenticated MCP authorization.
ChatGPT shows an identified, **pending** device and confirmation data that
the user can compare on the Linux terminal; the user explicitly confirms
this exact pending device. The gateway provisions isolated management/
tunnel credentials and a loopback-only reverse SSH listener, runs
connectivity and denial-of-privilege tests, and then marks the device active.
The code expires/gets consumed; the connection starts **Restricted**
independently of the requested `persistent` boolean.

**Never equate:** user Auth0 authentication, possession of a pairing code,
possession of a Linux SSH key, and authorization to grant root. These are
separate trust assertions; successful enrollment **does not imply sudo**.

**Protocol and threat model:**
1. Use the **OAuth 2.0 Device Authorization Grant (RFC 8628) model** as
   inspiration, not as a claim that our custom MCP pairing is an OAuth
   authorization-server implementation. Public HTTPS creates a pending
   device-bound session; the device receives both a high-entropy,
   nonhuman `device_secret` for authenticated polling and a short
   `user_code` for presentation to the operator. The server creates and
   stores only digests of these secrets and never logs them.
2. The human code alone is **never a credential for remote access** or
   approval. It only looks up a pending session when paired with an
   Auth0-verified, authorized MCP principal. Rate limit and audit *all*
   public session creation, code lookups, confirmation attempts and polls;
   enforce short TTL, finite total attempts, one-use resolution, strong
   random code entropy, and explicit code-disclosure/abuse safeguards.
   No plain single word such as `girafa` is adequate. A random
   multiword phrase is an optional UX, with measured entropy.
3. Bind the enrollment to target-generated Ed25519 public identities.
   Challenge-response with the private key proves key possession.
   The server supplies verifiable gateway identity material, the terminal
   displays a comparison phrase/fingerprint, and the authenticated user
   checks the same value in ChatGPT before confirming. This mitigates
   code guessing, session confusion, substitution, interception and replay.
   Before activation the server must recheck the bound principal,
   exact pending device identity, expiry, challenge/nonce and key proofs;
   multiple claimed codes/users cannot silently replace the device.
4. **The model's text alone is not an approval token.** The MCP write
   operation must be authorized with `gateway:control`, explicit
   `device_enroll` policy, attributable to the actual Auth0 principal,
   user-initiated and approved via a host-mediated confirmation UI or
   independently verifiable signed confirmation/step-up. If the current
   ChatGPT/host cannot supply that assurance, keep the independent human
   approval boundary as fallback: do not bypass it by treating
   a model-generated tool call as human consent.
5. The installer comes from a versioned, TLS-served artifact with
   verified SHA-256/signature and controlled release; no unverified
   `curl | sudo bash`, no permanent broad sudo, no credential in command
   line/history. Installer privileges must be narrow and local; SSH
   private keys are created and kept on their originating machine.
6. Persistent vs on-demand is independent and applies to every device,
   per ADR-028. The v2 candidate coexists with any v1 connection until
   successful SSH/authorization/reconnect/rollback tests; revocation
   of v1 happens only after verified cutover.

**API separation:** public unauthenticated *initiation/polling*
(which cannot authorize); authenticated MCP *lookup/request/confirm*;
privileged, narrow, auditable *provisioning* after effective human
authorization. Prefer distinct Unix identities/sockets and explicit
root-owned allowlisted provisioning operations. Never allow a public
device request to authorize itself or choose arbitrary SSH listen ports.

**Deployment approach:** Keep existing production pairing v2 invite/claim
and browser approval service operational while developing this
device-code flow as an opt-in candidate. Test under synthetic sessions
first and against the existing WSL without a second Ubuntu distribution,
then test from a truly virgin Linux target before considering onboarding
complete. Do not grant generic overnight root access merely for
development. Existing Oracle `ai-maintenance` elevated privileges
expired on 2026-10-15 at 05:08 UTC and are not automatically renewable.

**References:** [device-code protocol and acceptance criteria](device-code-pairing-v2.md),
[v2 onboarding/access contract](v2-device-onboarding-access.md),
[WSL migration checkpoint](wsl-v2-migration.md), ADR-027 and ADR-028.


**Staging UX/security refinement — 2026-10-15 (not yet deployed):**
Two independently displayed, 40-bit human-typeable codes are used.
The first locates the provisional Linux through the user's real
Auth0-authorized MCP session; lookup never discloses the **second** code
or the signed challenge needed to reconstruct it. Only the target
terminal displays the second code, and the user must manually type it
in the ChatGPT conversation. The Gateway checks a protected HMAC digest,
the exact request and verified subject, ten-minute expiration and a
durable limit of four guesses. The model may not authorize via its own
`yes`, a guessed Boolean or a code returned by a tool. This terminal-
possession mechanism is a candidate independently verifiable consent
channel, without a second browser login; its phishing risks require
review and the browser approver remains available as fallback.
Pairing identity approval does **not** activate SSH and does not grant
sudo. See `docs/device-code-pairing-v2.md` for lab tests/limitations.

The pre-release Linux bootstrap is pinned to an immutable Git commit
and a verified SHA256 hash, downloaded over TLS, and never runs as root.
This does **not** equal a separately signed release distribution;
official signature management and on-server `/install.sh` deployment
remain future work.


### ADR-029 product UX clarification — 2026-10-15 (supersedes two-code prototype UX)

**Canonical end-user journey: TV-style pairing, one human-visible pairing code.**
The operator is **already authenticated in ChatGPT to the Gateway MCP via Auth0**.
The user says "Quero conectar um novo Linux"; ChatGPT offers one stable,
public HTTPS installer command with no user token embedded. The user runs it
on the previously unknown Linux. The client verifies the installer, generates
local device SSH credentials, initiates outbound HTTPS, and displays **one
short human-typeable pairing code**. The user provides that code in the
existing ChatGPT conversation. Auth0-authenticated MCP resolves it, displays
the pending device and requests approval for **that exact device**. The
Gateway records verifiable human consent, provisions isolated SSH trust, and
the Linux automatically connects outbound via reverse SSH. The Gateway
validates the connection and makes the device available to MCP, starting
**Restricted**. No manually pasted SSH keys, manual Oracle port configuration,
second website login, TOTP for normal enrollment, or second terminal code.

The earlier **two independently typed codes** are an experimental security
prototype, **not** the agreed production UX and not a required user step.
Do not make the user type two codes simply because the experimental
implementation currently supports them.

**Non-negotiable security distinction:** a model-generated button, conversation
text, or MCP tool call alone is not authenticated human approval. Use a
verified host-native user-confirmation/step-up boundary if supported; if not,
identify that missing capability and preserve a secure separately authenticated
fallback until equivalent consent evidence is implemented. This internal
requirement must not be disguised as a completed one-code ChatGPT integration.

Build the thinnest sufficient secure server-side orchestration; do not add
new user-facing steps. Pairing grants identity and nonroot access only.
The per-device Restricted / Partial / Unrestricted privilege-selection flow
remains a later, separate action under ADR-027. Legacy WSL 10002 and Raspberry
10001 stay operational until the v2 candidate passes real end-to-end tests.
