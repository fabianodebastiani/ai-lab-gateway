# AI Lab Gateway v2 — pairing by a code shown on the device

**Decision:** Accepted 2026-10-15 (ADR-029).  
**Implementation status:** design and non-production prototype work; NOT a
statement that the feature is available on the live Oracle gateway.

## User experience — two different computers

The ChatGPT user may be on a phone, a different laptop, or in another
network. They have already authenticated to our MCP server through Auth0.
The Linux target is **never required** to have been accessed by MCP, to
have any preexisting AI Lab SSH account, or to be reachable inbound.

1. On the unknown Linux, run the same public installation command every time.
   The URL contains **no access token** or account-specific data. Download
   and verify a signed, versioned installer before permitting privileged
   changes. The installed client generates fresh per-device identities.
2. The client makes a TLS-authenticated, outbound request to the public
   gateway **without authenticating as a user**. The gateway records a
   temporary request but grants **zero** device trust or SSH access.
3. The terminal shows a human-friendly code, such as
   `K7M2-P9Q4` (example only), and a short confirmation string/fingerprint.
   It then waits; the device can poll using an unrelated, long secret.
4. The person tells ChatGPT: "Conectar dispositivo K7M2-P9Q4."
   ChatGPT calls `pairing_lookup_code` using its **real, validated**
   Auth0 principal, `gateway:control` scope and `device_enroll` grant.
5. ChatGPT displays host name, platform, key fingerprint/confirmation
   string and access starting as **Restrito**; the user compares the same
   confirmation string on the Linux terminal and explicitly authorizes
   this **one immutable request**.
6. An independent user-consent boundary approves the exact request. A mere
   model-generated phrase or tool call is not accepted as proof of human
   confirmation. Use a real host-provided action confirmation/step-up or
   cryptographically verifiable human-origin signal; where unavailable,
   retain the separate browser approver as a mandatory fallback.
7. A narrowly privileged server-side provisioner issues isolated management
   credentials and a loopback-only reverse SSH tunnel binding. The device
   receives only the gateway's **public** key/verified SSH host identity
   and local configuration instructions, never a gateway private key.
   The server receives the device public key and a cryptographic proof of
   possession; the device private key remains on the device.
8. The device connects outbound through NAT/CGNAT. Gateway tests target
   host identity, key rejection, non-root identity, command timeouts,
   reconnect/persistence and rollback. Only after testing is its
   status **active**. The short code and polling secret expire/are consumed.
9. Onboarding always starts **Restrito**. Changing to **Parcial** or
   **Irrestrito** requires a separate, audited privilege grant. The
   `persistent` flag is an unrelated per-device on/off setting.

### Example target terminal (illustrative, not yet deployable)

```text
AI Lab Gateway — Vincular dispositivo
Linux: lab-ubuntu-01
Chave local Ed25519: pronta
Código: K7M2-P9Q4
Confirmação: FAROL-LAGO-LIVRO (illustrative)

No ChatGPT: "Conectar dispositivo K7M2-P9Q4"
Aguardando confirmação autenticada...
```

The fixed bootstrap address (e.g. `https://gateway.debasti.com/install.sh`)
and installer release signature/verification process are **planned**, not
currently published for production. Do not present an unverified
`curl | sudo bash` command to users.

## Trust boundaries

| Actor | May | Must NOT |
| --- | --- | --- |
| Unauthenticated Linux | Request/poll its own bounded pending session over TLS | Activate itself, enumerate users, edit registry, obtain management private keys |
| MCP operator (Auth0) | Discover a code/request, inspect public identity, initiate explicit confirmation | Bypass independent user-consent evidence, grant root by pairing |
| Consent verifier | Certify one authenticated human confirmation bound to immutable request and digest | Give blanket/transferable approval to model |
| Narrow root provisioner | Install tightly scoped per-device public keys, pin verified host identity, atomically update registry after tests | Provide generic shell/sudo to MCP; leak keys |
| Enrolled device | Create outbound SSH tunnel on assigned 127.0.0.1 port | Choose arbitrary listeners, manage other devices, change root privileges |

## Two tokens: user code and device secret

The pairing backend, not the model, generates:

- **User code:** 8 random Base32 symbols, grouped as four/four. The alphabet
  excludes ambiguous letters/digits if practical. A full uniformly random
  8-symbol code from 32 symbols provides **40 bits of entropy**; changing
  alphabet size requires re-evaluating entropy. Validate normalization
  safely (case/space/dash) without leaking whether unauthenticated guesses
  match; store a keyed digest/HMAC rather than plaintext code.
- **Device secret:** independent, cryptographically secure >=256-bit
  URL-safe token, **never shown in ChatGPT**. It is a poll/capability
  credential tied to one pending device session, and stored only as a
  digest at the gateway. The secret permits *status* queries but never
  changes approval or grants access.

The two must be independent: knowing one never reveals the other. Rotate
identifiers every new attempt; 10-minute expiry, finite attempts, global
plus source/request/operator quotas, audits without token logging,
idempotency, and cache-safe HTTP headers. The code alone cannot complete
enrollment. TTL expiration and revocation must take effect at every
transition and polling endpoint, including after an approval.

**Code-stealing and session substitution:** A person who reads another
person's terminal code may attempt to bind the wrong user to the device.
Before confirmation, compare a server-bound phrase or SSH fingerprint
visually on **both** the target and authenticated ChatGPT. Exact request,
public keys and owner become immutable at first claim. A second user or
unexpected duplicate request cannot silently replace the first.
Explicitly test this attack in addition to guess-rate limits.

### Ed25519 possession proof

The Linux generates a fresh Ed25519 identity and authenticates it with
a challenge-response. One lightweight option is OpenSSH `ssh-keygen -Y
sign/verify` with canonical challenge bytes, since the target must
already support SSH. A Python `cryptography` implementation may serve
as the laboratory verifier, but the deployable client should not
silently depend on extra packages without installing/verifying them.
The challenge must bind a random server nonce, request ID, normalized
device ID, protocol version, role, expiry and the hashes of **both**
the tunnel and host public keys. Reject mismatched keys, altered
fields, replayed nonces, invalid signatures and substituted requests.
Do not accept TLS alone as a device identity proof.

## Proposed API — *not yet live*

```text
POST /pairing/device/start          anonymous, rate limited; returns
                                    request_id + user_code + device_secret
                                    + server nonce (no authorization)
POST /pairing/device/prove          device_secret + signed challenge proof
POST /pairing/device/poll           device_secret in JSON body; throttled, no account info
MCP  pairing_lookup_code(code)      OAuth gateway:control + device_enroll
MCP  pairing_confirm(request_id,
                     confirmation)  consent-attested explicit authorization
MCP  pairing_deny(request_id)       authenticated operator
LOCAL provision_candidate(request)  protected root-only provisioning after approval
LOCAL verify_activate(request)      exact SSH verification + atomic registry update
```

Polling uses POST (rather than query-string GET) to avoid placing the\nlong device secret in URLs, intermediary access logs and browser history.\n\nSeparately version protocol structures. The existing live
`/pairing/claim`, `pairing_invite` and approval web must remain
unmodified until the new API is deployed and verified. No compatibility
or live endpoint is promised by this document.

## Test plan

**Unit/integration (no root):**

- Codes/token generated independently and never logged; 40-bit code
  alphabet, single-use, expiry, replay, collisions and quotas.
- Unauthorized/anonymous API cannot approve, enumerate users or expose keys.
- Auth0 subject and exact request bound to one user; malformed code does
  not reveal existence; rate limiting per IP/operator/device.
- Ed25519 valid signature passes, wrong key/modified challenge/replay fails.
- Wrong confirmation phrase/fingerprint fails. Model-only requests cannot
  self-approve without host-attested user confirmation.
- Concurrent claims/approvals yield exactly one terminal transition.
- Persistence preference is independent, Restricted enforced, no sudo.

**End-to-end staging:**

- Single existing WSL Ubuntu on `LAPTOP-5RJJ0KBM`. Keep active v1
  management path on loopback 10002 while testing v2 candidate 10003.
  A separately generated v2 tunnel key already exists; no separate WSL
  distribution is permitted for this pilot. Do not revoke v1 credentials
  before successful v2 SSH/mcp/reconnect/rollback tests.
- At least one **truly virgin** Linux later, containing no prior gateway
  user, keys, authorized_keys, registry record or MCP access. Prove
  local prerequisites, secure download, device code, approval, new
  credentials, outbound tunnel and finished MCP execution.
- Attacker simulations: guessed code, code stolen by another user,
  tampered download, wrong SSH host key, revoked invitation,
  expired consent, duplicate device ID and disconnected network.
- Record redacted logs, acceptance evidence, rollback steps and
  operative status in GitHub.

## Existing deployment checkpoint (2026-10-15)

- v2 browser-approved WSL request:
  `n-OXzoFmx3v93hTuNuCUVmOa` approved; `restricted`,
  `persistent=false`.
- Oracle candidate gateway key and `permitlisten=127.0.0.1:10003`
  were staged; the v1 `windows-wsl` registry still points to 10002.
- WSL new tunnel key fingerprint:
  `SHA256:WNQwcglksL5gtUlmVKWv1rByzFlJbffK1ZJeqbM8EPo`.
- An earlier attempt to transfer the **public** management key via
  remote tooling was blocked by host security controls. A separate
  operator-run mechanism is required to complete v2 SSH acceptance;
  do not try to bypass controls or leave persistent root access.

See [WSL migration notes](wsl-v2-migration.md).


## Implementation checkpoint — 2026-10-15 (local WSL lab)

**The device-initiated code + key-possession handshake now exists as
tested code, NOT as a public production endpoint or completed enrollment.**

Implementation:
- `src/ai_lab_gateway/device_code.py` — transactional 10-minute sessions,
  independent 40-bit human code and high-entropy device secret, Ed25519
  possession proof, expiry/replay/source/operator quotas, 0600 SQLite in
  owner-only 0700 directory. Restricted-first, no sudo.
- `src/ai_lab_gateway/device_code_http.py` — loopback HTTP
  `POST /pairing/device/start`, `/prove`, `/poll`, plus health endpoint.
  Anonymous requests can **only** ask/prove/poll. No approval or activation.
  Per-peer quotas use kernel TCP peer address, not untrusted forwarded
  headers. **Before public Caddy exposure**, deploy a trusted source-IP
  accounting scheme, reverse-proxy limits and audit.
- `scripts/device_code_pair_linux.py` — target-side Python CLI with
  outbound HTTPS, local ssh-keygen, versioned challenge validation, Ed25519
  signing, terminal code+confirmation display, and authenticated polling.
  Currently requires preinstalled `python3-cryptography`, `ssh-keygen`
  and a Linux OpenSSH ED25519 host key; a truly virgin installer must
  prepare these prerequisites securely. `--no-wait` is for lab only.
- `src/ai_lab_gateway/device_code_operator.py` — separate Unix IPC
  operator lookup, enforcing the gateway daemon's Linux peer UID;
  only `lookup` exists. The Auth0 subject must originate from a
  trusted OAuth-verifying caller and be authorized for `device_enroll`.
  This socket does **not** expose confirm/approve/root/activate actions.
- `src/ai_lab_gateway/server.py` — proposed MCP tool
  `pairing_lookup_code(code)` is **feature-gated off by default**
  (requires `AI_LAB_DEVICE_CODE_MCP_ENABLED=1` and a separate verified
  operator socket). It still requires the real Auth0
  `gateway:control` scope + per-operator `device_enroll` policy.
  Do not enable on the production service before its IPC is deployed.
- `scripts/run_device_code_lab.py` — non-root **loopback-only** staging
  runner with 0600 HMAC secret, SQLite and private local operator socket.
  Requires explicit `--lab-only`, has no Auth0 front end and must never
  be exposed directly on the Internet.

**Acceptance evidence:** in the existing WSL
`/home/ai-gateway/device-code-lab`, 26 tests passed, including subprocess
client/server interaction, HTTP rate limiting, key proof, guessed/stolen
codes, remote HTTP rejection, Unix peer-UID rejection, protected local
secrets and absence of MCP self-approval.

**Important boundaries still open:**
1. Signed/version-pinned Linux installer that can prepare virgin
   Linux (OpenSSH server/host key, management user and service).
2. New device API deployed on Oracle with trusted proxy client identity,
   defense-in-depth rate limiting and authentication/monitoring.
3. Protected operator IPC installed, Auth0 MCP lookup tool enabled,
   and **independent host-attested explicit human consent** before any
   `confirm` is exposed to an AI caller. The current web approval may
   remain as fallback while that is unresolved.
4. Narrow SSH credential delivery/provisioning, candidate tunnel,
   successful new `exec/read/write` end-to-end, atomic registry
   update, old-credential revocation and negative tests.
5. A real no-previous-SSH Linux enrollment test before declaring
   the onboarding production-ready.

**No Oracle production Caddy/SSH/systemd/registry changes were made for
this checkpoint.** WSL v1 still uses port 10002; staged v2 port 10003
has not been activated.


## Implementation refinement — two short codes, no second browser login

**Experimental mechanism implemented 2026-10-15; UX/security review still
required before production.** On a previously unknown Linux terminal,
the bootstrap client displays two independent values:

```text
AI Lab Gateway — Vincular dispositivo
Código: K7M2-P9Q4             # Example only: lookup by Auth0 MCP
Confirmação: 8H6P-L3SK       # Example only: target-terminal secret
No ChatGPT: Conectar dispositivo K7M2-P9Q4
Aguardando autorização...
```

The authenticated ChatGPT MCP operator provides the **first** code to
`pairing_lookup_code(code)`. The response includes device name,
request_id, Restricted mode, persistence preference, tunnel and host
fingerprints, but **never** the second code, signed challenge, device
secret or private SSH key. The user compares the fingerprint/details
with the Linux they are physically using. ChatGPT asks the person to
type the second code shown **only on the target terminal**. The user
sends it in the chat; the model invokes
`pairing_confirm_code(request_id, confirmation_code)` with its real
verified Auth0 identity and `gateway:control` + `device_enroll` grant.

The backend stores only an HMAC digest of the second code, binds it to
the exact request and OAuth subject, enforces 10-minute expiry, and
permanently denies after **four** bad confirmation attempts. This is a
bounded proof of access to the target's terminal, rather than a model
asserting that the user typed "yes". It works when ChatGPT runs on a
*different computer* or phone, without a separate admin-panel password.

Security assumptions and boundaries: a stolen/phished terminal code
can still authorize a device for an authorized operator who submits it.
Display request details and insist that the person reads the second
code from the intended device; never accept it from a retrieved web
page, an untrusted tool result or the MCP lookup response. The browser
approver remains available as a higher-assurance administrative
fallback. This only approves enrollment identity; SSH provisioning and
status=active are separate operations, and sudo is never granted by
pairing.

**Staging implementation status:**
- `src/ai_lab_gateway/device_code.py` stores `confirmation_digest`
  (not plaintext) and a durable `confirm_failures` counter, discloses
  no confirmation in `lookup`, and accepts confirmation only from the
  bound principal.
- `src/ai_lab_gateway/device_code_operator.py` exposes two exact
  Unix RPC actions, `lookup` and `confirm`, with `SO_PEERCRED`
  UID enforcement; neither can provision SSH or grant root.
- `src/ai_lab_gateway/server.py` prepares
  `pairing_lookup_code` and `pairing_confirm_code`, both behind
  `AI_LAB_DEVICE_CODE_MCP_ENABLED=1` (**OFF BY DEFAULT**) and
  `gateway:control`/device_enroll authorization.
- `src/ai_lab_gateway/sshsig.py` verifies the signed OpenSSH SSHSIG
  challenge. Linux `scripts/device_code_pair_linux.py` uses Python
  3.10+ stdlib + the local OpenSSH `ssh-keygen -Y sign`, without
  extra Python cryptography packages or an already configured sshd.
  It generates *separate* local tunnel and host Ed25519 identities,
  plus a stable, randomly suffixed device identifier.
- `scripts/install_ai_lab_device.sh` downloads the exact CLI source
  from immutable Git commit `536f5e1ce5fa885d9aa1d757182a01c10d751ae5`
  and checks SHA256
  `c25b3ad332c439e49aa9946cd0fd1330c68b979ed34237a6665e88627f8594d3`
  before nonroot execution. It is an **experimental HTTPS bootstrap**,
  NOT yet available from the proposed permanent `/install.sh` URL.
  HTTPS authenticates the first-stage bootstrap origin; the embedded
  hash authenticates the pinned downstream client relative to that
  bootstrap. A separately verifiable release signature and formal
  distribution/release process are still pending.

**Evidence:** 35 automated tests passed on the current WSL
`/home/ai-gateway/device-code-lab`, including a subprocess
fresh-home download without existing SSH keys, Python `-S`
(no site packages), real `ssh-keygen -Y sign` verification,
Hash mismatch refusal, Auth0-bound Unix lookup, retyped second
terminal PIN approval, four persistent failed attempts, replay
prevention, and no remote root privilege.

**Outstanding critical blockers:** There is **no public production
`/pairing/device/start` service**, no live MCP confirm tool, and no
automatic SSH management-key delivery, tunnel activation or registry
cutover. The root-owned provisioner, real authenticated MCP deployment
and truly unconfigured target acceptance tests remain to be completed.
Keep WSL legacy port 10002 intact and staged 10003 inactive.
