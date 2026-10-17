# AI Lab Gateway — lifecycle of a Linux device and supervised root execution

**Canonical product architecture — 2026-10-16; approved for incremental implementation.**
Use this document together with ADR-027 (access profiles), ADR-028 (connection
persistence), ADR-029 (one-code enrollment), and issue #2 (operation-specific
privilege approvals). An update must state exactly what it supersedes; a later
document that only covers profiles does **not** silently discard single-use
approvals.

## Invariants retained from previous decisions

1. A human authenticated to the ChatGPT MCP through Auth0 (possibly using a
   Google account) asks ChatGPT to connect a *previously unknown* Linux device.
   ChatGPT supplies one stable, **public, credential-free HTTPS** installation
   command. The user runs it **locally**, in a normal login that can invoke
   sudo for one-time OS preparation. Never run unverified remote shell as
   root; version-lock artifacts and verify trusted hashes/signatures.
2. The target initiates outbound **HTTPS**, generates an independent local
   Ed25519 tunnel identity, and displays **one eight-symbol code grouped 4-4**.
   The user enters the code into ChatGPT. The authenticated, independently
   confirmed human authorizes **this exact device**. The Gateway provisions
   a dedicated SSH management public key, pins both SSH host identities, and
   provides a loopback-only reverse SSH offer. The target connects outbound;
   only verified Restricted devices appear in MCP.
3. The local one-time sudo setup creates/verifies the Linux `ai-gateway`
   non-admin account and OpenSSH prerequisites; it also installs the local
   `ailab` connection manager and the separately owned **root executor**
   once the executor package is independently audited/validated. Installing
   an executor **does not grant its use**: it must start disabled/deny-all.
   No root SSH credentials are uploaded to the Gateway or Git.
4. Gateway -> target management SSH always uses `ai-gateway`, which has **no
   general sudo**; tunnel identity and management identity stay separate.
   Login as the local Linux administrator is only a one-time installer or
   recovery mechanism, **not** another MCP admin SSH session.
5. Distinguish (a) local SSH **connection state**, (b) **startup/persistence
   preference**, (c) **device access profile**, and (d) **one-use operation
   approvals**. They have separate lifetimes and permission checks.
6. A second device/user cannot obtain permissions from the first one's
   pairing code, key, Auth0 subject, connection state, or sudo approval.
   Existing tunnels and the Oracle Gateway's own administrative account
   are not to be modified by the first rollout.

## Connection experience: one local `ailab` command

Commands the operator can run *on the Linux device* after its initial pairing:

```text
ailab status
ailab connect
ailab disconnect
ailab persistent on
ailab persistent off
```

- `connect` starts the device-owned reverse SSH tunnel; when one is already
  healthy, do nothing. `disconnect` stops the current connection only.
- `persistent on` enables a verified device-owned **systemd --user** unit
  for automatic start when Linux/the user's systemd manager starts, and
  automatically reconnects after network drops. `persistent off` disables
  **startup** but intentionally does not kill the active tunnel. Both
  operations apply equally to all Linux types. `enable-linger` may be
  needed and is performed only with the original local admin approval.
- On-demand can still retry a connection failure **while the unit is alive**;
  this is different from coming up after a reboot. For WSL, systemd
  persistence cannot start Windows or wake a sleeping computer.
- These *local* connection commands require **no general sudo** and control
  **only the current user's registered AI Lab tunnel unit**, never arbitrary
  host services. A separate **MCP** ability to change persistence still
  requires explicit `connection_manage` per-device authorization; `exec`
  alone is not permission to change remote persistence.
- A disconnected device cannot be restarted *from that same sole SSH tunnel*
  by ChatGPT. `ailab connect` on the Linux console or an independent
  out-of-band mechanism is required.

## Privileged executor: a separate trust boundary, not a new admin SSH user

The installer, while **locally** authorized with sudo, installs a root-owned,
immutable program or narrowly scoped root service. A practical thin initial
design is an executable with a **single exact sudoers allowance** for
`ai-gateway`, *only* for the fixed executor path. The executable then
validates a verifiable, signed authorization issued following **independent
human consent** before doing any privileged action. An alternative Unix
socket/root service is acceptable if tests justify it; either way, no
standing `NOPASSWD: ALL`, generic `sudo bash`, command-shell trampoline,
or downloadable arbitrary command handler is permitted.

The normal MCP `exec` remains a nonroot SSH command. A **different,
permission-gated MCP operation** requests privileged execution. The executor
must validate:

- device identity, verified Auth0 user/approval authority, specific privilege
  scope, **exact program and arguments** (and relevant file contents/digests),
  expiry against the device clock and cancellation/revocation;
- a cryptographic proof distinct from model text, pair-code possession and
  ordinary OAuth client authorization;
- nonce/idempotency in a **root-controlled, fsynced, concurrency-safe**
  used-authorization store to prevent replay even across restarts;
- fixed executable policy, no symlink escapes, shells, script launchers,
  uncontrolled package hooks, file writes or other root escape through
  deceptively simple commands.

**Single-use authorization** is a FIRST-CLASS workflow even though the
**persistent device access profiles remain exactly three** under ADR-027:

- **Restricted:** no privileged execution without an explicit,
  independently verified **one-time, exact-operation approval**.
- **Partial:** allow approved administrative capability on *that* device
  for one selectable interval (15, 30, 60, 120, 240, 480 or 1440 minutes;
  default 30). Check the effective expiry on *each newly started* operation,
  including without a current browser session or Gateway connection.
- **Unrestricted:** a separately and strongly confirmed opt-in on a
  disposable/trusted lab device until revoked. Clearly display risk.
  The device still routes through the auditable executor; no unrestricted
  permissions to Oracle or any other device by implication.

Thus the three-radio **profile chooser is not replaced**, and a one-time
approval is **not a fourth persistent profile**. A one-time approval can be
requested while the selected profile remains Restricted. Both support
audit and explicit revocation. Approving a single operation may be more
convenient/safer than opening a 30-minute window. A command that itself
launches root shells, long-lived background processes or arbitrary programs
cannot honestly be called *narrow* merely because its token was consumed
once; such actions need stronger confirmation or prohibition.

Expiry prevents **new** privileged work, not necessarily processes already
running, and cannot reverse changes made while root was available.

## Explicit intentional additions / reconciliations

| Earlier material | Status after this decision |
| --- | --- |
| ADR-027: 3 modes, single duration dropdown for Partial | **Preserved**. One-use exact-command approval is orthogonal, not a fourth radio mode. |
| Issue #2: one-use signed broker and operation-level approval | **Preserved** and promoted to canonical. Its five early *role types* are superseded by ADR-027 three profiles, **not** its one-use security requirement. |
| ADR-028: connection persistence is per-device Boolean | **Preserved**. Local `ailab` CLI adds ergonomics, no alteration to OAuth remote policy. |
| ADR-029: one-code, no second login, Restricted-by-default | **Preserved**. Add local tooling during same trusted initial sudo phase; device identity approval never implies root. |
| Original experimental root broker on **Oracle** | **Retained separately**. It permits a tiny fixed Oracle allowlist; it does not itself implement arbitrary sudo on SSH-managed targets. |
| Existing one-code installer on PR #8 | **Live E2E on a fresh Oracle VM**, but does not install root executor and currently starts an on-demand **transient systemd --user** tunnel. Persistent/user CLI integration requires staged implementation/tests. |

## Incremental rollout, verification and recovery

1. **Docs and pure code** first; no privilege changes. Verify existing
   on-demand live unit and test a safe local `ailab status` with no sudo.
2. Develop `ailab` local connect/disconnect/startup preferences using
   pinned on-device configuration. Never stop an established tunnel remotely
   as the first test. Validate on disposable Linux / second Oracle VM.
3. Develop privileged executor and restricted installer separately. Use
   synthetic one-use signatures, negative tests, replay/races/expiry,
   symlink/file-owner checks, argument injection and restart. Deploy to
   second Oracle using an **explicit human local sudo operation** only
   after package verification; no user-side permanent root privileges.
4. Test a **harmless allowlisted root-only operation** with independent human
   consent: deny by default -> execute once -> replay denied -> new
   operation denied -> expiration/revocation -> restart/reboot denied.
   Then test time windows, and only later Unrestricted on a disposable VM.
5. Preserve rollback, original `ubuntu` local admin access, old tunnels,
   keys and Auth0 policy. Do not merge claims of production readiness before
   real MCP tests show correct privilege boundaries.

## Public Git and installation source (verified 2026-10-16)

GitHub reports `fabianodebastiani/ai-lab-gateway` has
`visibility=public`. The existing bootstrap downloads version-pinned
source from public `raw.githubusercontent.com` over HTTPS and checks
SHA-256; no GitHub login/token is needed on the target. The target never
downloads *secrets* from Git. A friendly future installation URL at
`https://gateway.debasti.com/install.sh` is a **planned** release surface,
not currently verified as deployed. It must serve only signed/versioned,
independently integrity-checked installer content and must never inject
dynamic privileged shell from the enrollment endpoint.

## 2026-10-16 — draft privilege integration checkpoint (NOT deployed)

[Draft PR #10](https://github.com/fabianodebastiani/ai-lab-gateway/pull/10)
now contains: root-only signer integrated into the **existing independent human
password/TOTP approval socket**; a separately protected, explicit
per-device issuer allowlist; device-local one-use signature verifier;
a feature-gated OAuth/per-device MCP privilege request/execute flow that
streams the signed voucher through SSH stdin **without revealing it
to the model**; two *local-admin-only* bootstraps with digest/fingerprint,
visudo checks and rollback; synthetic CI and legacy broker/web regressions.

**Do not confuse these repository artifacts with live capabilities:**
no production Oracle signer key has been provisioned, no target sudoers
rule has been activated, no Auth0 target privilege permission has been
granted, and no real human-approved target root execution has occurred.
The only live second-VM privilege test remains **denial** as the ordinary
ai-gateway user. Maintain PR #10 as draft until independent review,
approved local-admin installation and end-to-end testing.

The three profiles remain Restricted/Partial/Unrestricted. Single-use
exact-command approval is still an orthogonal privilege mechanism.
A previously issued signed voucher cannot yet be remotely revoked on an
offline device; current isolated voucher lifetime is capped at 300s.
Immediate post-issuance revocation is a future acceptance requirement.

## 2026-10-16 — live sudo supervisor rollout: installed, NOT yet E2E approved

**Human administrative actions completed on the two Oracle VMs:**
the original local `ubuntu` account installed the root-owned approver
signing key and one-device allowlist on `ai-lab-gateway-01`, then the
restricted target executor and exact `sudoers` no-arguments rule on
`ai-lab-experiments-01`. The original Oracle administrator also ran
the reviewed transactional broker/web/MCP rollout and received
`AI_LAB_GATEWAY_ROLLOUT_COMPLETE`, with all three services active.

**Independent live MCP observations:** Gateway status ok, Caddy and approval
health ok; new `AI_LAB_TARGET_PRIVILEGE_MCP_ENABLED=1` flag present;
the second VM is online and its SSH tunnel active; unrestricted `sudo id`
is still denied; invoking the protected target executor with an empty or
invalid voucher denies (code 77).

**Blocking the final positive human-approved root test:** This chat's
connected AI Lab Gateway MCP tool catalog remains the previous version and
does not yet expose the four new target privilege tool names. Source code
is running on the Gateway, but current ChatGPT connector discovery has not
refreshed. Do **not** substitute old Oracle privilege tools, bypass human
TOTP approval via shells/SSH, or manufacture a voucher. Refresh/reconnect
the existing connector in ChatGPT (user action; start a new conversation
if needed), then complete one genuine `root-identity-check` approval
and one-use execution. User must not share passwords, TOTP or keys in chat.

Source, reviewed installs, exact public signing fingerprint, backups,
rollback and acceptance checklist live in
[PR #10 runbook](https://github.com/fabianodebastiani/ai-lab-gateway/blob/feat/target-single-use-privexec/docs/target-one-use-privexec.md).
This is **live installed, only negative security tested**. It must not
be described as positive authorized root E2E verified. The single-use
mechanism is separate from the three access profiles; later 15min–24h
and opt-in unrestricted modes and offline revocation are still pending.

## Publication discipline

This file is the canonical cross-feature contract. When any connected
implementation changes, **update the ADR cross-reference and this status**,
include exact deployment/test evidence, and distinguish *implemented in a
draft branch*, *merged to main*, *installed on Oracle*, and *E2E verified*.
Never claim a GitHub commit by itself grants real root capability.
