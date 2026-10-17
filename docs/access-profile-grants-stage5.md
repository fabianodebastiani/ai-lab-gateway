# Stage 5 — Signed Linux access profile claims (isolated first increment)

**Status (2026-10-17): SOURCE + synthetic offline tests only. NOT DEPLOYED, NOT a sudo grant and NOT a finished device-local security boundary.**

This work follows ADR-027 and the canonical document [device lifecycle](device-lifecycle-and-privileged-execution.md); Stage 5 is tracked in [Issue #11](https://github.com/fabianodebastiani/ai-lab-gateway/issues/11). The first live single-use supervised root success belongs to [draft PR #10](https://github.com/fabianodebastiani/ai-lab-gateway/pull/10). That mechanism stays separate, unchanged, and working.

## Product contract (unchanged)

Exactly three access profiles are selectable **after** pairing a device:

| Profile | Intended policy | Stage-5 prototype |
| --- | --- | --- |
| Restricted | Enrollment default, no standing sudo. Individually approved, signed one-use operations remain available independently | Signed Restricted claim evaluates to Restricted; no sudo pathway |
| Partial | One time interval: 15, 30, 60, 120, 240, 480 or 1440 minutes (default 30) | Signature, time, device, expiry and simulated revocation checked; only a harmless diagnostic capability appears in metadata, without executing anything |
| Unrestricted | Separate, high-risk human opt-in on an isolated/trusted lab device until revoked | Signature can be verified, but always evaluates to **Restricted** in the prototype; no unlimited root |

Single-use exact-command approval is NOT a fourth access profile. SSH connection status and systemd persistence are also separate.

## New isolated source

The module [signed_profile_grants.py](../src/ai_lab_gateway/signed_profile_grants.py) currently provides:

- Versioned JSON envelope with precise required fields, duplicate-key rejection, payload length bound, strict expected device and authenticated OAuth subject, fixed capabilities, approved method label, generation ID, approved durations and expiration.
- Detached Ed25519 verification over canonical JSON with a protocol-specific domain separator. The 32-byte trusted public key is supplied by an external trusted local actor, **never learned from the authorization packet**.
- Pure assessment against caller-supplied root-owned revocation generation, revoked grant identifiers and trusted clock floor. The module **does not** create or persist this trusted state.
- Expired Partial grants fail closed. A moved-backwards clock relative to the supplied trusted floor fails closed.
- Unrestricted is **not enabled**. Partial means diagnostic metadata only; the returned result is not an executable privilege, and cannot confer sudo.
- Human approval provenance is a signed assertion by the future issuer. The code does not prove the human actually approved anything; that independent confirmation must occur **before** a trusted issuer signs.
- No issuer service, private key, root executor integration, MCP endpoint, shell access or Linux sudoers mutation.

**Protocol separation:** signed profile grants use a distinct Ed25519 signing domain and will require separate, locally pinned trust provisioning. Never reuse the existing single-use SSHSIG issuer without explicit reviewed migration and tests.

## Security decisions needed before ANY installation

1. **Consent and identity:** independently authenticated human confirmation tied to exact device, profile, duration, operator, and rationale. A chat button or Boolean supplied by the model is not approval.
2. **Root-owned state:** persist and fsync per-target revocation epoch, grant generations, revoked IDs and trusted clock watermark under restrictive ownership, with concurrency and rollback protection. This prototype's passed-in state is **not a substitute** for local enforcement.
3. **Trusted clock:** simply storing the last seen wall-clock time does not prevent restoring an old disk snapshot AND old clock. Define secure time attestation and a fail-closed recovery mechanism. Verify reboot and offline expiry.
4. **Offline revocation:** a target disconnected from the Gateway cannot immediately learn about a revoke. Proposed approach: a long requested Partial window but only short, at-most-300-second renewable execution leases; fresh Gateway consent/policy verification before new privileged work after that lease. Disconnected targets stop accepting new privileged work at the end of the short lease. This is a **proposal, not implemented**.
5. **Unrestricted semantics:** determine separately whether arbitrary shells are appropriate at all. A shell can launch background processes and make persistent changes that survive expiration. Never grant generic wildcard NOPASSWD sudo to the management user.
6. **Acceptance and rollback:** synthetic/root-only CI first; then only the disposable second Oracle with explicit original local administrator approval. Test target-side nonce/replay after restart, denied wrong device/subject, expiring grants, offline revoke, races, clock rollback, audit, rollback and unchanged Raspberry/WSL.

## Tests

Run: python -m pytest -q tests/test_signed_profile_grants.py

The 45 local tests use disposable, in-memory Ed25519 keys and deterministic timestamps. They do not touch root, SSH, Auth0, Oracle, real signing keys or service policies. A dedicated GitHub workflow repeats these tests on each relevant PR/push.

**Next incremental implementation:** root-owned state and short renewable lease verification in synthetic fixtures only; then a separately reviewed issuer backed by independent consent, MCP operations, and eventually a narrowly deployed target executor on the disposable Oracle.

Until those layers exist, these profile grants are **design and parser evidence, not administrative access**.


## 2026-10-17 — Increment 2: root-local revocation and short signed leases (isolated)

**SOURCE/TESTS ONLY; still NOT installed on any managed Linux device, not exposed by MCP, not a general root executor.**

Added [profile_lease_state.py](../src/ai_lab_gateway/profile_lease_state.py) and [test_profile_lease_state.py](../tests/test_profile_lease_state.py). This increment completes the first *synthetic proof* of durable root-state bookkeeping and separately verified short-lived lease metadata, without granting execution capabilities.

### Verified scope

- **Lease verification:** separate Ed25519 signing domain, canonical signed envelope and exact binding to device, expected OAuth subject, signed Partial grant ID/generation, harmless allowlisted capability, current Linux boot ID and issue/expiry timestamps. Lease duration is **at most 300 seconds** and cannot extend beyond its parent grant's expiry. Invalid signature, altered data, wrong device/subject/boot, oversized TTL and missing fields fail closed.
- **Root-local protected state prototype:** root-owned 0700 directory and 0600 regular files, no-follow file opening, immutable file ownership/mode checks, bounded strict JSON, flock serialization, atomic replacement, file/directory fsync, persistent revocation by grant ID or generation and non-decreasing recorded wall-clock watermark.
- **Startup/recovery:** initial state is deny-by-default until an original *local* root administrator creates a protected directory and initializes it. Re-initialization is rejected. **After reboot or Linux boot ID change, checks fail closed until an independently reviewed recovery/rebinding mechanism is developed**; this is not the final operational restart experience.
- **Evaluation:** two signed artifacts (profile grant and short lease) are independently verified against root-local state before the module reports Partial diagnostic metadata. Revocation immediately changes that local assessment to Restricted. This module does NOT execute commands, install a sudo rule, modify the PR #10 executor or create a working Partial privilege.
- **Separate lifetime:** short leases are intentionally renewable/multi-use *metadata* within their lifetime, not one-use sudo vouchers. To execute as root, the separately signed exact-command mechanism (PR #10) would still have to enforce a privileged operation. The actual lease issuer, refresh/renewal path and execution integration are **NOT implemented**.

### Tests and reproducibility

- The 45 original synthetic signed-profile tests are retained.
- The new tests cover 43 synthetic cases including Ed25519 lease validation, wrong subject/boot, expiry, local revocation persistence, concurrent writers, malformed/symlink/untrusted root state, clock regression, short-lease expiration and the **full cryptographic chain** with both grant and lease signatures.
- Run the 45 unprivileged tests with python -m pytest -q tests/test_signed_profile_grants.py.
- Run the new root-filesystem tests **ONLY on a disposable test runner**, for example the root-only GitHub Actions job. They MUST NOT be run on the production Gateway or user devices. The tests create only temporary synthetic files and random test keys.
- GitHub workflow .github/workflows/profile-grant-lab.yml now has two separate jobs: unprivileged profile parser tests and root-owned state tests on a disposable Ubuntu runner.

### Known security boundaries / blockers before deployment

1. **Offline immediate revocation is impossible** for an already issued valid lease without contacting an authority or receiving revocation information. The prototype bounds a signed short lease to 300 seconds; an offline target may still evaluate the previous lease until it expires if its local trust state has not learned about the revoke. Issuer policy rechecks before lease renewal do not exist yet.
2. **Wall-clock + state file is not a secure clock.** A system-clock change alone is detected when the stored floor exceeds the new value. A disk snapshot rollback combined with a matching clock rollback is *not* detected. Define trusted time / rollback protection and documented fail-closed recovery before attaching real privileges.
3. **No boot reconnection protocol:** current root-local prototype rejects a new boot ID. Fresh independent authorization and strictly monotonic revocation generation must be required before rebinding after reboot; neither procedure is implemented.
4. **No issuer and no independent human evidence** is added here. The module verifies a signing authority's attestation but does not itself confirm that a person consented; that must be handled at the trusted issuer.
5. **No unrestricted administration:** a signed Unrestricted claim still evaluates to Restricted, and this increment does not expose shells, apt, services, file mutation or wildcard sudo. Broad access would require a separate, explicit high-risk design and acceptance protocol.
6. **No deployment approvals implied.** Keep PR #12 Draft and separated from PR #10. Audit, replay, restart/rollback and root enforcer integration remain required before enabling anything on the second Oracle.

**Next:** independently human-approved issuer for short leases and root-controlled renewal after checking the current profile/revocation; prototype a minimal signed/verified grant installation and audited metadata-only MCP status before connecting to any privileged executor.


## 2026-10-17 — Increment 3: independent-approval issuer + device-signed renewal (source only)

[profile_lease_issuer_lab.py](../src/ai_lab_gateway/profile_lease_issuer_lab.py) and [test_profile_lease_issuer_lab.py](../tests/test_profile_lease_issuer_lab.py) introduce a **separate, isolated** signing and renewal prototype. It does not modify the production privilege broker, any Linux executor, MCP scopes, sudoers or device configuration.

### Protocol and state transitions

1. A separately held **independent human-approval Ed25519 key** signs a short-lived, exact Partial-profile consent assertion containing the device, authenticated user, approver identity, duration, fixed diagnostic capability, decision nonce, confirmation and time window (max 120 seconds).
2. The lab issuer checks that **signed assertion**, bound device, caller-supplied authenticated subject and trusted verifier key. It rejects approvals with the wrong signature, extra privileges, an unrecognized profile, stale time or a repeated decision ID. A code caller cannot simply claim that a chat message constituted human approval.
3. Only then does the issuer sign a separate Partial-profile grant. The issuer has a different Ed25519 private key from the approval authority and device.
4. For each lease renewal, the device submits a fresh **request signed by a pinned device-specific Ed25519 key**, bound to the grant, subject, generation, short-lived request ID, diagnostic capability, boot ID and timestamp. A valid signed request proves key possession, but **does not independently prove the actual kernel boot ID**; the protected executor on the target must check that it matches the target's actual boot ID.
5. A root-only SQLite ledger rechecks the stored, signed original grant, expiry and current revocation status before signing each lease, then atomically consumes the device request nonce. Concurrent identical requests yield only one successful issuance. A new nonce can renew a still-valid grant, but never past its parent expiry.
6. Revoking a grant or revoking a device generation prevents **subsequent renewal**. Independently human-approved new grants receive a strictly higher generation than revoked generations. The issuer persists state with SQLite transactions and FULL synchronous mode.

**Strict scope:** the issuer only permits Partial with diagnostic root-identity-check metadata; it does not execute that command. Restricted remains the default and Unrestricted is disabled. The existing single-use sudo flow from PR #10 is unaffected.

### Guarantees deliberately NOT claimed

- The signer for independent human consent currently exists **only as a disposable synthetic CI key**. There is no real human Auth0/terminal consent flow for profiles yet; cryptographic validation of a synthetic approval is not evidence that a person actually approved it.
- Authenticated OAuth subject is a trusted integration input to the issuer in this prototype. Its provenance must be validated at the eventual MCP boundary; caller-supplied chat text cannot be accepted.
- The target-specific device signing key for renewal is also synthetic. Future target key provisioning, approved host binding and compromise/recovery procedures are pending.
- **Offline revocation is not instantaneous:** a previously signed lease is still locally valid until it expires (up to 300 seconds), unless the target receives a separate valid revocation update. The issuer cannot reach backwards and invalidate it merely by changing the SQLite ledger. CI includes a target-local demonstration of this exact limitation.
- SQLite FULL synchronous transactions do not protect a reverted disk snapshot with a simultaneously rolled-back clock. A stronger trusted-time/recovery architecture is still required.
- No root shell, package-management operation, generic sudo or broad administrative access is exposed. A signed renewal lease is NOT an independently usable root voucher.
- This lab issuer is **not deployed**, lacks a production service/IPC/authenticated approval adapter, and has no ability to create or update real device privileges.

### Acceptance strategy

The GitHub Actions workflow includes a third isolated job for this issuer. It tests independent approval signatures, wrong device/subject, device challenge, grant renewal, nonces after process reopening and under eight concurrent workers, monotonic revocation, issuer clock rollback, and full cryptographic grant + lease verification against synthetic root-local target state. Root filesystem tests run only on disposable Ubuntu CI runners.

**Next increment:** review production-independent consent integration and safe target boot/key attestation, audit and recovery; design authenticated local revocation delivery and lease renewal transport as source-only, then consider a supervised disposable-VM deployment only after all remaining PR #10 security checks are closed.
