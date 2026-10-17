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

- Versioned JSON envelope with precise required fields, duplicate-key rejection, payload length bound, strict device/subject identity, fixed capabilities, approved method label, generation ID, approved durations and expiration.
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

The 44 local tests use disposable, in-memory Ed25519 keys and deterministic timestamps. They do not touch root, SSH, Auth0, Oracle, real signing keys or service policies. A dedicated GitHub workflow repeats these tests on each relevant PR/push.

**Next incremental implementation:** root-owned state and short renewable lease verification in synthetic fixtures only; then a separately reviewed issuer backed by independent consent, MCP operations, and eventually a narrowly deployed target executor on the disposable Oracle.

Until those layers exist, these profile grants are **design and parser evidence, not administrative access**.
