# AI Lab Gateway v2 — Enrollment + Access Manager (product contract)

Status (2026-10-14): approved requirements, implementation in progress.
This supersedes any UX mockups that presented duration as multiple radio options.
No part of this document claims a deployed enrollment API or remote sudo grant.

## One unified onboarding workflow

1. An operator runs one guided installer on a Linux target, with minimal
   prerequisites (OpenSSH, Python or shell, outbound HTTPS/SSH). The target
   generates its **own** tunnel key and never exports its private half.
2. It requests a pending pairing with the gateway over authenticated TLS,
   using an unpredictable one-time pairing credential. The gateway generates
   a distinct management key and keeps its private half exclusively local.
3. The operator reviews device identity/fingerprint, device name, source
   and capabilities. They choose an initial access profile using **exactly
   three radio buttons**:
   - **Restricted** (restrito): normal isolated Linux user, no administrative
     elevation; **default** on a fresh enrollment.
   - **Partial** (parcial): administrative access for a chosen time window.
     **Only this radio** reveals a duration dropdown. Initial options:
     15 min, 30 min, 1 h, 2 h, 4 h, 8 h, 24 h.
     After the deadline, new administrative commands are denied and the
     device reverts to Restricted automatically.
   - **Unrestricted** (irrestrito): broad administrative access on this
     specific experimental device until revoked. Explicit opt-in with risk
     description and visible revoke control; never the enrollment default.
4. Pairing approval causes atomic, verified provisioning of the gateway-side
   registry/policy, loopback-only reverse listener allocation, per-device
   tunnel public key restrictions, target-side pinned gateway host identity,
   per-device SSH management public key, and managed reconnecting systemd
   service. No private keys are copied between parties.
5. The device is listed by MCP only after identity verification, successful
   reverse SSH/management SSH, and required negative permission tests.
   A failed pairing remains pending or rolls back, with an audit record.

## Access change for existing devices

The identical three radios are shown when changing permissions on an
already-enrolled Linux, subject to operator/device authorization.
Partial shows the dropdown; other radios do **not** show any time selector.
The policy UI must display the effective profile, who authorized it,
remaining time, last change, and a one-click revoke action.

Possible ChatGPT request:
> The command needs administrative rights on raspberry-lab.
> ( ) Restricted   ( ) Unrestricted   (x) Partial
> [30 min ▼]    [Confirm] [Cancel]

This is a **UX concept**. A rendered ChatGPT button alone is **not** proof
that an authenticated human approved a privilege change. The gateway must
obtain verified and auditable operator consent via a host-provided MCP
confirmation capability (when actually supported and provably bound to the
requester), or through a minimal independent HTTPS approval flow.
Do not treat a model-generated message, unconstrained conversation text,
or an OAuth-authenticated AI-client token by itself as human approval.

Google Authenticator remains an available step-up factor, **not** something
the operator must enter before every normal command or each sudo command in
an already authorized partial window. High-risk unrestricted grants may
reasonably demand independent confirmation.

## Enforcement and safety boundaries

- Privileges belong to the **target device**, not to the Oracle cloud host.
  Target-side enforcement is mandatory; filtering chat text is insufficient.
- Default: a non-root management account with its own per-device SSH identity.
  Each device gets independent credentials, access history and revocation.
- A per-device root helper accepts authenticated, validated grants tied to
  the device, operator, scope and expiry. Normal MCP exec never has a
  standing shared passwordless sudo wildcard merely to implement the UI.
- Any temporary grant is checked at execution time against a trusted clock,
  and expires without ChatGPT, a browser session or a live tunnel.
- Changes to host sudoers, services and credentials must be transactional,
  auditable and recoverable; do not overwrite unrelated host files.
- Duration limits **new commands**; they cannot guarantee terminating
  commands already started during an allowed window. Full root control
  may create persistence, so revoking it cannot cryptographically guarantee
  removal of changes made while root was available.
- Unrestricted permissions are dangerous; the device should be explicitly
  designated as a disposable or trusted lab target. No unrestricted rights
  to Oracle by default, and no automatic propagation between devices.
- Existing raspberry-lab, windows-wsl, and oracle-gateway records must not
  be changed by the first rollout. Start with simulated pairing, then a
  dedicated test Linux target, then migration.

## Incremental acceptance milestones

A. Three-mode model, strict duration validation and expiration regression
tests, with restricted default. Source:
\`src/ai_lab_gateway/access_profiles.py\`, tests:
\`tests/test_access_profiles.py\`. Pure domain logic only: no system-level
privilege changes in this phase.

B. Device installer + pairing API + operator approval + device registry
transactions; complete end-to-end test with new Linux target.

C. Target-local privilege enforcement with restricted, partial (time-bound)
and unrestricted profiles; automatic expiration, logout/reboot recovery,
revocation and negative escalation tests.

D. UI integration: exactly three radio controls and only one dropdown,
linked to verified human approval. Human usability testing in ChatGPT.
At this point, the feature can be declared ready.

## Operational status observed

At 2026-10-14 02:23 UTC, \`ai-maintenance\` no longer had
\`sudo -n\` (returned "a password is required"); gateway, broker and web
service all remained active. This confirmed expiration of the temporary
Oracle bootstrap grant. Subsequent installation of root-owned components
requires a separate narrowly scoped administrative deployment operation;
do not silently recreate blanket sudo.

Related tracked discussions:
- Issue #1: simplified device enrollment.
- Issue #2: per-device access profiles and privileged operations.
- Issue #3: isolate tunnel identity vs management SSH vs filesystem access.
