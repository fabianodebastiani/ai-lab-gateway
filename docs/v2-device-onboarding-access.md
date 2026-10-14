# AI Lab Gateway v2 — Enrollment + Access Manager (product contract)

Status (2026-10-14): approved requirements, implementation in progress.
This supersedes any UX mockups that presented duration as multiple radio options.
No part of this document claims a deployed enrollment API or remote sudo grant.

## Product decision — 2026-10-14: enrollment always starts restricted

**Accepted decision:** Pairing a device and granting elevated Linux privileges
are independent workflows with different lifetimes. **All newly paired devices
must start in Restricted mode.** The initial device-pairing screen shall NOT
ask the operator to choose Restricted / Partial / Unrestricted. Device
enrollment does require an explicit confirmation of the *device identity*
before adding a trusted connection, but that is not authorization for sudo.

This decision supersedes earlier text that required choosing an access
profile during onboarding. It avoids accidental root privileges and makes
onboarding substantially simpler. Mode changes are requested *after pairing*,
on demand, with an authenticated authorization flow.

## Simple device enrollment — one-time pairing

1. An operator runs one guided installer on a new Linux target, with
   minimal prerequisites (OpenSSH, Python or shell, outbound HTTPS/SSH).
   The device creates its own tunnel private key locally; this key never
   leaves the device.
2. The device establishes a short-lived, single-use HTTPS pairing request.
   The gateway creates a separate per-device management key and keeps the
   private half on the Oracle gateway.
3. The operator checks the new device's identifier, reported identity and
   host-key fingerprint and confirms **pair this device**. The confirmation
   authenticates the new device — it does not elevate its privileges.
4. Enrollment provisions the registry/policy, device-specific SSH public
   keys, loopback-only reverse listener, pinned SSH host identities and
   persistent reconnecting service in a fail-closed, auditable way.
5. Only after identity verification, bidirectional SSH and negative
   permission tests does the device appear in MCP as **Restricted**.
   An incomplete pairing cannot accidentally enable sudo.
6. From this point, normal permitted operations are available without
   asking for administrative approval. A request for elevated permissions
   can be made later if a task needs them.

**Enrollment invariant:** no onboarding API argument, token or missing field
may cause a newly enrolled device to start as Partial or Unrestricted. The
initial mode is a server-enforced constant, not just a selected UI default.

## On-demand access changes — exactly three radio buttons

Only after the device is registered, an operator can request a change to its
effective access. This may happen during an MCP task, when a command needs
administrative privileges, or from a device-management page.

There are **exactly three radio options**, not four (duration is not a
separate radio option):

- **Restricted / Restrito:** normal isolated Linux management account,
  no general administrative sudo. Default at enrollment, and the state
  returned to after temporary access expires.
- **Unrestricted / Irrestrito:** explicit, high-risk opt-in for broad root
  administration on one specific lab device, remaining until revoked.
  Never implicit, never enabled on the Oracle or any other device merely
  because a new device is enrolled.
- **Partial / Parcial:** administrative capabilities available for the
  chosen **duration**. Only when Partial is selected is a dropdown shown:
  **15 min, 30 min, 1 h, 2 h, 4 h, 8 h, 24 h**. The default choice for a
  newly requested partial grant can be 30 minutes. Once the deadline is
  reached, the enforcing device-side component refuses **new** privileged
  commands and the effective mode becomes Restricted.

Example desired interface:

```text
Raspberry Pi Lab: administrative access requested

( ) Restricted
( ) Unrestricted
(x) Partial
    Duration: [ 30 minutes ▼ ]

[Confirm authorization] [Cancel]
```

The confirmed mode belongs to the selected **device**, not to the Gateway
in general. The UI should display the active profile, remaining time where
applicable, who approved it, last change, and an early-revoke action.
Changing the connection or re-enrolling the device is never required.

### Approval and Google Authenticator

The preferred experience is an operator confirmation surfaced within the
ChatGPT task. However, a simulated chat button is *not by itself* a secure,
authenticated grant. We must verify whether the ChatGPT/MCP host provides a
suitable approval API that binds the consent to a user, operation, device and
time. If not, a short, authenticated HTTPS confirmation step is needed.

The existing password + Google Authenticator panel is a reusable optional
step-up and administrative recovery mechanism. It is **not** a requirement
for every normal command, every sudo command during an active partial
window, or the initial device enrollment. Higher-risk Unrestricted grants
may use stronger confirmation.

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

A. **Three-profile contract** — model Restricted, Partial and Unrestricted,
duration validation, automatic expiry to Restricted, and regression tests.
Pure domain logic exists in `src/ai_lab_gateway/access_profiles.py` and
`tests/test_access_profiles.py`; this does NOT implement target-side sudo.

B. **Restricted-first enrollment** — device installer, HTTPS pairing API,
short-lived one-use code, verified device identity, gateway-side registration,
dedicated SSH trust and tunnel automation. The pairing API must force
Restricted regardless of client input. Validate on a test Linux device.

C. **Device-local privilege enforcement** — root-capable target helper,
grants and revocation, one explicit Unrestricted opt-in, Partial expiration
after restart or network interruption, deny-by-default tests and audit.
Privilege changes must be bound to approved operator/device/scope.

D. **Approval experience** — exactly three radio controls during an
elevation request, dropdown only for Partial, authenticated human
confirmation, visible countdown, and immediate revoke option.

E. **End-to-end acceptance** — add a fresh Linux with one setup command,
prove it starts Restricted, request Partial for 15 minutes, validate access
before/after expiry, revoke, try Unrestricted on a disposable test device,
then ensure the existing Raspberry/WSL/Oracle devices are unaffected.

Do not declare enrollment or privilege administration complete before
B–E are validated on real devices.

## Prerequisites before installing live components

- **Available now:** GitHub repository and connector, operational MCP/HTTPS
  and SSH reverse tunnel, existing Oracle privilege broker, approved product
  direction, and a dedicated test suite.
- **Oracle privileged deployment:** the temporary unrestricted sudo grant
  was automatically revoked. Root-owned services, pairing listener routing,
  keys and system policy require **a new, explicitly approved installation
  path** using the Oracle `ubuntu` administrative recovery account.
  No permanent wildcard sudo for `ai-maintenance`.
- **Test Linux target:** preferably a disposable VM or spare Linux/Raspberry,
  where an operator has local sudo for the *one-time installer*, and Internet
  outbound HTTPS/SSH. A simulated test can precede it; do not risk the
  existing Raspberry and WSL as the first real enrollment.
- **Proof of human authorization:** choose and verify a native MCP/client
  confirmation capability if available, otherwise adapt the existing web
  approval. A model-written message must not be trusted as approval.
- **Safety:** snapshots/backups, logging and rollback of registry/keys;
  negative tests proving that Restricted cannot run arbitrary sudo.

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
