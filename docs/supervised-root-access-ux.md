# Supervised privileged operations — simpler daily administration

**Status 2026-10-15:** implementation candidate on branch
\`feat/supervised-root-operations\`; no new privileged operation installed on Oracle.

## Problem observed

A manual one-hour root shell through \`ai-maintenance\` took ~40 minutes
of human terminal interaction: verifying SSH, discovering sudo policy,
finding the previous expired systemd timer, reviewing an old bootstrap
script, cleaning up its units, and re-arming root-wide NOPASSWD sudo.

The time-limited script did successfully grant broad access at
**2026-10-16 00:40:36 UTC**, with an independently scheduled removal of
the sudoers rule at **2026-10-16 01:40:36 UTC**. The actual MCP runtime
subsequently confirmed root UID 0 via \`sudo -n id -u\` and timer status.

That script is **recovery/bootstrap only**, not the normal UX. Broad
root sudo can create processes or persistence that outlive the timer.
Do not make it permanent, silently extend it, or give the AI access to
the human \`ubuntu\` recovery account.

## Already deployed and previously tested

- \`privilege_request\`, \`privilege_status\`, \`privilege_execute\`,
  \`privilege_revoke\` through the existing authenticated MCP app.
- Auth0 \`gateway:control\` and explicit \`privilege_request\` policy
  for the exact gateway principal and Oracle device.
- Root-owned \`ai-lab-privilege-broker\` with two separate Unix sockets
  and peer-UID checks.
- Independent browser approval at
  https://gateway.debasti.com/approvals, protected by a human-only
  password, authenticated session, CSRF and per-decision TOTP.
- Operation allowlist, one-use execution, persistent consumption
  before execution, subject binding, expiry and root-only audit.
- Full end-to-end web-approve -> MCP-execute -> replay-denied was
  confirmed previously in \`docs/approval-web.md\`.

Crucially, **the existing broker is not a general sudo shell**.
A model-originated tool request is not an independent human consent.

## Preferred normal workflow

1. ChatGPT says what exact administrative action it needs and why,
   and uses the MCP \`privilege_request(operation, ttl_seconds)\`.
2. The user clicks https://gateway.debasti.com/approvals.
   If needed, they sign in with their independently stored password,
   inspect the *exact operation and device*, and approve using TOTP.
3. ChatGPT polls \`privilege_status\`, invokes \`privilege_execute\`
   **once**, and reports the audit/exit code.
4. The broker consumes approval before executing. No user SSH terminal,
   sudo password, repeat bootstrap or broad root grant is needed.

**Make that easy in the chat UI:** show the concrete operation,
a direct approval URL and status; never ask the human to paste
passwords, OTPs, bearer tokens or private keys into ChatGPT.

## First executable improvement

Branch source adds \`oracle-ssh-protected-paths\`, a fixed read-only
broker operation. Exact root executable \`/usr/bin/stat\` receives five
hardcoded absolute SSH/registry paths and a fixed metadata format.
The caller can supply only the operation name, not a command, file
path, \`sudo\` argument or arbitrary shell.

Security tests cover: explicit independent approval via the
\`ai-lab-approver\` endpoint; rejecting execution while pending;
rejecting operational actor self-approval; immutable \`stat\` argv even
if hostile command/path fields appear; consume-once/replay denial.

The new privileged operation is **NOT deployed**; must only be deployed
after branch CI, exact source review, independent controlled
root installation, backups and rollback plan. Production currently
has a smaller operation allowlist than the repository.

## Next UX and security milestones

1. Gradually add exact admin operations frequently needed for
   onboarding (fixed root inventory, explicit named service restarts,
   fixed device-code candidate dry-run), each independently reviewed,
   allowlisted, bounded, audited, and tested before deployment.
2. The approval page should show distinctive request IDs, precise
   side effects, requesting device, expiry and parameters to avoid
   approval confusion. Human never sees generic "approve root".
3. Short-lived *capability bundles* (e.g., "read-only SSH diagnostics")
   may group carefully scoped operations after one independent approval,
   with a fixed maximum number of calls and immediate revocation.
   Do not grant a generic Unix shell as a bundle. Design and test
   binding of exact operations to the approved bundle before exposure.
4. Only if truly necessary, consider exceptional unrestricted
   maintenance windows with separate explicit human confirmation,
   independent hard deadline/reboot behavior and out-of-band recovery.
   An expiry timer is *not* a sandbox: root processes may persist.
5. Device elevation after pairing is separate from SSH pairing and
   independent from the Persistent/On-demand connection preference.
   Keep all newly enrolled devices Restricted.

## Acceptance criteria

- Routine fixed root diagnostics: **zero Oracle SSH/sudo interaction**,
  only independent web approval for the exact operation.
- Self-approval, wrong OAuth subject, replay, expired/denied grants,
  unknown operation, caller-supplied commands and paths: denied.
- No new root NOPASSWD sudoers entry and no existing-root-key exposure.
- Immutable operation/version recorded, and production install can be
  rolled back without affecting Gateway/WSL/Raspberry access.
- CI runs on branch/PR instead of pushing untested changes to main.

The Oracle bootstrap expiry remains separately controlled by its
systemd timer. Developing this UX does not extend that expiry.


## Parallel read-only Oracle validation during active bootstrap

At 2026-10-16 00:48 UTC the Gateway, broker, approver and Caddy were
active; Raspberry loopback 10001 and WSL loopback 10002 both listened,
and both devices answered \`device_status\`. No listener on 10003.

The existing protected \`known_hosts\` unexpectedly already contains
a fingerprint at loopback 10003. Read-only root-side verification showed
the 10003 Ed25519 fingerprint equals the verified WSL Ed25519 fingerprint
at 10002, \`SHA256:hh1guyo4yOa81Qj0zrf+XZlNpwaMlH0BfDAdo0SGwCw\`.
The 10002 host also has additional known host algorithms pinned.
This is a **known-hosts entry only**, NOT evidence an SSH listener or
candidate has been activated. The new root candidate preflight must
handle this pre-existing entry deliberately, not overwrite it or
incorrectly assume port 10003 is unused in all respects.

The supervised sudo window remains temporary and tied to the existing
fixed deadline. Neither this branch nor the new read-only stat
operation changed production services, SSH host trust or sudoers.
