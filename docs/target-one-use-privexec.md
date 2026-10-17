# Target-local one-use privileged executor — laboratory v0.1

**Status (2026-10-16): signed broker/transport/installer SOURCE in draft PR #10 with isolated CI tests; no target root installation or production signer activation yet.**

Canonical decision: [device lifecycle and privileged execution](https://github.com/fabianodebastiani/ai-lab-gateway/blob/main/docs/device-lifecycle-and-privileged-execution.md), ADR-027, ADR-028, ADR-029, and Issue #2. The **one-use exact-command authorization is independent of the exactly three persistent access profiles**; it is not a fourth radio mode.

## Trust model and protocol

1. ChatGPT and the regular MCP process must NEVER create an approval token merely because the model asks. An **independently authenticated human-approval** authority on the Gateway must sign one strictly scoped permit. That service and its long-lived Ed25519 signing private key are **not implemented** in v0.1. The private key must not enter a managed target, the ordinary SSH account, GitHub, or a model tool call.
2. A local human administrator installs the verified approver PUBLIC key as a root-owned OpenSSH allowed_signers file, plus a root-owned copy of the target device ID that matches the trusted pairing. Do not learn the issuer identity from untrusted HTTPS pairing responses or writable target SSH state. Provisioning this root trust is a separate initial sudo operation.
3. The executor is a fixed path (/usr/local/libexec/ai-lab-target-privexec), isolated Python interpreter shebang, and a **single exact sudoers allowance** for the dedicated ai-gateway account with **NO arguments**. Planned example (NOT INSTALLED):

    ai-gateway ALL=(root) NOPASSWD: /usr/local/libexec/ai-lab-target-privexec ""

   There must be no sudo wildcard, arbitrary interpreter, generic shell, or permanent privilege for normal MCP exec. Target installation needs a version-pinned audited artifact, root:root ownership, a rollback-capable sudoers edit checked with visudo, and an independent human local sudo approval.
4. The caller sends the signed envelope via **stdin**, not command arguments. The permit includes exact device_id, Auth0 subject, operation name, fixed argv, issued_at, expires_at and a random 256-bit nonce. The verifier checks OpenSSH SSHSIG signature namespace ai-lab-privexec-v1 and principal ai-lab-privilege-approver-v1, root-owned signer key, root-owned device binding, strict fields, up to 300-second lifetime, expiration at time of execution, and exact allowlisted argv.
5. The nonce is consumed BEFORE running the root operation, using root-only files, an exclusive lock, O_CREAT|O_EXCL|O_NOFOLLOW, fsync(file) and fsync(parent dir). Reuse is denied even across restarts. A root-controlled revoked-nonce directory can deny otherwise valid vouchers. Expiration is enforced locally without live Gateway access.
6. v0.1 ONLY allows root-identity-check = /usr/bin/id -u, with no extra argv, scripts, shells, environment overrides, writes, package installation, systemctl or unknown operations. Never represent one-time approval of a shell or arbitrary script as a narrowly scoped operation.

## Wire contract

The request is a JSON object with **exactly** permit and signature fields. The permit has **exactly** version, device_id, subject, operation, argv, issued_at, expires_at and nonce. Signature covers the ASCII bytes of sorted compact JSON of the permit plus a final newline, using ssh-keygen -Y sign -n ai-lab-privexec-v1. Verification uses ssh-keygen -Y verify with a root-owned allowed_signers trust anchor. Real public keys, Auth0 identities and credentials are NEVER in this repository.

## Tests and status

- **CI (2026-10-16): SUCCESS**, isolated disposable Ubuntu runner with temporary *synthetic* signing key and root-only state. Proved correct signed root-identity check, single use, eight-process replay race yielding exactly one success, tampering/wrong device/unknown argv rejection, expiry, future/overlong TTL denial, explicit revocation, symlink/permission fail-closed, and nonroot denial.
- **Second Oracle via live ChatGPT MCP:** downloaded source in a temporary regular-user location and ran with no sudo. It returned PRIVEXEC_DENIED with exit code 77; independent sudo -n id -u remained denied and hostname/SSH worked. **No root executable, sudoers file, signing key or privilege policy was installed.**
- **Not delivered:** independent real-human signing authority, issuance bound to Auth0 approvals, verified signer distribution, separate MCP tool/permission, target-side installer/rollback, *positive* sudo execution on the real Oracle VM, revocation API, multi-device negative verification, Partial and Unrestricted grants.

## Next milestones

1. Implement and independently test a minimal root-owned installer with exact sudoers allowance, pinned artifacts, root binding and rollback. Do NOT invoke it from ordinary MCP exec; user must authorize local sudo.
2. Build protected Gateway-side signer behind the already existing independent human approval channel. No signing ability from general MCP command tools.
3. Add dedicated scoped privilege operation to MCP (Auth0 gateway:control plus per-device action); never reuse ordinary exec grant as privilege permission.
4. E2E test on disposable second Oracle: deny before approval; sign one consented fixed id operation; execute once; reject replay after restart; reject expired and revoked; confirm Raspberry/WSL and Gateway untouched. Only then extend to timed/indefinite profiles.

Source branch must stay DRAFT until these milestones are verified. This decision preserves ADR-027's three profiles and Issue #2's operation-specific consent rather than replacing either.

## Implementation update — 2026-10-16 (PR #10 draft, CI only)

**What changed since v0.1:** The separate root broker now implements
target_request -> pending -> **existing independent password/TOTP approval
socket** -> approved -> target_voucher. Root-only issuer signs an SSHSIG
Ed25519 voucher only when approval_method is separate_human_web_ui and the
device is present in the root-owned **explicit allowlist**.
The approved request is durably consumed *before* signing, and cannot sign
twice even after failure. The approver UI displays device ID, exact fixed
argv, OAuth subject, and duration, not a general-purpose sudo request.

A feature-gated MCP tool family is in src/ai_lab_gateway/server.py:
target_privilege_request/status/execute/revoke. These require BOTH verified
OAuth gateway:control scope and a **separate** per-device protected policy
action target_privilege_execute, never generic exec. The server starts with
the feature flag OFF; production policy and services have not been changed.
Execution uses src/ai_lab_gateway/ssh_exec.py to stream the signed voucher
**privately over SSH stdin** to one fixed sudo executor command. The
voucher is NOT returned to ChatGPT. The target verifies independently.

Two inert local-admin installers were added:

- scripts/install_target_issuer.py: **Oracle local root only**, checks the
  protected live device registry for the chosen eligible Restricted target,
  creates a root-only Ed25519 private signer and explicit one-device
  targets.json allowlist. No operator approval is issued and no service
  is restarted automatically. Private key must NEVER leave Oracle.
- scripts/install_target_privexec.py: **target local root only**,
  verifies the enrolled device ID, trusted approver PUBLIC-key fingerprint,
  pin of exact root executor SHA256, root-owned paths and visudo-checked
  no-argument sudoers allowance. It has a non-mutating --check and a
  separate --revoke of this exact sudoers rule. It does NOT enable generic
  sudo or install an admin SSH connection.

Both install scripts are **source-only, not run on Oracle or second VM**.
The root-only test runner uses disposable directories and synthetic keys.
The existing root broker/approver/MCP systemd units and live device SSH
connections are not changed by creating this draft.

### Acceptance evidence

GitHub Actions workflow target-privexec-lab.yml executes:
synthetic signed voucher / eight-process replay race;
synthetic approved-browser-socket -> broker one-use signer -> target
root verifier; identity/argv/device restrictions and expiry;
trusted-root signer installer tests, root-owned target installer
visudo/rollback tests, fixed SSH argv/stdin transport tests. These
synthetic tests do **not** prove live human consent or deployment.

### Live deployment gate (explicit human administrator step)

1. Original Oracle administrator reviews code/source pin and takes backup
   of the broker, approver, MCP, OAuth policy and root registry. Run
   issuer installer **--check** on the Oracle, then manually approve its
   --apply. Trust its private key only in root-owned /etc. Ensure the
   root allowlist names exactly the second Oracle test VM. Deploy and
   restart only the reviewed broker/approver/MCP code with recovery path.
   New MCP tools remain feature-disabled and inaccessible until the
   per-target protected OAuth rule is separately authorized.
2. Copy ONLY the Oracle signing PUBLIC key and verify its fingerprint by
   an independent trusted channel. Run the target installer --check,
   then --apply through the **second VM's original ubuntu administrator**
   account; never over restricted MCP account. Original root recovery
   remains intact; no SSH keys/tunnels should be rotated.
3. Enable the dedicated target_privilege_execute action only for the
   authorized Auth0 subject + second VM. Human uses real existing HTTPS
   approval site with password and a fresh TOTP code for one
   root-identity-check request. ChatGPT calls target_privilege_execute;
   verify result 0, replay denied, unauthorized/expired/revoked
   denied, protected audit and recovery. Check legacy connections.
4. Early revocation of a voucher **after issuance** on an offline Linux
   requires an additional target revocation channel and is NOT YET
   implemented. Existing request revocation works *before* issuance.
   The laboratory voucher TTL is capped at 300 seconds. Do not claim
   immediate revocation of an already signed offline credential.
   Partial/Unrestricted profile enforcement remains future work.

**No deployment claim** may be made from this draft. Do not blindly
execute shell snippets or sudoers changes from ChatGPT. Show the user
the exact signed/verifiable installation command and its risk when ready.


## Operator hand-off: Oracle gateway ROOT READ-ONLY preflight (2026-10-16)

The live MCP user `ai-maintenance` cannot read
`/etc/ai-lab-gateway/devices.json` (permission denied), has no sudo,
and cannot create the issuer. The three core gateway services were
`active` and no issuer directory existed when last checked. The
second Oracle was `online` with `ai-gateway` and no sudo.

**ONE required operator action:** log on to the ORIGINAL Oracle
Gateway VM (`ubuntu@ai-lab-gateway-01`, NOT experiments) using the
original recovery/OCI console. Paste the following **preflight only**.
It downloads a commit-locked Python script, verifies its SHA256, copies
it under root ownership, checks the real root-owned device registry,
then removes the temporary script. The script's `--check` path **never**
creates a signing key, authorizes root, changes services or creates
sudoers. The temporary /root file is a housekeeping step only.

```bash
set -e
tmp="$(mktemp)"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  'https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/f0d4871d39499c27083e163c1132f3ceab3d7c7b/scripts/install_target_issuer.py' \
  -o "$tmp"
printf '%s  %s\n' \
  '8c7408f6302550c39e95dff25cebc98c33d6a379a20028816250ea7d380334eb' "$tmp" | sha256sum -c -
sudo install -o root -g root -m 0500 "$tmp" /root/ai-lab-target-issuer-preflight.py
rm -f "$tmp"
sudo /usr/bin/python3 -I /root/ai-lab-target-issuer-preflight.py \
  --check --device-id ai-lab-experiments-01-fd3dab34
sudo rm -f /root/ai-lab-target-issuer-preflight.py
```

Expected last line on success: `DRY_RUN_OK: eligible registered target;
nothing changed`. If any step fails, STOP and share only the error
(no tokens/secrets). The subsequent `--apply` procedure is a
**separate reviewed and human-authorized** task, never silently
performed by this preflight.

The preflight GitHub raw artifact and digest were independently
verified via the live Gateway nonroot MCP account. **Do not infer**
that the final PR branch head/future revised script has the same
digest: this command is locked to the exact commit above.


## 2026-10-16 São Paulo — actual Gateway signer prepared, target not installed yet

**Explicit original local `ubuntu` administrator operation SUCCESSFUL** on the
Gateway `ai-lab-gateway-01`:

- The previously verified pinned local `install_target_issuer.py --check`
  returned `DRY_RUN_OK: eligible registered target; nothing changed`.
- The human then separately executed `--apply`; returned
  `ISSUER_PREPARED: root-owned, one enabled target; no human approval issued`.
- The **public** (not private) signing key fingerprint is:
  `SHA256:r0E6FcgCHXL0/bOarLK9gP4QQK6BFDaDiUDfUCBXW6E`.
- Public SSH Ed25519 key:
  `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGVKpXLqOIGRXuYF9Z1T7HZ9Xv+CpH1b00zhTHSzckp`
  (public key independently recomputed to match fingerprint).
- The issuer **private** key remains on the Gateway under
  `/etc/ai-lab-target-issuer/issuer_ed25519` root-only. Never copy
  it to targets or Git. The trust directory exists `root:root 0700`.
- Read-only Gateway MCP checks after this step:
  `ai-lab-gateway`, `ai-lab-privilege-broker`,
  `ai-lab-approval-web` services are all `active`; `ai-maintenance`
  continues to have **no sudo**. No new broker deployment, API privilege
  action, human approval or service restart was performed.
- Second Oracle VM via MCP: `ai-lab-experiments-01` reachable as
  `ai-gateway`, SSH user unit `active`, no target executor yet.

**New predeployment correction:** Minimal Ubuntu second VM has no
`/usr/local/libexec`. The target installer now supports creating that
root-owned non-writable directory with explicit rollback on failure.
GitHub Actions tests for the missing-directory path, visudo refusal and
rollback completed successfully.

Target files frozen to Git commit
`930b288f5cf661e2883a68e032f27ffecc78790b`:
`scripts/install_target_privexec.py` SHA256
`cef19bc7bdcaf24d17051eb2d47bc5b3124b931ade0f08d6143d8e75a795788b`;
`scripts/ai-lab-target-privexec` SHA256
`d94660a4e1a925d50fd3bd2fda02408cf5300458ad0ddd85498ba4203bdea632`.
Both source files downloaded anonymously over pinned GitHub commit,
hashed and Python compiled via Gateway read-only MCP; dedicated workflow
for that head completed success. Do not substitute mutable branch URL.

**NEXT HUMAN ACTION:** original `ubuntu` console of SECOND Oracle
(`ai-lab-experiments-01`) verifies these exact hashes plus signer public
fingerprint locally, then grants the **single path no-argument sudoers**
allowance via tested local installer with explicit human administrator sudo.
The safe negative test using the normal MCP after installation must return
denied for unsigned or absent voucher, while `sudo -n id -u` continues
to be denied. Gateway broker/MCP runtime is not yet updated.

**Note**: an installed verifier plus trusted public key is not consent
or entitlement to administrative work. The three profiles remain unchanged.


## 2026-10-16 — read-only target preflight verified via LIVE MCP

The second Oracle VM `ai-lab-experiments-01` passed **without sudo**
after independently downloading both artifacts from the immutable
`930b288f5cf661e2883a68e032f27ffecc78790b` commit and
checking their SHA256 digests. Provided only the previously confirmed
**public** issuer key and matching fingerprint. The command was:
`python3 -I install_target_privexec.py --check --device-id ai-lab-experiments-01-fd3dab34 --issuer-public-key issuer.pub --issuer-fingerprint SHA256:r0E6FcgCHXL0/bOarLK9gP4QQK6BFDaDiUDfUCBXW6E --executor-source executor`.

Live results: **both digests OK** and `DRY_RUN_OK (no files or
privileges changed)`. Identity: `ai-gateway`, host:
`ai-lab-experiments-01`. This additionally checks the real directory
layout and the existing paired target ID. The original admin `ubuntu`
must still run the **actual** `--apply` on the second VM; no sudoers
rule has yet been installed. After that, verify the root policy only
permits the exact protected executable, unsigned claims return 77,
and `sudo -n id -u` stays denied.
