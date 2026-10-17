# Target-local one-use privileged executor — laboratory v0.1

**Status (2026-10-16): DRAFT code and CI tests. No root installation on any managed Linux. No production consent/signing service exists yet.**

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