# One-command Linux onboarding + Auth0-bound supervised sudo (Stage 6)

**2026-10-17 STATUS: DRAFT CODE, ISOLATED TESTS ONLY. No real machine modified or Gateway service restarted. The current public install.sh is still version 1.**

## Product contract preserved

1. ONE short HTTPS shell command, executed as the original ordinary Linux user. Its existing local sudo authorization prepares OpenSSH and the nonadmin ai-gateway account. Artifacts are commit-pinned and SHA-256 checked.
2. ONE device code, authenticated in existing ChatGPT/Auth0. The human confirms that exact Linux identity; the protected Gateway activation creates only isolated Restricted SSH credentials and grants access to the same Auth0 principal.
3. In that SAME shell installer execution, **after confirmed pairing**, the root-owned one-use verifier is installed by the original local administrator. A fixed, no-args sudoers entry permits calling ONLY the verifier, which starts deny-all. This is NOT a grant of root to the AI.
4. Privileged operations use the SAME Auth0 subject, MCP gateway:control and explicit per-device target_privilege_execute request entitlement. User login is NOT replaced or re-created.
5. A SEPARATE INDEPENDENT HUMAN APPROVAL is required for every exact root operation. Only the protected Gateway broker signs an SSHSIG single-use voucher (TTL at most 300 s). Root verifies exact device, subject-bound permit, fixed argv, signature, expiry and non-replay. Current harmless fixed operation: root-identity-check = /usr/bin/id -u.
6. No generic sudo, wildcard sudoers, root SSH login, arbitrary commands, shell/root, automatic Partial/Unrestricted or sudo authorization during pairing.
7. Existing SimoneLaptop gets an --upgrade-sudo pathway without re-pairing, replacing keys or reconfiguring its SSH tunnel. A separate one-time original-Gateway-admin backfill adds only the ability to REQUEST sudo for that already verified device's original Auth0 owner.

**Security distinction:** Auth0 identifies WHO requests; the independent approval proves THAT specific root operation was authorized. This is not yet a completely host-attested one-click ChatGPT consent UI; the existing independent web/Oracle-console approval channel remains necessary.

## Root-side opt-in: deliberate, not implicit

The verified owner of a newly paired Restricted device receives the scoped target_privilege_execute REQUEST action in their protected ACL. The Gateway root broker still fails closed until the original Oracle administrator explicitly upgrades its root-owned issuer policy from v1 static allowlist to v2 allow_verified_restricted_onboarding=true. Dynamic eligibility checks unique Auth0 owner, protected registry, active nonroot SSH, loopback listener and exact standard management key path. Existing static allowlist stays unchanged.

This means publishing code or adding an SSH device does not silently grant privileged execution.

## Deployment gates and order (NOT YET EXECUTED)

1. Source review and isolated CI, including root-owned synthetic authorization, broker, SSHSIG, issuer activation, negative permission, backup/rollback and fresh disposable Ubuntu.
2. Original Oracle admin verifies and executes scripts/deploy_auth0_sudo_bridge.py --check then --apply. Updates only protected broker + verified pairing authorization plan after SHA checks and backup, leaving issuer v1 gating active.
3. Original Oracle admin verifies and executes scripts/enable_auth0_sudo_onboarding.py --check and --apply, explicitly specifying backfill-device simonelaptop-3099cd33. Root-only backup, no signing or root operation.
4. Original Oracle admin verifies and executes scripts/upgrade_verified_public_installer.py --check then --apply. Requires installed broker/plan hashes and activated v2 issuer; publishes new static installer with verified HTTPS digest and backup, without changing Caddy routing.
5. Original local operator on SimoneLaptop runs the published v2 installer using --upgrade-sudo once. No second Auth0 pairing.
6. ChatGPT requests fixed root-identity-check for SimoneLaptop; original human independently approves the exact device and operation; signed permit executes once. Retry is denied. Generic sudo remains denied and unchanged SSH tunnel remains online.
7. Preserve untouched old tunnels/devices; run reboot, recovery, audit and revocation tests separately before stable release.

**Release NOT accepted yet:** actual administrator rollout, real approved root E2E on SimoneLaptop, host attestation for ChatGPT pairing consent, broad profile support, reboot persistence/revocation. Passing CI means components were tested, NOT that these live gates passed.

See docs/device-lifecycle-and-privileged-execution.md (main), ADR-027/028/029, issues #2/#14 and earlier draft PRs #8/#9/#10/#13.
