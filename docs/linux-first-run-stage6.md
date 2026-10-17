# Stage 6, first slice — one-command Restricted Linux installation (draft)

**2026-10-17 status: code-only, dependent on Draft PR #9 and its parent Draft PR #8. Not released and NOT deployed on any managed Linux.**

The purpose of this slice is to make the first-run Restricted path repeatable before adding the complex Partial/Unrestricted privilege profiles. The separate human-approved **one-use exact-command** executor from Draft PR #10 remains supported as an independently provisioned component; it is not silently installed with the Restricted SSH pairing.

## Target experience

On a fresh Ubuntu/Debian Linux machine with systemd, an ordinary human user will run a **version-pinned installer**, from a public verified source, **without invoking the installer itself with sudo**.

1. Optionally invoke the downloaded installer with `--check` to verify local prerequisites without network access, writing files or invoking sudo.
2. Run the same script without options. It fetches pinned artifacts over HTTPS and checks their SHA-256 digests. It then explicitly calls only the audited, narrow **local** preparation helper under the operator's sudo permission. The helper creates/verifies the `ai-gateway` nonadministrator account and the Linux SSH service.
3. The installer installs the pinned device pairing client and the `ailab` CLI inside the Restricted account; only the Restricted account creates local SSH keys.
4. The user sees **one device code** on the Linux terminal and supplies it in ChatGPT. An Auth0-bound, independently confirmed pairing operation must approve the exact device. This is never interpreted as root approval.
5. After the approved offer has been verified against the locally pinned Gateway host public key, the client establishes the nonroot reverse SSH tunnel. The enrolled device starts with **Restricted** access and **on-demand connection** (`persistent=false`) in the currently validated target implementation.
6. After local setup the original operator can invoke `~/.local/bin/ailab status`, `connect`, `disconnect`, or `persistent on/off`. The shortcut invokes the installed `ailab` Python CLI as user `ai-gateway` via **local** sudo's user-switching. The shortcut does not grant a generic sudo rule to the remote account. A local sudo prompt may occur; do not paste its password into ChatGPT.

**Boot persistence caveat:** pairing defaults to on-demand. Switching to persistent mode converts a transient systemd user unit into a stable service; PR #9 contains unit tests and safe read-only live tests, but complete reboot acceptance remains pending. The installer must not claim that reboot persistence has passed until E2E validates it.

## Implementation changes in this PR

- `scripts/install_ai_lab_device.sh`: adds `--check` for read-only local compatibility, consolidates all three artifacts under TLS-only curl/wget, displays accurate initial security expectations and creates a nonoverwriting local `ailab` shortcut for the original user.
- Existing SHA-256 and immutable Git commit pins for device pairing, local setup and the `ailab` CLI remain unchanged. The installer itself also must be published as a **versioned integrity-verifiable artifact** in a later release. No unverified `curl | sudo bash`.
- `tests/test_one_command_installer.py` and `.github/workflows/linux-first-run-lab.yml`: POSIX syntax, pinned artifact declarations, offline preflight, fixed-only shortcut actions, no accidental overwrite, and a disposable mock showing every shortcut executes under `ai-gateway`, not root.
- The previous source and tests from PR #8/#9 remain available in this branch for staging.

## Security and missing integration

- **Not deployed**: there is currently no newly deployed stable public `https://gateway.debasti.com/install.sh` endpoint, nor a signed released installer artifact. Do not pretend the eventual short one-liner is ready for a third-party Linux.
- This staged source is attached to a PR branch, not a reviewed immutable production release. The source URL for this draft is not an installation instruction.
- The current first-run script supports Ubuntu/Debian + systemd with a locally sudo-authorized original operator; arbitrary distros and minimal embedded Linux need adapters. `ai-gateway` itself has no general sudo.
- No automatic root executor install. The existing PR #10 installer requires a separately trusted signer **public key and independently confirmed fingerprint** and a local original administrator's explicit sudo. Pairing must not acquire those values from an untrusted server response or automatically add sudoers.
- Unlike the profile grants in PR #12, one-use privileged execution is already functional E2E on the second Oracle. Full target-voucher replay, offline revocation, audit, reboot/rollback security tests remain before promising general readiness.
- The initial SSH pairing code is NOT a cryptographic human sudo consent. Independent Auth0-bound enrollment and root approvals remain separate security boundaries.
- A local `ailab` shortcut can be called by the human only on that Linux; it controls its own previously paired systemd SSH tunnel. It cannot reconnect a target from ChatGPT if that target's sole tunnel was disconnected.
- Tested functions should fail closed on conflicting paths, changed binary hashes, unsupported host environments or tampered SSH offers. Preserve original WSL/Raspberry/gateway state.

## Lab acceptance before stable release

1. CI: installer/wrapper tests + prior device-code, SSH offer and local CLI regression suites.
2. A **virgin disposable Ubuntu** with sudo-enabled human login: `--check` prints plan, initial install downloads all verified artifacts, creates nonadmin `ai-gateway`, shows one code and waits for approval.
3. ChatGPT resolves the code, confirms the device via Auth0 and validates `hostname`, `whoami=ai-gateway`, `sudo -n /usr/bin/id -u` denied; unapproved/expired codes fail.
4. Local human runs `ailab status`, `connect` repeatedly (idempotent), `persistent off` without disconnecting, and then independently verifies `persistent on` + actual reboot + reconnection. Deliberately disconnect only at a local console that can reconnect.
5. Verify optional independent installation and E2E of the *one-use* signed root executor, with explicit original admin authorization and pinned issuer trust, without widening the default Restricted policy.
6. Test interrupted downloads, incorrect hashes, conflict with preexisting `~/.local/bin/ailab`, rollback of failed local setup, recovery from partial enrollment, and harmless rerun behavior.
7. Only after passing release gates publish the reviewed installer using a stable public HTTPS endpoint and verifiable pinned digest/signature. Then make the user-facing ChatGPT instruction a **single command** without leaking credentials.

## Branch dependencies

- PR #8: Linux device-code activation and Gateway enrollment worker.
- PR #9: `ailab` local CLI and pinned installation; based on PR #8.
- **This PR**: Restricted first-run UX, based on PR #9.
- PR #10: one-use root independently approved; kept separate until its negative tests pass.
- PR #12: Partial/Unrestricted R&D, deliberately not a dependency for the Restricted first-run experience.

**Release posture: DRAFT.** Do not merge or deploy until the final local admin security checks, clean-VM E2E and stable verified HTTPS publishing path are ready.
