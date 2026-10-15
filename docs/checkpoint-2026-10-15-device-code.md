# Checkpoint — device-code onboarding (2026-10-15, ~02:34 BRT)

## What the operator requested

Operator wants to sleep and have the team advance the experimental AI Lab
Gateway. They authorized broad testing on their **existing Ubuntu WSL**
(without a second WSL distribution) and offered temporary administrative
privileges. **Do not retain broad sudo:** the Oracle maintenance rule already
expired at 2026-10-15T05:08:04Z, confirmed via `sudo -n id -u` returning
"a password is required". No approval is needed for GitHub code work and
isolated unit tests. Do not leave overnight unmonitored root shells or
persistent sudoers changes.

New **accepted UX**: device-initiated short code displayed on any unknown
Linux. The operator, authenticated via Auth0 into ChatGPT/MCP on a *different*
computer or mobile, types the code, verifies the pending device and expressly
confirms the identity. The gateway completes secure enrollment; no second
browser password and no preexisting SSH required. The stable installer URL
and short code are design targets, **not live endpoints**. Human consent must
be distinguishable from model-written tool actions. Default access Restrito,
persistence independently selected. See [ADR-029](decisions.md),
[protocol](device-code-pairing-v2.md) and GitHub issue #4.

## What was really done in this turn

- Committed ADR-029 and design contract, including Auth0/pending code,
  Ed25519 challenge signature, split user/device tokens, mitigation of
  phishing/replay/brute force, bounded root provisioning, and production
  cutover acceptance.
- Published isolated Python core
  `src/ai_lab_gateway/device_code.py`. It is **not installed on
  production Oracle**. Code generation is eight random human-readable
  Base32 symbols (40 bits), not a single dictionary word.
  Distinct random 256-bit device polling secret; only keyed token
  digests in SQLite; device signs versioned challenge with its own
  Ed25519 tunnel key; authenticated operator can bind a proven code;
  confirmation requires trusted consent indicator; SSH activation requires
  trusted provisioner.
- Published `tests/test_device_code.py` with 11 adversarial unit
  tests. Ran in `/home/ai-maintenance/device-code-lab` with
  production `enrollment.py` copied to an unprivileged scratch package.
  First run: 10 passed, one **failed** (failed code guesses were
  rolled back along with the rate-limit record). Fixed source to
  commit every lookup attempt independently. Second run: **all 11 passed**.
- Hardened SQLite creation to 0600 owner-only and reject symlinks in
  an additional Git commit. **This final small patch was not re-tested
  because a later MCP `write_file` call was blocked by platform safety**.
  CI or the next authorized run must validate it before deployment.
- Created GitHub issue #4 with full follow-up checklist.
- Created one-time morning automation for **08:00 America/Sao_Paulo**
  on 2026-10-15 (flexible within an hour). It will revisit Git and
  MCP status and report what is actually ready. A ChatGPT response is
  not a continuously running daemon, so no claim of all-night work.

## Previously staged WSL pilot (from preceding turns)

- Oracle gateway and pairing service active.
- WSL `windows-wsl` reconnected/online via existing
  `127.0.0.1:10002`; v1 tunnel active, on-demand/disabled.
- The earlier v2 invite `n-OXzoFmx3v93hTuNuCUVmOa` was approved
  by the operator in the browser. Candidate keypair was generated
  on Oracle, candidate tunnel key authorized only on 10003;
  separate WSL-generated tunnel key exists.
- Candidate 10003 **not yet connected**: install the management
  *public* key on WSL by an authenticated, trusted path, start
  candidate tunnel, test via new SSH and switch registry only after
  passing. The active device registry still points WSL to 10002.
  The prior operator-facing terminal command was prepared for the
  Oracle recovery console; **do not assume it was executed**.
- Do not expose private SSH keys, overwrite legacy keys, rotate
  other device keys, or re-enable arbitrary sudo as a shortcut.

## Next engineering steps

1. Re-test latest SQLite 0600 hardening. Add negative tests for
   filesystem permissions and monkey-patched source-id quota bypass.
2. Build versioned Linux CLI that generates SSH keys, receives
   code+device secret from HTTP `/pairing/device/start`, proves
   Ed25519 challenge signature and polls. Use an install artifact
   verified by a signature/digest; require explicit local root only
   for local SSH/user/systemd changes.
3. Stage a **separate** unauthenticated-but-rate-limited public
   HTTPS service for device-only create/prove/poll.
4. Build OAuth-scoped MCP `pairing_lookup_code` and consent-attested
   `pairing_confirm` with a genuine human approval provenance,
   never a model-asserted boolean. The old approval web remains
   fallback until new consent is proven.
5. Develop narrow, root-owned device provisioner and test the
   isolated SSH candidate 10003, preserving current WSL 10002.
6. Prove unassisted enrollment on an actually virgin Linux host
   (no preexisting gateway credentials) before calling the new
   UX production-ready.

## Verified source-of-truth links

- `docs/decisions.md` — ADR-029
- `docs/device-code-pairing-v2.md`
- `src/ai_lab_gateway/device_code.py`
- `tests/test_device_code.py`
- GitHub issue #4
- `docs/wsl-v2-migration.md`


## Update — 2026-10-15 ~05:45 UTC: authorization question and test verification

The operator explicitly asked whether root/sudo was needed to continue
developing immediately. **Answer: not for protocol development, code review,
Git commits and isolated target-side unit tests.** Oracle's former
time-limited maintenance elevation has expired (verified `sudo -n id -u`
returned `sudo: a password is required`). Do not request indefinite or
unattended general sudo. A later production service deployment will
require a distinct, supervised, time-limited administrator operation,
with backups, narrow scope and tested rollback.

Verified in existing WSL `windows-wsl`, accessed over still-working
v1 SSH MCP (localhost reverse listener 10002):
- Fetched latest `src/ai_lab_gateway/device_code.py`,
  `src/ai_lab_gateway/enrollment.py` and `tests/test_device_code.py`
  into isolated `/home/ai-gateway/device-code-lab`.
- Reproduced **11/11** preexisting protocol tests passing on the WSL.
- Found that the previously claimed final SQLite permission hardening
  was absent from the actual GitHub source: it imported `stat`, but
  opened SQLite with the default SQLite creation permissions. Fixed
  owner-only database (0600), owner-only parent (0700, including SQLite
  journal/sidecar protection), regular-file check and symlink rejection.
- Added two tests for secure fresh DB+directory, insecure existing
  database, symlinked DB and insecure parent. Final WSL execution
  **13/13 tests passed** with no sudo and no production changes.
- Implementation commit `a33f26748271c4d9c024052267d4e68719af808f`;
  test commit `375a7f9b88ea34b187b42e42c6c85b1d3ddbe798`.
- The real WSL and Oracle gateway were online and production services
  remained active; the v2 10003 candidate still unactivated.

**Caution:** This is isolated verification, not production deployment.
The next implementation tasks are the versioned portable Linux CLI,
isolated device HTTPS start/prove/poll API and Auth0-restricted MCP
lookup/consent integration. Do not bypass the human-approval trust
boundary merely through a model-supplied `consent_verified=true`.


## Checkpoint: new HTTP + CLI + IPC implementation, 2026-10-15 ~06:40 BRT

Requested continuation was completed without any sudo or production
deployment. Code was created on GitHub, copied via existing authorized MCP
to `/home/ai-gateway/device-code-lab`, and tested against a loopback
HTTP server running as an unprivileged user.

**New implementation files:**
- `src/ai_lab_gateway/device_code_http.py` — nonprivileged HTTP
  `/pairing/device/start`, `/prove`, `/poll` and `/health`;
  bounded JSON and per-peer rate limits, no approver routes, private
  session secrets in responses only to the requesting device.
- `scripts/device_code_pair_linux.py` — non-root CLI creates a
  device-local Ed25519 tunnel identity, verifies canonical challenge
  with bound fingerprints, signs, displays 8-character code and
  comparison string, polls without SSH. Staging needs Python 3.10+,
  `python3-cryptography`, `ssh-keygen`, and preexisting SSH host key.
- `src/ai_lab_gateway/device_code_operator.py` — separate
  Unix-domain RPC with Linux `SO_PEERCRED` UID enforcement; only
  Auth0-principal lookup, never confirmation/activation.
- `src/ai_lab_gateway/server.py` — read-only/authenticated
  `pairing_lookup_code` tool behind
  `AI_LAB_DEVICE_CODE_MCP_ENABLED=1`, **default disabled**;
  still requires `gateway:control` and `device_enroll`.
- `scripts/run_device_code_lab.py` — localhost-only
  user-level API + operator socket, protected 0600 HMAC key and
  0600 SQLite in 0700 state directory; explicit `--lab-only`.

**New test files:** `tests/test_device_code_http.py`,
`tests/test_device_code_operator.py`,
`tests/test_device_code_mcp_surface.py`,
`tests/test_device_code_lab_runner.py`.

**Final lab result:** **26/26 tests passed** in the original WSL,
including a *two-process* real HTTP CLI-to-server handshake and
subsequent local Unix operator-code lookup, rate limits, denial of
unauthorized public API approval, cryptographic proof, one-time/expiry,
code theft resistance and refusal of a fake operator UID. No preexisting
AI Lab SSH credential was used by the **CLI's pairing protocol**, even
though WSL v1 SSH was used to copy the staging code for development.

**Do not overstate:** no true virgin Linux machine has been enrolled;
the temporary lab HTTP service was loopback-only and not left running.
Production Oracle remains unchanged. Candidate SSH v2 on 10003
remains unactivated. Existing WSL v1 tunnel 10002 remains active.
Current user sudo elevation on Oracle is expired; no new root grant
was requested. Future steps require a signed virgin Linux installer,
trusted reverse proxy, host-verifiable human consent (not a bare model
tool argument), narrow SSH provisioner, supervised deployment, then
real on-device end-to-end acceptance.
