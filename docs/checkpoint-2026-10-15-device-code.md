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
