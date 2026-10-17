# Live acceptance: one-use supervised root on a managed Linux target — 2026-10-17

**Scope:** Draft PR #10, independent experimental Gateway. This is a technical acceptance checkpoint, not a production-readiness or merge approval.

## Six-stage project plan and status

1. Independent human approval to signed authorization issuer — **implemented and live E2E verified**.
2. Safe local-root installer for target executor — **installed on the disposable second Oracle target**.
3. Dedicated MCP request/execute tools — **available and live E2E verified**.
4. Real second-Oracle allowlisted root execution with single-use denial — **functional E2E passed**; additional negative/security acceptance remains.
5. Restricted / Partial / Unrestricted access profiles, expiry and revocation — **pending**. A one-use operation remains independent of these three profiles.
6. Single verified Linux installer integrating pairing, `ailab`, and protected executor — **pending**.

## Components verified live

- Gateway `ai-lab-gateway-01`: MCP, root privilege broker and independent approval service were `active` after the broker-only console-approval hotfix.
- New broker executable: `/usr/local/libexec/ai-lab-privilege-brokerd`, `root:root`, mode `755`, SHA-256 `479034afb80594138cd3c6e4a1d5f7dfad1835e3a62888cc83353727ba64d902`. Previous baseline checksum `f75d339600c30a063cb5f556434523e658de048f708429dc1f1dc3ad441b8199`; root-only backup directory `/var/backups/ai-lab-console-approval-broker-v1` was present.
- Installer `scripts/deploy_console_approval_broker.py` was retrieved from immutable commit `dcaf707a920a675b2852395b688232413d236e99`, verified against SHA-256 `6142bb3e0ac7acee9ae97b98a4ba26acab772009198bbe5119b6b0cadb58f914`, and locally run by the original `ubuntu` administrator with `--check` followed by `--apply`. Console reported `BROKER_CONSOLE_APPROVAL_CHECK_OK` and `BROKER_CONSOLE_APPROVAL_DEPLOYED: no request approved`. Broker alone was restarted; subsequent MCP read-only checks verified other services active.
- Target `ai-lab-experiments-01-fd3dab34`: online via existing management SSH as nonroot `ai-gateway`; target executor had already been installed using the local administrator's approved, pinned installer. This checkpoint did not change target sudoers or SSH.
- Dedicated MCP tools `target_privilege_request`, `target_privilege_status`, `target_privilege_execute` were discovered and callable. The unrelated Oracle self-management privilege tools were **not** substituted.

## Real test observations (same authenticated user and target)

1. Dedicated MCP request for `root-identity-check` returned `ok: true`, `status: pending`, and fixed `argv: ["/usr/bin/id","-u"]`; its single target was the second Oracle.
2. Original human `ubuntu` administrator independently reviewed the pending request using `sudo /usr/local/libexec/ai-lab-privilege-brokerd --list`. Approval used the new `--approve-target` CLI, with **both** `--expected-device ai-lab-experiments-01-fd3dab34` and `--expected-operation root-identity-check`. Broker returned `status: approved` and a finite expiration.
3. MCP `target_privilege_execute` returned `ok: true`, `status: consumed`, `exit_code: 0`, `stdout: "0\\n"`, `stderr: ""`. This is a real root UID response on the target, not a synthetic CI result.
4. A second call with the **same request** returned `ok: false`, `error: not_approved`. A status lookup confirmed `status: consumed`. **Scope of evidence:** this proves broker/request one-use rejection in the live flow, not direct target-side re-submission of a previously issued signed voucher; target nonce replay rejection has separate synthetic CI coverage.
5. Ordinary nonroot MCP `exec` on the target returned `ai-gateway` for `id -un`; `sudo -n /usr/bin/id -u` returned exit code `1` and `sudo: a password is required`. No general sudo was granted.

**No private SSH key, voucher, OTP, password, or OAuth token was published.** The request identifier and OAuth subject are intentionally omitted from this public record; the root broker has its own protected audit trail.

## Acceptance coverage and remaining security tests

| Assertion | Evidence | State |
| --- | --- | --- |
| Correct device and fixed argv approval | live separate console approval + MCP | PASS |
| Real target root execution via authenticated MCP | UID 0, exit 0 | PASS |
| Second issuance from consumed request | `not_approved`; `consumed` | PASS |
| No general target sudo | `sudo -n /usr/bin/id -u` denied | PASS |
| Wrong device/operation, unsigned voucher, stale nonce, concurrent request, target replay | existing isolated/synthetic CI and previous denial checks | CI-only / partial live |
| Root-side audit trace independently inspected | no root audit inspection captured during this checkpoint | NOT YET VERIFIED |
| Permit expiry and revocation after issue / offline device | not exercised end-to-end | PENDING |
| Restart/reboot persistence of replay denial | not exercised live after issued permit | PENDING |
| Raspberry/WSL unaffected | gateway and target services health checked; no comprehensive regression executed here | PARTIAL |
| Recovery from failed deploy using protected backup | rollback feature tested separately in CI; no live rollback attempted | PENDING LIVE DRILL |

## Follow-up

1. Preserve this PR as **DRAFT** until security negatives, audit and rollback are reviewed. Do not claim that the offline-device revocation gap has been solved; current signed voucher max TTL is 300 s.
2. Before enabling broader administrative functions, define a strict capability model for **Partial** and **Unrestricted** in a separate work item, preserving per-target enforcement, independent consent, explicit expiry/revocation and deny-by-default. Avoid a plain broad `NOPASSWD: ALL` or model-accessible root shell.
3. Integrate the validated executor and one-code pairing into the single version-pinned Linux installer only after the policy model and CI/E2E matrix are satisfactory.

Canonical architecture: `docs/device-lifecycle-and-privileged-execution.md` on main, ADR-027/028/029, Issue #2, and the PR #10 runbook `docs/target-one-use-privexec.md`.
