# Stage 6 — Real Gateway E2E on a virgin disposable Ubuntu (operator-guided)

**2026-10-17: procedure PREPARED, NOT YET EXECUTED.** This document is for a disposable Linux whose original human console is available. It is NOT an instruction to reconfigure the Gateway Oracle, the second Oracle, WSL or Raspberry Pi. Keep the PR Draft until the live checks are complete.

## Evidence before touching any new host

- MCP `gateway_status` returned `status=ok` on `ai-lab-gateway-01`.
- `ai-lab-device-code.service`, `ai-lab-pairing.service`, `ai-lab-gateway.service` and `ai-lab-privilege-broker.service` were running.
- The public HTTPS reverse proxy reached the device-code POST-only endpoint (`OPTIONS` produced a route-specific 501; `GET` was not accepted). **No real pairing was started during this preflight.**
- All three immutable Git commit pins and SHA-256 hashes embedded in the draft installer were fetched and verified remotely:
  - `device_code_pair_linux.py` — **MATCH**.
  - `ai_lab_prepare_linux_target.py` — **MATCH** (fresh-account `useradd` timeout raised to a bounded 90 seconds following disposable-runner failure).
  - `ailab` CLI — **MATCH**.
- Bootstrap's hard-coded public SSH host key matches the SSH host public key on the real Oracle.
- Local-only GitHub Actions acceptance: [successful run 39003114929](https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/39003114929), 11 installer tests, 201 pairing regressions (23 skipped), eight CLI tests and three real disposable-Ubuntu/localhost tests. **This does not establish an actual production-device E2E.**

## Preconditions and risk boundary

- Create a **new disposable** Ubuntu 24.04 VM with network access, systemd, Python 3.10+, OpenSSH client, curl or wget, and a **normal human Linux login that can explicitly approve local sudo**. Preserve its console even if the SSH tunnel fails.
- Do not use the actual Gateway Oracle, experiments Oracle, Raspberry, WSL, or any Linux with valuable workloads for this first full-install attempt.
- The installer requests LOCAL sudo only to prepare `sshd`, create `ai-gateway` (no generic sudo) and enable a systemd user service. It **does not** install the separate one-use privileged executor and never grants `NOPASSWD: ALL`.
- This is a Draft pre-release, not a signed production release. A locally checked immutable commit plus manually supplied expected SHA is the lab integrity gate. Do not run `curl ... | sudo bash` and never send SSH private keys, Linux passwords or tokens to ChatGPT.
- The device code intentionally appears **only in the VM's local human console** and must be entered by the human in the authenticated ChatGPT session. Avoid displaying this temporary code in public GitHub Actions logs, public CI artifacts or public issues.
- Human pairing confirmation approves **identity only**, never root, and does not create a standing sudo permission.
- Restrict the evaluation to a single VM and one code; do not turn on persistent connectivity or reboot until the one-off tunnel and restricted identity have been verified.

## Immutable installer verification

Immutable URL (draft bootstrap, PR #13 commit from successful CI):

```text
https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/13a06d291b3e9c2b17025c1c54cd657fc68e39f2/scripts/install_ai_lab_device.sh
```

Expected installer SHA-256, independently checked from the running Gateway:

```text
367fb8d46b0efcac3c319c92174af29e96e943ae18cdbeb7a8e62576c0857127
```

Run as the VM's **original human (NOT root)** in its terminal:

```sh
set -eu
curl --fail --location --silent --show-error \
     --proto '=https' --proto-redir '=https' --tlsv1.2 \
     'https://raw.githubusercontent.com/fabianodebastiani/ai-lab-gateway/13a06d291b3e9c2b17025c1c54cd657fc68e39f2/scripts/install_ai_lab_device.sh' \
     -o "$HOME/ai-lab-install-reviewed.sh"
printf '%s  %s\n' \
     '367fb8d46b0efcac3c319c92174af29e96e943ae18cdbeb7a8e62576c0857127' \
     "$HOME/ai-lab-install-reviewed.sh" | sha256sum -c -
sh "$HOME/ai-lab-install-reviewed.sh" --check
```

Expected: `AI_LAB_INSTALL_PRECHECK_OK` with no sudo or system modification.

If the operator reviews and accepts local sudo preparation for this **disposable** VM, run:

```sh
sh "$HOME/ai-lab-install-reviewed.sh"
```

Expected: all pinned downloads verify; **only then** the locally authorized Ubuntu account/sshd preparation occurs; the device prints a short code such as `ABCD-EFGH` and waits for an **independent** human approval.

## ChatGPT-controlled approval checkpoint

1. The human types in this chat **`Conectar dispositivo XXXX-YYYY`**, copying the exact code from the VM terminal. A sample placeholder is **not** a usable code.
2. Agent calls **`pairing_lookup_code`** (read-only) and presents the concrete device name/ID and restricted profile. If data do not match the intended disposable VM, **stop without approval**.
3. Only after the human explicitly confirms the exact requested device should the agent call `pairing_confirm_single_code` with the unchanged code/request_id. Device activation and SSH authorization are enforced independently by the trusted Gateway provisioner. No general sudo and no root privilege request.
4. Agent polls `pairing_status`/checks `list_devices`, then `device_status` and `exec` of **read-only** `hostname`, `whoami`, `id`, and `sudo -n /usr/bin/id -u`. Required identity: `ai-gateway`; generic sudo must fail.
5. VM console should report a verified connection offer and then `active` if the independent provisioner successfully stages and verifies the SSH tunnel. If only `approved` or `candidate_staged`, **do not claim connected**; inspect Gateway audit without weakening authorization.
6. Locally check `$HOME/.local/bin/ailab status`. At this point the operator may experiment with `connect`, but **do not disconnect the only reverse tunnel from ChatGPT**; only the local human console can restore it.

The code/pairing grant expires in roughly 10 minutes; if it expires, stop and restart the request on the disposable VM, not by bypassing any approval step.

## Separate acceptance gates AFTER connecting

- Inspect authoritative root-side approval/audit logs without exposing sensitive records in ChatGPT.
- Test `ailab status`, repeated `connect`, and nonpersistent preference; verify no sudo was silently granted.
- Only with console recovery available, test `ailab persistent on`, actual VM reboot, automatic tunnel recovery and then `persistent off`. A hosted CI runner is unsuitable for this reboot acceptance.
- Independently optional: install the PR #10 single-operation root executor with the original Linux administrator, pinned trust fingerprint and supervised human approval; do not silently include it with pairing.
- Publish a reviewed signed/bootstrap release and stable HTTPS entry point only when genuine human/ChatGPT/production-Gateway E2E and recovery are complete.

**Stop conditions:** checksum mismatch, changed SSH host key, missing human confirmation, unexpected sudo, unknown device identity, incorrect offer, service timeout or failure to preserve original local console.
