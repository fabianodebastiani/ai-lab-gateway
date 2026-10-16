# Device-code v2 — Oracle protected-path reconciliation

**Date:** 2026-10-15 (GitHub CI run 38827258103).  
**Status:** root-console audit source and tests prepared; **not installed/executed with Oracle root**.

## Why a separate root audit is required

The MCP `exec(oracle-gateway)` command executes as **`ai-maintenance`** (UID
1003, GID 1003), not as root or the `ai-lab-gateway` service user. The MCP
can verify service status and active loopback sockets, but cannot list
`/etc/ai-lab-gateway` (Permission denied), the private Gateway state, or
the private tunnel account state. `test -e` produces a misleading false
result when a parent is inaccessible. Such results must **not** be
interpreted as evidence the SSH files or registry are missing.

Observations from read-only calls:
- `ai-lab-gateway.service` is launched from
  `/opt/ai-lab-gateway/.venv/bin/ai-lab-gateway`, working directory
  `/opt/ai-lab-gateway`, as the independent `ai-lab-gateway` Unix user.
- Production systemd has environment/pairing drop-ins; their sensitive
  contents were **not** printed.
- `/etc/ai-lab-gateway` has root ownership and mode `0750`.
  Membership/permissions prevent `ai-maintenance` from inspecting it.
- Tunnel account home is `/var/lib/ai-lab-tunnel`; Gateway service
  home is `/var/lib/ai-lab-gateway`.
- `sshd -T` from the unprivileged MCP failed with
  `sshd: no hostkeys available -- exiting`. Its absent output does
  **not** establish the effective root sshd policy.
- Existing reverse-forward listener on `127.0.0.1:10001` remained up.
  WSL 10002 was offline in its on-demand mode; candidate 10003 was
  not listening. Oracle MCP and Raspberry were healthy.
- Existing pairing HTTP service was live. New device-code HTTPS
  `/pairing/device/health` continued returning 404.

## Inventory implementation

`src/ai_lab_gateway/device_code_root_inventory.py` has a pure, bounded
implementation of **read-only inventory**. Its wrapper
`scripts/audit_device_code_production.py` accepts only
`--audit-paths-only` and requires actual root. It is **not an MCP tool**
and cannot configure, activate or provision anything.

When an operator runs the reviewed code as root in a separate trusted
Oracle console, the audit:

1. Obtains the actual running `ai-lab-gateway.service` process PID from
   systemd and reads **only** the allowlisted
   `AI_LAB_DEVICE_REGISTRY` environment path. It does not output any
   environment variable values except this safe path; all other entries
   are discarded. The default registry path is used only when the
   override is truly absent.
2. Runs OpenSSH `sshd -T -C user=tunnel,...` as root, and resolves the
   effective `AuthorizedKeysFile` relative to the actual tunnel Unix
   home. Unsupported `%...` substitutions or path traversal are denied
   instead of guessed.
3. Reports owner, group and mode using `lstat`, never reading/printing
   private SSH key content or following symbolic links.
4. Inspects the Gateway service account's default
   `~/.ssh/known_hosts` **as a candidate, not as independently proven
   effective SSH-client configuration**. The current Python SSH executor
   uses `StrictHostKeyChecking=yes` without an explicit
   `UserKnownHostsFile` override, but service-level SSH config files may
   override OpenSSH defaults. Root review must verify the effective
   target host trust source independently.
5. Reports only device IDs, SSH user, assigned ports and existing
   management **file paths**, never the private key bytes or bearer tokens.
   Its report is a diagnostic, **not an activation authorization**.

The previous hardcoded paths in
`device_code_root_environment.py` and
`device_code_root_transaction.py` are **hypotheses**, not reconciled
production facts. They must not be used by an installer until the
administrator compares them against the root audit and adjusts the
source with independent review and further tests.

## Validation and next gate

GitHub CI: https://github.com/fabianodebastiani/ai-lab-gateway/actions/runs/38827258103

- The unprivileged job discovered 151 tests and passed 133; 18
  root-only cases were intentionally skipped.
- The isolated root job passed all 18 of those root-only tests
  (13 atomic candidate SSH and 5 protected key identity tests).
- Total: **151 distinct passing cases**, no failures.

The root-console audit itself is not yet exercised on production.
No keys, services, daemon configuration, registry or listener were
altered on the Oracle by this audit or by this CI run.

**Next gate:** after verifying and reviewing the exact script version and
its supply-chain provenance, run the audit **read-only in a trusted
human-administered root console**. Review the resulting metadata before
modifying production constants or beginning SSH candidate provisioning.
Keep WSL 10002 credentials and Raspberry 10001 intact.


## Root-console operator observations — 2026-10-15

The authorized operator executed **read-only** commands on the real Oracle
as Unix account `ubuntu`, confirmed `sudo -n whoami` returns `root`,
then ran `sudo -n sshd -T -C user=tunnel,host=gateway.debasti.com,addr=127.0.0.1`
and root `stat` on fixed candidate paths (output supplied in the project
conversation; no SSH key bytes disclosed):

```text
maxsessions 0
passwordauthentication no
gatewayports no
allowtcpforwarding remote
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
authenticationmethods publickey
/var/lib/ai-lab-tunnel/.ssh | directory | tunnel:tunnel | 700
/var/lib/ai-lab-tunnel/.ssh/authorized_keys | regular file | tunnel:tunnel | 600
/var/lib/ai-lab-tunnel/.ssh/authorized_keys2 | absent
/var/lib/ai-lab-gateway/.ssh | directory | ai-lab-gateway:ai-lab-gateway | 700
/var/lib/ai-lab-gateway/.ssh/known_hosts | regular file | ai-lab-gateway:ai-lab-gateway | 600
/etc/ai-lab-gateway/devices.json | regular file | root:ai-lab-gateway | 640
```

This *confirms existence, exact immediate ownership and basic permissions*
of all three production input paths configured in
`device_code_root_environment.py`, and confirms that the actual OpenSSH
server searches the `tunnel` account's `authorized_keys` as expected.
The missing optional `authorized_keys2` is not an error.

**Still to verify separately before staging:** contents/semantics of the
protected device registry (without revealing secrets), expected target
host entry in actual Gateway known_hosts, that the Gateway service really
uses that OpenSSH client host-key source, all ancestor trust, candidate
keys and approval handoff. No root-owned candidate files/services were
installed; no privileged transaction was invoked on Oracle.
