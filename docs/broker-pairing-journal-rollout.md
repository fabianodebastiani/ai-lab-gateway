# Oracle supervised pairing diagnostics (15/10/2026)

## Purpose

Add a **read-only, fixed-argument** operation to the existing independent,
human-approved root broker. No general sudo, root shell, sudoers modification,
privilege elevation window or self-approval is introduced.

Operation: `pairing-service-journal`

Exact command (single use only after password + TOTP web approval):

```text
/usr/bin/journalctl --unit=ai-lab-pairing.service --no-pager --lines=60 --output=short-iso
```

Existing broker security boundaries stay intact: Auth0 `gateway:control`
and device `privilege_request` scope, Unix SO_PEERCRED separation, independent
web approval, one-use consumption, expiry, subject binding and root-only audit.

## Prepared (not deployed as of document creation)

Source: `scripts/privilege_broker_daemon.py`, with a single new allowlisted
read-only action. Regression test added to `tests/test_privilege_broker.py`.

On Oracle, staged by the non-root MCP management account as:

```text
/home/ai-maintenance/privilege_broker_candidate.py
```

SHA-256 of that exact staged file:

```text
db3610b745d40bb5664628a58c53b359629c0f108443d7e41bbdd1b30aaff6c5
```

`python3 -m py_compile` passed. An isolated, unprivileged synthetic test
passed: fixed argv, invalid operation denial, approval required, subject
binding, one-use execution, replay blocked. Production broker has been
compared with the candidate: apart from a docstring comment, only the
three-line read-only action was added.

## One-time independent Oracle admin action

Run ONLY at the Oracle `ubuntu` terminal; do not run via the ChatGPT/MCP
SSH user. Verify the staged SHA-256 **first**:

```bash
sha256sum /home/ai-maintenance/privilege_broker_candidate.py
```

If and only if it matches the expected value, make a root-owned backup:

```bash
sudo cp -p /usr/local/libexec/ai-lab-privilege-brokerd /usr/local/libexec/ai-lab-privilege-brokerd.before-pairing-journal
```

Install the reviewed file with root ownership:

```bash
sudo install -o root -g root -m 0755 /home/ai-maintenance/privilege_broker_candidate.py /usr/local/libexec/ai-lab-privilege-brokerd
```

Restart ONLY the broker; do not restart MCP, Caddy, or the approval panel:

```bash
sudo systemctl restart ai-lab-privilege-broker
```

Check `systemctl is-active ai-lab-privilege-broker` and MCP
`gateway_status()` before requesting any privileged operation.

## Independent human approval and recovery

From ChatGPT: `privilege_request(operation="pairing-service-journal",
ttl_seconds=300)`. User opens
[https://gateway.debasti.com/approvals](https://gateway.debasti.com/approvals)
**directly** in a browser, reviews the operation, enters the existing
password and a fresh TOTP code, approves, and ChatGPT calls
`privilege_execute(request_id)` once. This is a log read, not permission
for arbitrary sudo or deployment.

If broker fails to restart or health checks fail, from the Oracle
`ubuntu` terminal:

```bash
sudo cp -p /usr/local/libexec/ai-lab-privilege-brokerd.before-pairing-journal /usr/local/libexec/ai-lab-privilege-brokerd
sudo systemctl restart ai-lab-privilege-broker
```

Preserve the recovery `ubuntu` account and old SSH identities. Never paste
passwords, TOTP seeds, private SSH keys, root authorization files or
production audit databases into chat or Git.

## Background

On 15/10, the pairing v2 installer `--check` passed, but `--apply`
failed because `http://127.0.0.1:8002/pairing/health` refused the
connection (curl exit code 7). The installer attempted rollback; a subsequent
MCP verification found gateway, broker, approval panel, and Caddy active,
Oracle management SSH working, and v2 pairing unit absent. The actual
pairing failure cause remains to be determined from the privileged journal.
