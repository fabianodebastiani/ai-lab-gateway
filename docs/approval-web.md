# Independent human approval web interface

Status: **deployed but awaiting human credential enrollment** (2026-10-14 UTC).
This is an experimental, self-hosted AI Lab Gateway feature.

## Goal and boundaries

A ChatGPT/MCP principal can request a **predefined** privileged operation, but
cannot approve its own request through MCP. Approval instead requires a human
in a separate HTTPS web interface with a dedicated local password and a
time-based one-time password (TOTP). The web app is an independent, unprivileged
systemd service; it has no sudo permission.

The security flow is:

```text
ChatGPT + Auth0 OAuth
    -> gateway MCP privilege_request (subject + device policy)
    -> broker operational Unix socket (gateway service UID only)
    -> request stored pending in root-owned broker database

Human browser -> HTTPS gateway.debasti.com/approvals
    -> approver password (short-lived secure browser session)
    -> TOTP per approval or denial + CSRF + same-origin enforcement
    -> dedicated approval Unix socket (approver service UID only)
    -> broker verifies SO_PEERCRED and changes request to approved/denied

ChatGPT -> privilege_execute with original verified OAuth subject
    -> broker checks same subject, expiry, approval, operation whitelist
    -> consumes request before executing fixed argv without a shell
    -> audit record
```

## Deployment verified

- `ai-lab-gateway` systemd service: non-root MCP on `127.0.0.1:8000`.
- `ai-lab-privilege-broker`: root, hardened systemd, two Unix sockets:
  - `/run/ai-lab-privilege-broker/broker.sock`, root:ai-lab-gateway 0660
  - `/run/ai-lab-privilege-broker/approval.sock`, root:ai-lab-approver 0660
  - socket directory root:root 0711 (traversable but not listable).
- `ai-lab-approval-web`: runs as dedicated locked Unix service identity
  `ai-lab-approver`, listens on **127.0.0.1:8001** only, no sudo.
- Caddy reverse proxy routes `/approvals*` to localhost:8001 and leaves
  the MCP/OAuth backend behind localhost:8000. The public endpoint is
  **https://gateway.debasti.com/approvals**.
- Socket negative tests: Gateway user cannot connect to approval socket;
  approver user cannot connect to operational socket. The approver user can
  connect to its own socket, after the broker verifies Linux peer credentials.
- `/approvals/health` responds HTTP 200, MCP endpoint continues returning
  HTTP 401 without OAuth. Approval page responds HTTP **503 until enrolled**.
- Credentials file `/etc/ai-lab-approval/credentials.json`, root:ai-lab-approver
  0640; directory 0750. It contains a salt, scrypt password hash, and
  symmetric TOTP secret (never commit this file).
- TOTP replay marker `/var/lib/ai-lab-approval/last_totp_step`, service user
  only, 0600, updated atomically so code reuse is rejected across restarts.
- Browser protections: secure, HttpOnly, SameSite Strict 15-minute session
  cookie; anti-CSRF token on decisions; strict Origin and Host check;
  HTTPS via Caddy; strict content security policy; no external scripts;
  login/OTP rate limiting and one-use TOTP windows.
- **48 pytest tests passing** on Oracle after web interface and persistent
  TOTP protection were introduced. These include end-to-end local HTTP tests
  with *synthetic test credentials only*; a live human login has **not yet**
  been performed as of this entry.

## One-time human credential enrollment

**Must run locally by the human over the trusted SSH/OCI terminal as `ubuntu`:**

```bash
sudo /usr/local/libexec/ai-lab-approval-web --enroll
```

The command generates a strong random password and an RFC 6238 TOTP seed,
stores only the scrypt hash of the password and root-managed TOTP secret, and
prints **the password and the TOTP seed ONLY in that terminal**.
Never paste those values into ChatGPT, MCP, GitHub, issue comments, or email.

The human should save the password in a password manager and add the printed
TOTP seed to a phone authenticator app (Google Authenticator, Microsoft
Authenticator, etc.) using the manual setup mode (6 digits, SHA-1, 30 seconds).
Enrollment refuses to overwrite existing credentials; no accidental reset.

After enrollment:

1. Open `https://gateway.debasti.com/approvals` over HTTPS.
2. Sign in using the generated local password. This reveals only pending
   privileged requests; it **does not grant approval**.
3. For a request, inspect the operation, requester, device, and TTL.
4. Enter a *fresh* 6-digit authenticator code and choose Approve or Deny.
   An already used 30-second code cannot approve another request.
5. ChatGPT calls `privilege_status` and `privilege_execute`. The request
   executes once and subsequent attempts fail.

For a safe acceptance test, use `gateway-service-status` (read-only).
The restricted root-write self-test may also be used, but avoid broad
operations until explicitly reviewed and added to the broker whitelist.

## Operations and safety model

Operations are fixed argv tuples in
`scripts/privilege_broker_daemon.py`; user-supplied shell commands and paths
are **not** accepted in human-approval requests. Requester identity comes from
the verified OAuth token in the MCP server. The **web approver identity is not
the same** as the ChatGPT/OAuth principal; it is protected by a local password,
a TOTP secret, a Unix service identity, and a separate socket. The approver
can only list pending requests or approve/deny a specified pending request.
The web app never receives root UID or SSH management keys.

The broker audit is rooted under `/var/lib/ai-lab-privilege-broker` and its
requests persist across broker service restarts. All privileges are single-use,
expire automatically, and can be revoked. Approvals have a one-hour
pending deadline and grant TTL is measured after approval.

**Important limits:** the TOTP credential is stored on the same Oracle VM,
so host-root compromise defeats this boundary; it is not equivalent to a
hardware-backed or out-of-band security authority. Brute-force throttling
uses process memory and resets on web service restart; distributed attacks
and availability require further hardening. The UI is an additional independent
human consent factor, not a replacement for backup access through `ubuntu`.

## Operational checks

```bash
sudo systemctl is-active ai-lab-gateway ai-lab-privilege-broker ai-lab-approval-web caddy
curl -I https://gateway.debasti.com/approvals
curl -fsS https://gateway.debasti.com/approvals/health
sudo stat -c '%a %U:%G %n' /run/ai-lab-privilege-broker/*.sock
sudo /usr/local/libexec/ai-lab-privilege-brokerd --list
```

If the public route breaks, restore the Caddy backup from before this deployment:

```bash
sudo cp /etc/caddy/Caddyfile.before-approvals-v05 /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Do not store passwords, TOTP seed, recovery codes, production authorization
policy, or private SSH keys in the repository.

## Login troubleshooting (2026-10-14)

The initial credential file was verified present and readable by the
`ai-lab-approver` service, with the expected schema and scrypt hash length.
A self-contained synthetic password test validated the hashing and comparison
routines without accessing or disclosing the real password or TOTP secret.

The enrollment CLI originally printed the password with two spaces between
`Senha:` and the generated URL-safe password. Version v0.5.2 now prints a
single separating space and accepts accidentally copied leading/trailing
whitespace during login; the generated password itself contains no whitespace.
All **48 pytest tests passed** after the patch and the HTTPS approval endpoint
was confirmed online. If login still fails, check the stored password carefully
inside the password manager; do not paste secrets into chat or issue comments.

## v0.5.4 Chrome login repair — 2026-10-14

Real Chrome sessions rejected a form POST with `Origem ou rota inválida`
before password verification. Login now uses a 10-minute random form CSRF
token tied to a separate Secure, HttpOnly, SameSite=Strict login cookie.
Absent Origin and Fetch Metadata headers no longer break same-origin login,
but supplied cross-site Origin or Fetch-Site remain forbidden. Approval and
denial still require authenticated session CSRF and per-decision TOTP.
A fresh GET of `/approvals` is needed to obtain the new form and cookie.
The Oracle deployment passed **50 pytest tests**; web, broker, and MCP remain
active. A new human-browser attempt remains to be verified.

## Browser POST compatibility follow-up — 2026-10-14 (v0.5.5)

A Chrome session still displayed `Origem ou rota inválida` after the prior
login form-CSRF fix, before password checking. The server's earlier approach
also required metadata such as `Origin` and `Sec-Fetch-Site`, which can
vary with extensions and intermediaries.

In v0.5.5, the application validates the exact public Host and
`application/x-www-form-urlencoded` form encoding; CSRF resistance is
enforced using the unpredictable 10-minute login form token tied to its own
`Secure; HttpOnly; SameSite=Strict` cookie. Approval/denial still requires
the authenticated session's CSRF token **plus a fresh TOTP code**. Neither
endpoint trusts the mere presence of a browser Origin header.

Synthetic HTTPS tests through Caddy confirmed that standard, omitted and
nonstandard Origin/Fetch-Metadata combinations all passed the form gate
and reached password validation when paired with a valid form token. Requests
cannot skip the cookie-bound CSRF check. The Oracle installation passed
**50 pytest tests**; the approval service, privilege broker and MCP remained
active; `/approvals` returned 200 and `/approvals/health` returned 200.
A real browser login with v0.5.5 is awaiting human confirmation. No real
credential content was accessed or disclosed in the diagnostic.

## First verified human approval in the browser — 2026-10-14

The operator entered the TOTP code in the HTTPS approvals website and clicked Approve on a pending `gateway-service-status` request. The ChatGPT MCP client then checked the two pending tests and confirmed that one had changed to `approved` while the other was still `pending`.

The approved request was executed through `privilege_execute` via the real Auth0-authenticated MCP connection: `exit_code=0`, `stdout="active\\n"`, status `consumed`. A second execution returned `not_approved` with status `consumed`, confirming single-use enforcement. The other pending duplicate was explicitly revoked via `privilege_revoke` to avoid two identical entries in the approvals UI.

This verifies real **browser login + Google Authenticator approval → root broker → MCP execution → replay denial**. No passwords, TOTP secrets or codes are stored here.

UI observation: duplicate-looking TOTP fields were actually two independent pending requests bearing the same operation name; each request has its own form and approval deadline. Future UI improvement: show shorter request identifier, distinguish requests and group or de-duplicate repeated test requests.
