# One-code Linux pairing — observed production checkpoint (2026-10-15)

## User experience target

A ChatGPT user already authenticated to the Gateway through Auth0 asks to
connect a new Linux. ChatGPT supplies **one public, stable command**. On
the Linux, that command fetches a SHA256-pinned client and initiates outbound
HTTPS to the Gateway. Linux displays **one** human-readable code. The
operator types it into ChatGPT; ChatGPT looks up the exact pending device
using its authenticated principal, shows the identity, and asks the user
to confirm. The Gateway provisions isolated SSH trust; Linux starts its
reverse tunnel and the MCP connects under **Restricted** privileges.

No second typed code, no forced login to an unrelated portal and no sudo
grant as a side effect of enrollment. Privilege-mode selection is a
**separate** workflow under ADR-027.

## What is actually deployed and verified

Observed at **2026-10-16 01:41 UTC**, Oracle `ai-lab-gateway-01`:

- `ai-lab-device-code.service` is active as Unix user `ai-lab-pairing`,
  not root; binds only to `127.0.0.1:8003`. It persists a private SQLite
  store/HMAC key under `/var/lib/ai-lab-pairing/device-code`.
- Caddy serves `https://gateway.debasti.com/pairing/device/*` through
  the loopback service. `/pairing/device/health` responds HTTP 200.
  Legacy `/pairing/health` remains HTTP 200; unauthenticated MCP
  `/mcp` remains HTTP 401.
- `/run/ai-lab-device-code/operator.sock` is
  `ai-lab-pairing:ai-lab-gateway` mode `0660`, with the directory
  `0711`. An independent live test confirmed the `ai-lab-gateway`
  UID can connect but invalid codes are denied; `ai-maintenance` is
  denied at Unix socket permissions.
- MCP server was restarted with feature flag
  `AI_LAB_DEVICE_CODE_MCP_ENABLED=1`. Source includes Auth0-scoped
  `pairing_lookup_code`, original-code `pairing_confirm_single_code`
  and legacy experimental second-code tool. **The existing ChatGPT
  app catalog may need to be refreshed to discover new tools**. It has
  not yet been proven live through ChatGPT OAuth in this conversation.
- On the real **WSL through the preexisting v1 management connection**,
  a SHA256/Git-blob-verified version of the client ran with
  `--no-wait`. It created its own new Ed25519 credentials, requested
  and proved a pending session via the **public HTTPS Gateway**, and
  printed exactly **one** device code. The first real bootstrap smoke test
  also passed the fixed client SHA256 verification and generated a separate
  pending code. No code, device secret, SSH private key or token was copied
  into the project document. **Both were staging sessions, never approved,
  activated or used for an SSH connection.**
- Existing Raspberry `10001` and WSL `10002` are online. Candidate
  `10003` has no listener, and no existing SSH identity was replaced.
- `ai-maintenance` temporary NOPASSWD sudo expired at
  **2026-10-16 01:40:36 UTC**, verified by `sudo -n id -u` returning
  a password-required denial. This project change adds no new root grant.

## Code and release

- New original-code confirmation requires the **same already Auth0-bound
  principal** that reserved the proven device code, with limited failed
  attempts and consume-once behavior. Wrong principal/wrong code/replay
  are covered by laboratory regression tests.
- A new production runner and hardened systemd service are in
  `scripts/run_device_code_production.py` and
  `deploy/ai-lab-device-code.service`.
- `scripts/install_ai_lab_device.sh` now defaults to the public Gateway,
  pins the one-code client to immutable Git commit
  `b3b5f2584381c32700fcb22080913680e44a7290`
  and verifies SHA256
  `e4a9a0f3b1fb8bc66669d411d8f1f75711fbd5f813cdbc0f96546397c90be0d2`.
- This bootstrap presently **prepares and proves the device identity and
  polls an offer**. It does NOT automatically install sshd, provision
  root-controlled authorized_keys, enable the tunnel or activate MCP.
  Do not announce it as a finished one-command installer yet.

## Non-negotiable completion gaps

1. **Human authorization through real ChatGPT MCP:** current authenticated
   plugin must discover new tools after refresh. The single pairing
   code + Auth0-bound redemption is implemented; a model-authored call
   alone does NOT prove that the host obtained a separately verifiable
   human confirmation. Do not silently treat self-approval as host-attested.
   Keep independent confirmation as a fallback until equivalent host
   assurance is verified.
2. **Automatic, narrow SSH provisioning:** production root-controlled
   authorized_keys, per-device management keys and candidate port must be
   installed only after approved identity; target must install local
   management public key/sshd/tunnel service with its local admin's approval.
   The existing WSL `10002` and Raspberry `10001` must remain usable
   until separate acceptance and cutover.
3. **Production abuse controls:** anonymous HTTP currently sees loopback
   source behind Caddy for built-in peer quotas. This supplies a conservative
   shared/global quota but not real per-public-IP accounting. Add trusted
   reverse-proxy source binding before a broad public enrollment rollout.
4. **Final end-to-end acceptance:** no-prior-SSH Linux, one command, one code,
   authenticated ChatGPT approval, verified SSH identity, restricted exec,
   connect/disconnect behavior, revoke/replay denial and rollback.

## Rollback resources

- Caddy pre-change backup: `/etc/caddy/Caddyfile.before-20261016-one-code`.
- MCP server pre-change backup:
  `/opt/ai-lab-gateway/src/ai_lab_gateway/server.py.before-20261016-code`.
- Scope middleware pre-change backup:
  `/opt/ai-lab-gateway/src/ai_lab_gateway/scope_stepup.py.before-20261016-code`.
- New `ai-lab-device-code.service` can be separately disabled in an
  independent administrator recovery session without touching the
  existing pairing, Gateway, Raspberry or WSL tunnel services.
- A rollback must disable the new MCP feature flag and restore the old
  Caddy routing **before** removing the new service, with independent
  root access. No revocation/sudo bypass through MCP is acceptable.

Do not store pairing codes, OAuth subjects, tokens, raw production registry,
private keys or unredacted audit records in this repository.
