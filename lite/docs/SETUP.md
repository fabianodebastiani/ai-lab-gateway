# Isolated deployment runbook (DO NOT deploy to the existing Gateway)

The initial pilot runs on Natan's existing Ubuntu 22.04 VM, with Python 3.12 installed separately (do not replace system Python 3.10). The first SSH device is this SAME VM, reached over 127.0.0.1:22 using a separate non-sudo `lite-target` login. **No WireGuard is required during the pilot.** The later multi-device production design uses pre-existing WireGuard routing managed outside the Lite project. Preserve the existing `smartgrid` service, port 3031, and locally bound service on 8080.

## 1. DNS and HTTPS

Create a DNS A record for ai-gateway-lite.debasti.com pointing to the new VM's public IP. Reserve a stable IP if available. Open only the needed inbound ports: HTTPS 443 and, if Caddy's certificate flow needs it, HTTP 80; administrative SSH access must be restricted separately. Do not expose port 8010 or target SSH ports to the Internet. Caddyfile template is in deploy/Caddyfile.

## 2. Auth0 tenant (existing) and Google

Keep the ORIGINAL Gateway API and its resource identifier unchanged.

- Create a NEW Auth0 custom API named AI Lab Gateway Lite MCP with identifier/audience: https://ai-gateway-lite.debasti.com/mcp.
- Configure RS256 JWT, permissions gateway:read and gateway:control.
- Enable Auth0's Resource Parameter Compatibility Profile and CIMD registration if not already enabled. Reuse the previously imported ChatGPT CIMD client where supported, and grant its user-delegated access to the new Lite API. Keep DCR disabled unless explicitly required.
- Create a separate Auth0 application type Regular Web Application for the administrative panel. Configure Allowed Callback URL: https://ai-gateway-lite.debasti.com/auth/callback; Allowed Web Origins: https://ai-gateway-lite.debasti.com; Allowed Logout URLs (if desired): https://ai-gateway-lite.debasti.com/admin.
- Enable the existing Google social identity connection for this web app. For development and a limited controlled functional pilot, reuse the Auth0-provided Google social DEVELOPMENT keys (no new Google Cloud OAuth client necessary yet). These shared keys are explicitly NOT permitted for production/real operational user traffic: replace them with your own Google OAuth Client ID/Secret before non-test use. The website's hostname is NOT an Auth0 custom login domain; development social keys may not work with Auth0 custom domains.
- Record the stable Auth0 subject for the first administrator from the Auth0 user profile. This is not the email address. Put it into LITE_ADMIN_SUBJECTS in the protected VM environment file.
- The ChatGPT MCP flow and web admin login are independent Auth0 clients/flows. Do not reuse web client secret for the MCP, and never put it in Git.

## 3. Linux service account and application

On the NEW VM, create a dedicated non-root identity and directories:
- /opt/ai-lab-gateway-lite : code and virtual environment
- /etc/ai-lab-gateway-lite/gateway.env : environment, root-only 0600
- /var/lib/ai-lab-gateway-lite/ : SQLite database and JSONL audit
- /var/lib/ai-lab-gateway-lite/keys/ : 0700, unique SSH private key per device
- /var/lib/ai-lab-gateway-lite/known_hosts : pinned verified SSH public host keys

Install Python 3.12, venv, OpenSSH client and Caddy on Ubuntu. Copy the contents of the lite/ directory to /opt/ai-lab-gateway-lite on the new VM; do NOT copy an old production configuration. Create a virtualenv and run pip install -e '.[dev]' for development or pip install . in production.

Copy .env.example to /etc/ai-lab-gateway-lite/gateway.env and replace ALL placeholders. Set file ownership so the systemd service account can read only what it needs, while other users cannot. Generate a random 48-byte-or-longer session secret using the command described in the example, and use a new web Auth0 client secret. Do not use the example network prefix unless it matches the actual WireGuard network.

Install deploy/ai-lab-gateway-lite.service under systemd with a dedicated, non-root User and Group. Install the Caddyfile for the Lite hostname, keep Python listening at 127.0.0.1:8010, and verify local firewall rules before restarting Caddy.

## 4. Initial pilot: same-host SSH (no WireGuard)

The initial end-to-end target is the Lite VM itself; the transport must still be a REAL OpenSSH client/server connection, never direct local shell execution.

1. The VM administrator provisions a dedicated `lite-target` non-root account, with **no sudo, no privileged groups and no access to the original `ai-gateway` user's SSH material**. The separate service identity `ai-lab-gateway-lite` must have no interactive login or general sudo.
2. Create a new per-device Ed25519 key in the Lite runtime-owned keys directory. Install ONLY the PUBLIC half in `lite-target`'s `authorized_keys`; keep the private half in Lite's 0700-owned key directory, mode 0600.
3. Verify the VM's real sshd Ed25519 host public key through the local admin channel; pin it explicitly for `127.0.0.1` in Lite's private `known_hosts`. Never enable `StrictHostKeyChecking=no`.
4. In the protected service environment, set `LITE_ALLOWED_SSH_CIDRS=127.0.0.1/32` and `LITE_ENABLE_LOOPBACK_TARGET=1` — both required. This pilot exception accepts ONLY `127.0.0.1:22` as SSH destination and `lite-target` as SSH user; it rejects localhost aliases and ordinary public addresses.
5. Register `local-pilot` with `host=127.0.0.1`, `port=22`, `ssh_user=lite-target` and the basename of the new private key. Initial access grants are empty.
6. Verify real SSH `hostname`, read-only commands, then separately authorized harmless file-write/read/cleanup in `/home/lite-target/`. Test SSH host-key rejection, revoked grants, user separation and device disable. **Do not use this pilot to modify Caddy, systemd, the smartgrid service, the original `ai-gateway` account, root files or sudoers.**

To restore normal WireGuard-only restrictions, remove `LITE_ENABLE_LOOPBACK_TARGET` and replace `LITE_ALLOWED_SSH_CIDRS` with the independently maintained private VPN CIDRs. Without the explicit flag, loopback remains rejected.

## 4b. Later: WireGuard + SSH targets

1. At a later stage only, independently configure the VM as a WireGuard peer so it can route to each intended Linux host.
2. For each device, provision a dedicated non-root SSH target account without sudo; create one management Ed25519 keypair on the Lite VM under its key directory. Never share a private key across hosts.
3. Install ONLY the corresponding public key in that target account's authorized_keys.
4. Obtain the SSH target host key fingerprint over a separate trusted channel. Verify it manually before adding the exact host-key entry to the Lite VM's known_hosts file. Never automatically accept unknown SSH hosts.
5. Set the real LITE_ALLOWED_SSH_CIDRS, e.g. an actual pre-existing private WireGuard subnet. DNS names and public target IPs are intentionally rejected.
6. From the web panel, register device ID, display name, literal WireGuard IP, SSH port, restricted SSH user and the basename of its preinstalled private key. The panel never generates keys or changes WireGuard routes.

## 5. Admin and end-user workflow

1. Administrator opens https://ai-gateway-lite.debasti.com/admin and logs in via Google through Auth0.
2. Their Auth0 subject must exactly match LITE_ADMIN_SUBJECTS to see admin controls.
3. User signs in once to /admin using Google; their Auth0 subject is then registered, but with NO device grants.
4. Administrator sees that user and explicitly grants status/read_file/exec/write_file per device.
5. User adds the https://ai-gateway-lite.debasti.com/mcp endpoint to ChatGPT using OAuth. The MCP API checks Auth0 JWT scopes and SQLite permissions on EACH call.
6. A revoked grant blocks the next call, even if the OAuth access token remains otherwise valid.
7. The panel's "Verificar" link tests a device's SSH reachability on demand.

The panel itself never authorizes MCP access just because someone logs in.

## 6. Tests and go-live gates

- Run python -m pytest -q tests.
- Test HTTPS resource metadata at /.well-known/oauth-protected-resource/mcp and missing-token rejection on /mcp.
- Test authn/authz negatives, two real different users, revoked grants, SSH wrong host key, disallowed CIDR, target offline, service reboot, and log output.
- Ensure both Oracle services are separate and no config/port of the ORIGINAL Gateway is changed.
- Do not classify the Lite as production ready before full end-to-end checks.

## 7. Repository privacy

The branch currently resides in a PUBLIC parent repository and therefore remains public until repository visibility changes. It contains no runtime secrets. After testing, use the contents of lite/ to create a CLEAN new PRIVATE repository, not the full ancestor history.

Do NOT privatize the original repository while its anonymous raw.githubusercontent.com installer remains necessary. Prepare a private authenticated or independently verified distribution path first. GitHub visibility is an administrative action in the repository Settings and is not currently exposed by this GitHub connector.
