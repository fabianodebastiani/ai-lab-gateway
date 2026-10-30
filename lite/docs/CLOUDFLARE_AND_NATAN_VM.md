# Cloudflare DNS and Natan's dedicated Lite VM

Status: PREPARED ONLY, not deployed. The original AI Lab Gateway and the Oracle experiments VM must stay untouched.

## Architecture

ChatGPT / browser -> HTTPS 443 -> ai-gateway-lite.debasti.com -> Caddy -> localhost:8010 -> Lite MCP + admin UI.
INITIAL PILOT: Lite -> local 127.0.0.1:22 OpenSSH -> distinct no-sudo `lite-target` account on the same VM.
FUTURE MULTI-DEVICE: Lite -> existing WireGuard private network -> non-root SSH accounts on approved targets.

WireGuard peer configuration, target access and private routing are maintained separately and are NOT managed by the Lite. No WireGuard is needed or planned for the initial pilot.

## What is ready

- Auth0 tenant existing; separate Lite API audience `https://ai-gateway-lite.debasti.com/mcp`.
- `gateway:read` and `gateway:control` granted to existing ChatGPT CIMD client in user-delegated mode.
- Lite Admin regular web app configured for `/auth/callback`, `/admin` logout and hostname Web Origin.
- Existing Google social connection enabled for Lite Admin, using Auth0's development social credentials for tests only.
- Lite application, SQLite grants, test suite, Caddyfile and systemd unit committed to the `gateway-lite` branch.

## Cloudflare DNS preparation

Open Cloudflare -> select `debasti.com` -> DNS -> Records.

**Do not create a placeholder A record pointing to either existing Oracle VM.** We need Natan's VM public IP first. There is no reserved domain requirement; the hostname can simply be created when the IP becomes available.

Once the VM public IP is confirmed and the target has its own Caddy service:

| Field | Value |
| --- | --- |
| Type | A |
| Name | ai-gateway-lite |
| IPv4 address | The NEW VM's real public IPv4 |
| Proxy status | DNS only (gray cloud) for the initial MCP/OAuth acceptance |
| TTL | Auto |

Do not modify `gateway.debasti.com` or any of the existing Cloudflare DNS records. If `ai-gateway-lite` already exists, inspect it before editing.

With DNS only, TLS is terminated by Caddy on the VM. Caddy should be installed with the isolated Lite Caddyfile: `lite/deploy/Caddyfile`. The public VM needs inbound 443 and, for default HTTP-01 certificate issuance, 80; port 8010 remains strictly localhost. Firewall and OCI security-list/NSG controls must both allow the intended traffic. No public SSH port should be opened for target Linux devices.

After DNS and Caddy become reachable, validate:
```bash
dig +short ai-gateway-lite.debasti.com A
curl -i https://ai-gateway-lite.debasti.com/.well-known/oauth-protected-resource/mcp
curl -i https://ai-gateway-lite.debasti.com/mcp
curl -I https://ai-gateway-lite.debasti.com/admin
```

Expected MCP discovery lists resource `https://ai-gateway-lite.debasti.com/mcp`, scopes `gateway:read` and `gateway:control`, and the Auth0 authorization-server issuer. A request to `/mcp` without authorization must be rejected with HTTP 401. Admin page must never authorize the user merely because they have a Google login.

After the basic MCP tests succeed, evaluate enabling Cloudflare Proxy (orange cloud), with SSL/TLS mode **Full (strict)**. At that stage verify ChatGPT streamable HTTP, authorization callback, well-known endpoints and any WAF rules. Do not enable Cloudflare Access or Javascript challenges for the machine-facing MCP paths without testing client support.

## Natan VM prerequisite checklist

- Real target: Natan's `godel-testes-01-vnic`, Ubuntu 22.04.5 x86_64 (2 vCPU, ~1 GB RAM, ~39 GB free), with local sudo for one-time service setup; preserve the existing `smartgrid` service and ports 3031/8080.
- Install Python 3.12 separately without replacing Ubuntu 22.04's default Python 3.10.
- VM's public IPv4, SSH administrative access (kept private), and current free resources.
- Initial target is this very VM via SSH at `127.0.0.1:22`, with dedicated non-sudo `lite-target` identity and pinned SSH host key. Do NOT configure WireGuard in this phase. Enable the separately guarded loopback pilot flag and an exact `127.0.0.1/32` allowlist.
- Dedicated `ai-lab-gateway-lite` system identity, separate code/config/SQLite directories.
- Dedicated private Ed25519 SSH keys, pinned host fingerprints, target's non-root account.
- Auth0 domain, Lite Admin client ID, and the client secret installed only on the VM in a protected environment file; Lite initial administrator's stable Auth0 subject ID (not email) in that same protected runtime configuration.
- Never paste OAuth client secrets, SSH keys, session cookies, or tokens into ChatGPT/GitHub.

## Implementation sequence on the dedicated VM

1. Validate VM OS, disk, memory, public IP, currently occupied services and local sshd (read-only). Do not configure WireGuard.
2. Install and configure only the isolated Lite service; do not use production Gateway's directories or keys.
3. Check unit tests, then local 127.0.0.1:8010 endpoints.
4. Create DNS A record; enable Caddy and confirm valid TLS.
5. Verify Google/Auth0 admin login, unapproved-user denial and access-grant workflow.
6. First register the same VM as `local-pilot` and test real SSH to `127.0.0.1:22` under the dedicated no-sudo `lite-target` user. Then connect two distinct ChatGPT users and check scopes, grants, command/file operations, and immediate revocation.
7. Before server deployment, export only Lite source to the confirmed new PRIVATE GitHub repo; do not reuse the public original history. Do not choose between similarly named private repositories until the owner confirms the exact destination.

## Temporary test alternative

If the dedicated VM becomes unavailable, a temporary instance of the Lite could run on the existing experimental Oracle VM on a **separate loopback port, service account, database, and domain**, with an explicit removal plan. However this VM hosts other ongoing services and is not recommended as the default. The original Oracle Gateway must never be used for this test.

No temporary test has been started; no DNS/VM change has been performed.

## Verified observations on 2026-10-30

- DNS `ai-gateway-lite.debasti.com` resolved to `147.15.110.165` (Natan VM, subject to admin confirmation).
- Original device-code pairing completed with device ID `godel-testes-01-vnic-153e7b3e` via the original Gateway MCP and was verified online as the no-sudo `ai-gateway` user.
- OS: Ubuntu 22.04.5, Python 3.10.12, architecture x86_64; 2 vCPUs, ~956 MiB RAM, ~2 GB swap, ~39 GB disk free.
- Existing service `smartgrid`, listeners 0.0.0.0:3031 and 127.0.0.1:8080. Port 8010 is currently free. No WireGuard interface or wg command installed, by design for the pilot.
- The separate GitHub names `ai-lab-lite` and `ai-gateway-lite` both exist as private repositories and are empty; confirm destination before the code snapshot.
- This is a plan/code adjustment only. No target account, SSH key, Lite service, Python runtime, Caddy, firewall or WireGuard configuration has been changed on Natan's VM.
