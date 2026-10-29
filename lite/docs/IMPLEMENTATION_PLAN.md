# Lite rollout and security contract

## Confirmed choices (2026-10-29)

- Initial development branch: gateway-lite, cut from main.
- Future standalone repository: private, shared with invited collaborators.
- Original repo: private only after public installer dependencies are migrated.
- VM: separate Oracle Cloud Always Free instance, within usage limits.
- Hostname: ai-gateway-lite.debasti.com, HTTPS via Caddy.
- Identity: existing Auth0 tenant + Google login; distinct Lite resource/API and web app.
- Device network: externally managed WireGuard; Lite uses pre-existing private IP connectivity.
- Target access: dedicated non-root SSH user, per-device SSH keys and pinned host keys.

## Build phases

1. Branch, documentation and independent lite/ application without touching production.
2. SQLite registry of devices, OAuth users and subject/device/action permissions, with audit.
3. VPN-aware SSH backend with strict host key verification and bounded execution.
4. Auth0 resource server MCP with six basic operations, deny-by-default.
5. Auth0 OIDC admin web UI for managing users/devices/grants.
6. Tests, CI, isolated deployment and two-user acceptance.
7. Move into new PRIVATE repository with clean snapshot, not historic Git.
8. Privatize original only after replacing public-code installers/updaters.

## Security invariants

- Authentication is NOT authorization; a valid Google login gets no grants.
- Admin identity uses stable Auth0 subject, never email as permission key.
- A panel admin is not automatically granted MCP execution rights.
- Every MCP action checks OAuth scope, subject/device/action grant, and active device.
- MCP audience is https://ai-gateway-lite.debasti.com/mcp, never original gateway audience.
- SSH targets are literal IP addresses within explicitly permitted WireGuard CIDRs.
- Use isolated private SSH keys and pinned known_hosts; do not use TOFU.
- No SSH private keys, OAuth tokens, command output, or file contents in audit logs.
- Browser app is HTTPS only with secure session cookies and CSRF checks on mutations.
- New OAuth users have zero permissions until approved.
- Root, sudo, pairing and VPN configuration are out of scope.

## Privacy blocker: original repository

The original repo is public. The installer scripts/install_ai_lab_device.sh downloads pinned source using raw.githubusercontent.com without authentication. A private repo will break that anonymous path. Migrate verified distribution to a separately hosted signed artifact or authenticated private channel and test device recovery/update before changing visibility. Existing public copies/forks remain outside the owner's control. Check history for secrets.

The current GitHub integration does not expose a repository visibility mutation; a repository admin can use Settings -> General -> Danger Zone -> Change repository visibility.

## Acceptance

- Distinct Auth0 API and web application, owned Google social credentials before production.
- Unauthorized and unapproved requests are denied; valid OAuth alone grants no device access.
- Users A/B see only permitted devices and actions.
- Revocations take effect immediately.
- Out-of-CIDR SSH requests and invalid host keys fail closed.
- Commands time out; writes limited; audit excludes secrets and outputs.
- Unit tests pass; full two-user ChatGPT integration verified.
- Original Gateway stays online and unchanged.
