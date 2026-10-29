# AI Lab Gateway Lite

An independently deployable MCP gateway for authorized ChatGPT users to access registered Linux devices over an existing WireGuard network.

Status: initial implementation, not deployed. This directory will become a standalone private GitHub repository after testing.

## Boundaries

- ChatGPT -> Auth0 OAuth -> HTTPS MCP.
- Browser -> Auth0 Google login -> administration panel (administrator approval required).
- MCP -> per-subject, per-device, per-action database permissions -> SSH over WireGuard.
- Gateway does not create/manage WireGuard peers or expose target SSH publicly.
- No reverse SSH tunnels, pairing codes, automatic sudo, or approval broker.
- Dedicated non-root service and deny-by-default permission checks.

See docs/IMPLEMENTATION_PLAN.md.

## Proposed endpoint

- MCP: https://ai-gateway-lite.debasti.com/mcp
- Admin: https://ai-gateway-lite.debasti.com/admin
- OIDC callback: https://ai-gateway-lite.debasti.com/auth/callback

Create a separate Auth0 API audience and separate Regular Web Application for the panel, in the existing tenant. Never reuse the original Gateway audience or secrets.

This subdirectory is isolated on the gateway-lite branch. Do not deploy it to the original Oracle gateway.
