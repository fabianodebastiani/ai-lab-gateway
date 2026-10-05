# Authentication plan

The AI-facing MCP endpoint will use OAuth 2.1. Platform users are application
identities; they are not Unix users on the gateway.

## Resource server

The MCP gateway is the OAuth resource server. Its canonical resource identifier
is:

```text
https://gateway.debasti.com/mcp
```

The MCP endpoint remains:

```text
https://gateway.debasti.com/mcp
```

The resource server must publish protected-resource metadata at:

```text
https://gateway.debasti.com/.well-known/oauth-protected-resource
```

and reject missing/invalid credentials with a Bearer challenge that points to
that metadata.

Every accepted access token must be validated for signature, issuer, audience
(resource), lifetime and required scopes before an authenticated tool executes.

## Authorization server

Auth0 is the selected authorization server for the prototype. The gateway
remains provider-agnostic at the application boundary: it consumes standard
issuer/JWKS/audience/scope claims and does not delegate per-device authorization
to Auth0.

The Auth0 tenant was created as a Development tenant in the US region. A Custom
API was created with:

- Name: `AI Lab Gateway MCP`
- Identifier / audience: `https://gateway.debasti.com/mcp`
- JWT profile: `Auth0`
- JWT signing algorithm: `RS256`
- User-delegated application access: `Per-app authorization`
- Client access: `Per-app authorization`

The API identifier is intentionally the same canonical resource identifier used
by the MCP resource server. Auth0 notes that this identifier becomes the
`audience` in authorization requests and cannot be changed after API creation.

Do not put Auth0 tenant credentials, client secrets, private keys, access
tokens, or other secrets in this repository.

### Operator reconstruction

If the Auth0 tenant must be recreated:

1. create a Development tenant (the reference tenant used the US region);
2. open Applications -> APIs -> Create API;
3. create the Custom API using the values above;
4. define the scopes in the Permissions tab as documented below;
5. configure the ChatGPT/client application and OAuth interoperability only
   after the resource API and scopes exist;
6. configure Google/social login for human authentication when required;
7. copy only non-secret issuer/audience configuration into the gateway runtime;
8. validate signature, issuer, audience, lifetime and scopes end-to-end before
   exposing device-control tools.

Auth0's generic API Quickstart language/framework examples are not the source of
truth for this project; the gateway is a Python MCP OAuth resource server.

## Subject mapping

After token validation, the stable token subject (`sub`) becomes the platform
principal used by `AuthorizationPolicy`.

```text
OAuth token -> verified issuer/audience/scopes -> sub -> authorization policy
```

Email addresses are display/account metadata, not authorization keys.

## Initial scopes

In Auth0 these are created under the AI Lab Gateway Custom API's
`Permissions` tab. Keep them coarse; per-device/action rights remain in the
gateway's deny-by-default authorization policy.


Keep OAuth scopes coarse and enforce device-level rights in the gateway policy:

- `gateway:read` — discover permitted devices and read status.
- `gateway:control` — execute permitted state-changing/control operations.

A scope does not grant access to every device. Both checks must pass:

```text
OAuth scope AND subject -> device/action grant
```

## OpenAI client compatibility

The implementation must support Authorization Code + PKCE and protected
resource discovery. The authorization server must correctly bind tokens to the
gateway resource/audience.

OpenAI client integration is an acceptance test, not an assumption. Product
surface behavior must be rechecked against current OpenAI documentation when
the OAuth provider is configured.

## Security invariant

No `exec`, `write_file`, service-control or similar tool is registered on
the public MCP surface until request identity can be validated and authorization
can be enforced in the same request path.


## Auth0 MCP compatibility requirement

The MCP OAuth flow uses RFC 8707 `resource` to identify the target resource
server. For the Auth0 tenant, enable **Resource Parameter Compatibility
Profile** under Tenant Settings -> Advanced -> Settings. This makes Auth0 accept
the MCP `resource=https://gateway.debasti.com/mcp` parameter as the target API
identifier/audience.

This is required for a standards-compliant MCP client such as ChatGPT to obtain
an access token whose audience is the Gateway without a provider-specific
`audience` rewrite in the Gateway.

Do not enable Dynamic Client Registration merely by habit. The preferred
ChatGPT path is CIMD when supported/configured; DCR is a fallback with a broader
tenant security impact because it permits unauthenticated client registration.
Choose the client-registration mode deliberately during ChatGPT integration.


## ChatGPT CIMD registration and Auth0 setup (2026-10-05)

ChatGPT custom MCP integration uses Client ID Metadata Document (CIMD) registration. Enabling CIMD support in Tenant Settings is not sufficient by itself: Auth0 must also import the ChatGPT metadata document once per tenant.

Reconstruction path:

1. Tenant Settings -> Advanced: enable Client ID Metadata Document (CIMD) Registration. Keep DCR disabled unless CIMD cannot be used.
2. Applications -> Applications -> Create Application -> Import from URL.
3. Import `https://chatgpt.com/oauth/client.json`, preview it, then create the third-party CIMD application named `ChatGPT`.
4. Applications -> APIs -> create `AI Lab Gateway MCP` with Identifier `https://gateway.debasti.com/mcp`, JWT profile `Auth0`, signing algorithm `RS256`, and per-app authorization for user-delegated and client access.
5. In Permissions, add `gateway:read` (`Read permitted devices and gateway status`).
6. In Application Access, edit `ChatGPT` under User-Delegated Access, select `gateway:read`, and grant access. Do not grant Client Access merely for the interactive ChatGPT flow.
7. Keep third-party default permissions fail-closed; authorize ChatGPT explicitly.

Observed diagnostics:

- Before importing CIMD: `invalid_request: Unknown client: https://chatgpt.com/oauth/client.json`.
- After CIMD import: `access_denied: Service not found: https://gateway.debasti.com/mcp`, because the original API identifier was `https://gateway.debasti.com` while MCP discovery advertised `https://gateway.debasti.com/mcp`.
- The replacement API therefore uses the exact MCP resource URL as its Auth0 identifier/audience. Do not delete the original API until end-to-end acceptance passes.

Runtime configuration must use audience `https://gateway.debasti.com/mcp` before token validation is retested. Never commit user subjects, tokens, client secrets, private keys, or other tenant secrets.
