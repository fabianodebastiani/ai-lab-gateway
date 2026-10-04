# Authentication plan

The AI-facing MCP endpoint will use OAuth 2.1. Platform users are application
identities; they are not Unix users on the gateway.

## Resource server

The MCP gateway is the OAuth resource server. Its canonical resource identifier
is:

```text
https://gateway.debasti.com
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

Do not implement passwords, login sessions or token issuance in the gateway
from scratch. Use an established OAuth/OIDC authorization server that can meet
the MCP OAuth requirements.

The provider choice is intentionally deferred until deployment because it
affects account UX, cost and external configuration. The gateway code should
depend only on issuer/JWKS/audience/scopes, not on provider-specific user IDs.

## Subject mapping

After token validation, the stable token subject (`sub`) becomes the platform
principal used by `AuthorizationPolicy`.

```text
OAuth token -> verified issuer/audience/scopes -> sub -> authorization policy
```

Email addresses are display/account metadata, not authorization keys.

## Initial scopes

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
