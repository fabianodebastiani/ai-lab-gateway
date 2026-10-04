"""RFC 9728-style protected resource metadata for the MCP gateway."""

from .auth import AuthConfig


def protected_resource_metadata(config: AuthConfig) -> dict:
    return {
        "resource": config.audience,
        "authorization_servers": [config.issuer],
        "scopes_supported": ["gateway:read", "gateway:control"],
        "resource_documentation": "https://github.com/fabianodebastiani/ai-lab-gateway",
    }
