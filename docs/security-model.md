# Security model

## Trust boundaries

The gateway crosses three independent trust boundaries:

1. Internet client -> MCP resource server.
2. Gateway -> reverse-tunnel endpoint.
3. Reverse tunnel -> target sshd.

Success at one boundary never implies authorization at another.

## Execution gate

A privileged request is allowed only if all conditions hold:

```text
cryptographically valid access token
AND required OAuth scope
AND explicit subject -> device/action grant
AND enabled registry entry
AND valid per-device SSH management credential
```

Authorization is deny-by-default.

## No shell interpolation on the gateway

The SSH backend invokes OpenSSH with an argv list and `shell=False`. The remote
command is passed to the target SSH server; it is not interpreted by a local
gateway shell.

This does not make arbitrary remote commands harmless. The target account is
therefore non-root by default and sudo must be granted narrowly.

## Secrets

Never store private keys, OAuth client secrets, access tokens or refresh tokens
in Git. Registry and policy files contain identifiers and paths only.

## Reverse tunnel exposure

Every reverse listener must bind to loopback. Device tunnel keys are distinct
from target management keys. Compromise/revocation of one role should not
automatically provide the other.

## Audit privacy

Default audit events record identity, device, action, outcome, duration and exit
code. Raw commands and output are not retained by default because they can
contain secrets or personal data.

## Public-tool activation rule

The SSH backend and control plane may exist in code before OAuth is deployed.
They must not be registered as public MCP tools until the running server can
derive a verified identity from each request and apply the complete execution
gate above.
