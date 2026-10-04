# Implementation status

## Validated on the live gateway

- Public DNS for `gateway.debasti.com`.
- TLS termination with Caddy.
- Reverse proxy to MCP on `127.0.0.1:8000`.
- MCP Streamable HTTP initialization.
- `tools/list`.
- `gateway_status` tool invocation over public HTTPS.

## Implemented in repository, not yet deployed

- device registry with loopback-only tunnel validation;
- deny-by-default subject/device/action authorization;
- OAuth resource-server configuration primitives;
- protected-resource metadata model;
- OAuth scope/subject normalization;
- control-plane orchestration;
- SSH command backend with bounded timeout and strict host-key checking;
- append-only audit metadata;
- gateway systemd unit;
- device reverse-tunnel systemd template;
- device enrollment/bootstrap helper;
- unit tests for registry, authorization, OAuth helpers, audit, control plane and
  SSH invocation.

## Deliberately not enabled

- public MCP `exec` or file-write tools;
- OAuth token cryptographic verification before a provider is selected;
- automatic modification of gateway OpenSSH configuration;
- automatic sudo grants on targets;
- public binding of reverse-forward ports.

## Requires live gateway/device access

- run full test suite in the gateway virtualenv;
- install MCP service under systemd;
- persist/review host firewall rules;
- review/disable rpcbind if unused;
- configure chosen OAuth provider and token verifier;
- publish protected-resource metadata/challenges;
- create restricted tunnel landing account;
- enroll first Linux target;
- verify reverse tunnel and reconnect behavior;
- validate real ChatGPT product connection after OAuth is complete.

## Safety gate

The repository may contain the machinery for remote execution before deployment,
but the public server remains status-only until authenticated identity and
authorization are enforced end-to-end.
