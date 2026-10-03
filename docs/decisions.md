# Architecture Decision Log

This document records decisions and important working assumptions. They may be revised as the prototype teaches us more.

## ADR-001 — Public gateway with outbound device connections

**Decision:** use a public cloud Linux VM as the rendezvous/control point. Remote devices initiate outbound SSH/reverse-SSH connections to it.

**Reasoning:** lab and field devices commonly sit behind NAT, CGNAT, or firewalls. An outbound connection avoids requiring port forwarding or inbound reachability at every device location.

**Status:** accepted for prototype.

## ADR-002 — MCP on the AI-facing side

**Decision:** expose gateway capabilities to AI clients through MCP over authenticated HTTPS.

**Reasoning:** MCP provides a structured tool interface while keeping network/device mechanics behind the gateway.

**Status:** accepted direction; exact MCP implementation and authentication mechanism still to be selected.

## ADR-003 — Keep the device side thin

**Decision:** do not begin with a custom heavyweight device agent. Prefer standard SSH plus a persistent outbound tunnel managed by standard Linux facilities.

**Reasoning:** reduces installation complexity and keeps the solution portable across ordinary Linux and embedded Linux targets.

**Status:** accepted for prototype.

## ADR-004 — Generic MCP primitives first

**Decision:** begin with generic command/file/process primitives instead of encoding individual laboratory peripherals into MCP.

**Reasoning:** once the AI has controlled Linux CLI access, device-specific libraries and utilities can remain local to the target. This keeps the gateway reusable.

**Status:** accepted.

## ADR-005 — Hardware-specific software belongs on the target

**Decision:** radio, SPI, GPIO, AT-command and similar hardware interfaces should normally be represented by libraries, tools or scripts installed on the target Linux system.

**Reasoning:** separates transport/control-plane concerns from hardware behavior and allows the same gateway to control very different devices.

**Status:** accepted.

## ADR-006 — Separate identities and credentials

**Decision:** do not reuse the gateway administrator SSH key as a device identity, and do not use one shared device key for every target.

**Reasoning:** limits blast radius and enables device revocation, user/device authorization and useful auditing.

**Status:** accepted.

## ADR-007 — Non-root target access by default

**Decision:** AI-controlled sessions should normally run as a non-root user. Additional privileges can be granted narrowly with sudo policy.

**Reasoning:** arbitrary root access is unnecessary for most development tasks and greatly increases impact of mistakes or compromise.

**Status:** accepted.

## ADR-008 — Tailscale/VPN is optional, not a prototype dependency

**Decision:** do not require a network overlay initially.

**Reasoning:** SSH already supplies encrypted authenticated transport and reverse tunnels solve the immediate NAT/CGNAT problem. A VPN remains an option if later requirements justify it.

**Status:** accepted for prototype.

## ADR-009 — Avoid unnecessary infrastructure

**Decision:** do not introduce Docker, a heavy database, or additional platform components merely by default.

**Reasoning:** the initial gateway VM is small and the core problem can be validated with a lightweight stack. Complexity should be earned by requirements.

**Status:** accepted for prototype.

## ADR-010 — Cloud VM platform and initial shape

**Decision:** the first gateway is an Oracle Cloud Infrastructure VM in Brazil Southeast (Vinhedo), using Canonical Ubuntu 24.04 Minimal on x86_64.

Observed initial resources:

- approximately 1 GiB RAM;
- 45 GiB root filesystem;
- no swap initially;
- public IPv4 attached after provisioning.

**Reasoning:** sufficient for an initial lightweight gateway and immediately available during the prototype setup.

**Status:** implemented.

## Open decisions

- MCP server language/framework.
- MCP authentication/authorization mechanism.
- Device registry storage format for the prototype.
- Reverse tunnel lifecycle and port/address allocation.
- Audit-log storage and retention.
- Whether a stable DNS name/domain should front the gateway.
- TLS termination strategy.
- Exact sudo policy for managed devices.
