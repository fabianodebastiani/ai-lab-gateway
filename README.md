# AI Lab Gateway

Experimental gateway for giving AI clients controlled, auditable command-line access to remote Linux devices.

## Current verified status — 2026-10-16 (read before older historical checkpoints)

**Repository visibility: PUBLIC** (verified through GitHub repository metadata).
The device bootstrap fetches **commit-pinned and SHA256-checked** code from
public raw.githubusercontent.com over HTTPS; the target does not need a
GitHub login. Private SSH keys, OAuth secrets and human approval credentials
are never to be stored in Git.

**One-code Restricted Linux enrollment is live and E2E verified:** a
previously unregistered second Oracle Ubuntu VM was paired with a single
eight-character code in ChatGPT, after human approval. Reverse SSH
registered it at loopback port 11000. Live MCP command execution returned
hostname `ai-lab-experiments-01` and user `ai-gateway`, with sudo denied;
WSL and Raspberry remain online. The generic activation fixes and real
checkpoint are in [draft PR #8](../../pull/8), **not merged to main**.

**Local `ailab` command:** [draft PR #9](../../pull/9) implements
`status`, `connect`, `disconnect`, `persistent on/off`, using
existing approved local SSH identities and `systemd --user`, without sudo.
CI succeeded. The command was installed under the nonadmin
`/home/ai-gateway/.local/bin/ailab` on the second Oracle VM, and
`status`, already-connected `connect`, and non-disruptive
`persistent off` were validated via real MCP without dropping the tunnel.
The actual live tunnel is still **transient, on-demand**. Changing to
permanent startup, intentionally disconnecting and reconnecting, and
persistence after reboot **have not been live-tested**.

**Target sudo is NOT implemented or granted.** The approved architecture
preserves *one-use exact-operation approval*, temporary approval with a
selectable TTL, and strongly confirmed indefinite approval. These are
independent of the three Restricted/Partial/Unrestricted access profiles.
The privileged target executor requires a separate reviewed implementation,
local administrator bootstrap, independent human consent, and negative E2E
tests. See [canonical Linux lifecycle and supervised execution contract](docs/device-lifecycle-and-privileged-execution.md),
[ADR-027/028/029](docs/decisions.md), and [issue #2](../../issues/2).
The preexisting Oracle-root broker is a separate fixed-operation allowlist
and does not grant root to SSH devices.

**The older implementation statuses below are dated history.** Do not
use them as the current source of truth for E2E pairing or admin privileges.



The project is intended for labs, development boards, Raspberry Pi-class systems, embedded Linux targets, and other machines that may sit behind NAT/CGNAT or restrictive firewalls.

## Core idea

```text
AI client / ChatGPT
        |
        | MCP over HTTPS
        v
AI Lab Gateway (public Linux VM)
        |
        | SSH / reverse SSH tunnels
        v
Remote Linux device(s)
```

Remote devices initiate outbound SSH connections to the gateway. This avoids requiring inbound connectivity at the device site. The AI interacts with the gateway through MCP; the gateway mediates access to registered devices.

## Design goals

- Generic Linux access rather than hardware-specific MCP implementations.
- Minimal software footprint on remote devices.
- Work through NAT/CGNAT using outbound connections.
- Separate authentication for AI clients, gateway administration, and devices.
- Support multiple users and multiple devices with explicit authorization mappings.
- Keep hardware-specific libraries, scripts and tools on the target device.
- Make actions observable and auditable.
- Start small and add semantic MCP tools only where they add value.

## Status

The v1 control path is live and validated end-to-end.

The public HTTPS MCP endpoint authenticates ChatGPT users through Auth0, verifies
OAuth tokens and scopes, applies deny-by-default subject/device/action policy,
and reaches registered Linux targets over per-device management SSH identities
through loopback-only reverse SSH tunnels.

The first live target passed the complete tunnel/credential/reboot/timeout
acceptance checklist. A fresh ChatGPT developer-mode app then validated all six
v1 tools through the real production path:

- `gateway_status`
- `list_devices`
- `device_status`
- `exec`
- `read_file`
- `write_file`

The final acceptance included real `uname -a` execution plus a temporary
remote file write/read/cleanup round trip.

See [docs/architecture.md](docs/architecture.md),
[docs/decisions.md](docs/decisions.md),
[docs/build-log.md](docs/build-log.md),
[docs/recovery.md](docs/recovery.md), and the detailed
[ChatGPT + Auth0 OAuth runbook](docs/chatgpt-auth0-oauth-runbook.md).


## Estado confirmado em 15/10/2026 — servidor de pareamento v2 instalado

**Piloto de pareamento v2 implantado com sucesso na Oracle** em
15/10/2026 às 04:15 UTC (primeiros testes funcionais). O instalador
reportou `PAIRING_PILOT_DEPLOYED`; os três endpoints de saúde
(local /pairing, HTTPS /pairing, HTTPS /approvals) responderam.
`ai-lab-pairing.service` e ambos os sockets Unix estão ativos,
serviço roda sem root, diretório de dados 0700 e DB 0600,
socket MCP somente `ai-lab-gateway`, socket de revisão somente
`ai-lab-approver`. Acesso direto por `ai-maintenance` foi negado.
Os quatro serviços anteriores continuam ativos; SSH MCP da própria
Oracle e Raspberry online, WSL ainda offline. Chaves originais intactas.

**Importante:** isto é a infraestrutura de convite/claim/revisão,
**não** pareamento funcional completo: falta provisionamento real de
chaves/contas/SSH e teste ponta a ponta com Linux candidato.
Também falta elevação Restrito/Parcial/Irrestrito efetiva no alvo.
O catálogo do app ChatGPT poderá exigir reconexão para expor as
novas ferramentas MCP.

A implantação bem-sucedida foi após duas tentativas com rollback:
um health check imediato antes do serviço responder e uma checagem
que esperava JSON do painel antigo, cujo `/approvals/health` retorna
texto simples. As duas condições foram corrigidas e testadas.
Backup final: `/var/backups/ai-lab-gateway/pairing-v2-20261015T041535Z`.

**Autorização administrativa temporária separada:** o operador
habilitou explicitamente `sudo` para a conta `ai-maintenance`
apenas durante uma janela de 60 minutos, com revogação automática
em **2026-10-15 05:08:04 UTC** por timer root-owned do systemd.
Não significa aprovação permanente nem altera os perfis de novos
dispositivos. A conta Oracle `ubuntu` permanece recuperação independente.

## Histórico: checkpoint de trabalho (14/10/2026)

**Primeiro ponto de retomada:** [Checkpoint de 14/10 — pareamento WSL
v2, estado real e pendências](docs/checkpoint-2026-10-14-pairing-v2.md).

A versão v2 de cadastro já possui código, testes e pacote preparado
para a Oracle, porém **não está instalada**. O operador encerrou a sessão
e explicitamente **não executou** a cópia para `/root`, `--check` ou
`--apply` da última orientação administrativa. A Oracle mantém os
serviços v1 ativos; o WSL foi registrado **offline na última checagem**
e pode voltar pelo túnel sob demanda. **Não apagar as credenciais
antigas** antes da validação integral da substituição.

### Histórico: primeira tentativa em 15/10/2026

O bundle de pareamento v2 foi **tentado** pela primeira vez na Oracle em
15/10/2026. A instalação falhou no health check da porta 8002; o instalador
executou rollback e os quatro serviços v1 permanecem operacionais, inclusive
o SSH local da Oracle pelo MCP. A causa foi investigada e corrigida no instalador antes da implantação
bem-sucedida descrita acima. O plano ADR-027/028 permanece
inalterado. Ver [checkpoint com adendo](docs/checkpoint-2026-10-14-pairing-v2.md)
e [diagnóstico supervisionado do broker](docs/broker-pairing-journal-rollout.md).

## Implementation map

Current live/repository state is tracked in
[docs/implementation-status.md](docs/implementation-status.md).

Prepared runbooks:
- [Recovery / rebuild from scratch](docs/recovery.md)
- [Authentication](docs/authentication.md)
- [ChatGPT + Auth0 OAuth runbook](docs/chatgpt-auth0-oauth-runbook.md)
- [Device tunnels](docs/device-tunnels.md)
- [Device bootstrap](docs/bootstrap-device.md)
- [Security model](docs/security-model.md)
- [Deployment](docs/deployment.md)

## Supervised privilege broker (experimental)

The Oracle gateway now has a separate, hardened root broker behind a Unix
socket accessible only to the non-root Gateway service account. OAuth-authorized
users can request a predefined privileged operation; an administrator must
independently approve it, and execution is limited to a single use with an
expiry and audit record. This does **not** grant arbitrary sudo from MCP.

The independent approval UI is deployed, and a real browser approval with
TOTP was tested end-to-end, including one-time execution and replay rejection.
The current broker covers only a small predefined Oracle operation allowlist;
it is not yet the v2 per-device, temporary sudo manager.

See [Supervised privilege broker architecture and runbook](docs/privileged-broker.md).

### Human approval website (active)

A separate password-and-TOTP human approval interface has been deployed at
[https://gateway.debasti.com/approvals](https://gateway.debasti.com/approvals).
Credential enrollment and live end-to-end approval have been completed.
The UI runs as its own non-root service and can only approve or deny
pending, whitelisted broker requests.

See [docs/approval-web.md](docs/approval-web.md) for the setup, security
model, troubleshooting, and acceptance procedure.

## Next milestone: v2 device pairing and access profiles

**New devices always start Restricted** after explicit identity verification and
secure pairing. Enrollment does **not** ask the operator to choose sudo
privileges. After pairing, the operator can request access changes separately,
with exactly three choices: Restricted, Unrestricted, or Partial. Only Partial
shows a duration dropdown (15 minutes to 24 hours). Its expiration returns
to Restricted.

The initial profile domain model and regression tests exist in
`src/ai_lab_gateway/access_profiles.py` and
`tests/test_access_profiles.py`, but the enrollment API and device-side sudo
enforcement are **not yet deployed**. See [ADR-027](docs/decisions.md) and the
[unified v2 product specification](docs/v2-device-onboarding-access.md)
for the approved design and rollout prerequisites.

### Universal connection persistence flag (v2 preparation)

Every enrolled Linux device, regardless of hardware type, can select
`persistent=true` (automatic tunnel startup on Linux boot) or
`persistent=false` (local/manual connection). Connection preference is
**independent** of Restricted/Partial/Unrestricted permissions and current
online/offline status.

The proposed MCP operations `device_connection_status(device_id)` and
`set_device_persistent(device_id, persistent: bool)` have been implemented
in the repository but are **not yet deployed**. The setter requires separate
`connection_manage` authorization on the requested device and a
specifically allowlisted helper installed by that device's administrator.
Changing the flag does not directly connect/disconnect a live session; an
offline target cannot be reconnected via its already-down reverse tunnel.

Sources: [ADR-028](docs/decisions.md),
[`connection_control.py`](src/ai_lab_gateway/connection_control.py),
[`ai-lab-device-connectionctl`](scripts/ai-lab-device-connectionctl).

### Restricted-first pairing prototype (v2 in progress)

A first domain-level implementation is in
[`src/ai_lab_gateway/enrollment.py`](src/ai_lab_gateway/enrollment.py),
with focused tests in [`tests/test_enrollment.py`](tests/test_enrollment.py).
It generates high-entropy one-use 10-minute pairing invitations, stores
only token digests, validates distinct Ed25519 SSH public keys and the
universal `persistent` boolean, and always produces a **pending,
Restricted** enrollment.

It is **not** a public pairing endpoint yet and does not rotate existing
device keys. It must be integrated with authenticated HTTPS enrollment,
independent operator approval, atomic gateway/target provisioning, and
end-to-end acceptance on the WSL before v2 is declared usable.
