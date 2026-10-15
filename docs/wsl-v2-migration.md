# WSL migration pilot — new enrollment v2, restricted by default

Status: **planning and environment preflight** (2026-10-14 UTC).
Do not treat this file as proof the v2 pairing API is already deployed.

## Selected pilot

- Existing registered device: `windows-wsl` (Ubuntu 24.04 WSL on the user's Windows PC).
- Device management SSH account: `ai-gateway` (unprivileged).
- Existing reverse SSH listener: gateway `127.0.0.1:10002`.
- Existing tunnel unit on WSL: `ai-lab-wsl-tunnel.service`.
- Existing use pattern: **on demand**, via the Windows shortcuts `Conectar AI Lab.bat`
  and `Desconectar AI Lab.bat`. Preserve this behavior.
- Existing configuration is deliberately considered *replaceable*, but it
  must not be deleted until the new version passes its acceptance tests.
- `raspberry-lab` uses port 10001 and must remain completely unaffected.
- At 2026-10-14 02:45 UTC neither 10002 nor 10003 was listening on the
  Oracle gateway, consistent with an on-demand WSL tunnel currently off.
  Gateway, human-approval web and privileged broker services remained active.

## Live WSL connection verified — 2026-10-14 02:56 UTC

After the operator restarted the existing `ai-lab-wsl-tunnel.service` on
Ubuntu WSL, the authorized MCP `device_status("windows-wsl")` returned
**online** with hostname `LAPTOP-5RJJ0KBM`; the Oracle Gateway listened
on loopback port **10002**, and its other services remained active.
Remote management SSH returned non-root `ai-gateway`.

The current service is `ActiveState=active`, `UnitFileState=disabled`,
`Restart=on-failure`, `User=ai-gateway`. The systemd unit includes strict
SSH host-key checking, connection keepalives and
`ExitOnForwardFailure=yes`. The WSL Linux has `systemd=true`.
This is the intended **On-demand** configuration: starting the service
connects, stopping disconnects, and an ssh failure while running restarts
it; there is **no** Linux auto-start on next WSL boot.

The first reusable v2 local management helper was published at
`scripts/device-connection.sh` and copied to
`/home/ai-gateway/device-connection-v2.sh` solely for non-destructive
WSL tests. Bash syntax validation and read-only status succeeded:

```text
unit=ai-lab-wsl-tunnel.service
mode=on-demand
active=active
systemd-enabled=disabled
```

An invalid unit `ssh.service` was rejected, exit 2. The helper was
**not installed as a privileged system command**, and no WSL keys, sudo
grants, systemd configuration or old tunnel were changed. The current
production listener still uses port 10002; the v2 candidate port 10003
is not yet enrolled. We will preserve On-demand behavior during cutover.

**Connection mode != permission mode:** future pairing defaults Restricted,
while connection mode is chosen separately (On-demand for WSL laptops;
Persistent for always-on Linux/servers).

## Per-device persistence flag and MCP controls — 2026-10-14

The operator clarified that the connection preference must be **one Boolean
flag for EVERY device** (not a hard-coded laptop-vs-server category):
`persistent=true` or `persistent=false`. The flag is separate from the
live connected state and from device sudo/authorization profiles.

An initial MCP implementation was committed:
`device_connection_status(device_id)` and
`set_device_persistent(device_id, persistent: bool)`.
The read tool requires an existing `status` device grant; the setter requires
OAuth control scope and explicit `connection_manage` authorization for this
device, plus a narrow root-owned helper installed locally. The target's
systemd unit is the source of truth. The setter does **not** disconnect an
active tunnel when flag becomes false.

**Live WSL reference values:** connected=true, persistent=false, service
`ai-lab-wsl-tunnel.service` active/disabled. Unit-level tests using synthetic
state passed on WSL; the production MCP server and root-side helper have
**not yet been installed or authorized**, so this is not a deployed feature.

**Deployment operations still required** (after backup):
1. Install the root-owned allowlisted target script
   `scripts/ai-lab-device-connectionctl` on WSL, limiting sudo to exact
   `set-persistent ai-lab-wsl-tunnel.service 0|1` variants.
2. Add `connection_unit: "ai-lab-wsl-tunnel.service"` to the protected
   `windows-wsl` device registry item; add `connection_manage` to the
   explicitly authorized operator/device grant, not globally.
3. Install the updated MCP package and reload the Oracle Gateway using
   a supervised administrative rollout. Validate tool discovery, read-only
   status, and flag toggles with no changes to SSH keys or old port.
4. Confirm the flag can be changed back and forth while the connection stays
   up; then proceed with new WSL pairing credentials and eventual cutover.

## Product decision

**Pairing always produces a Restricted device.** Only later may the operator
separately select Restricted, Unrestricted or Partial with a duration dropdown.
Do not ask for administrative privileges during pairing or give the new
management account implicit sudo access.

## Safe replacement procedure (intended v2 behavior)

1. **Preflight:** user starts the existing `Conectar AI Lab.bat` shortcut.
   Through the existing authorized MCP connection we inspect WSL systemd,
   sshd, existing tunnel, and the non-privileged `ai-gateway` account.
   We do not copy, display or rotate secrets yet.
2. **Prepare in parallel:** implement/test HTTPS one-time pairing, device
   identity verification, operator approval and transactional registry
   update. Reserve the *candidate* reverse port 10003 only after confirming
   it is free. Generate a **fresh** target-side tunnel key on WSL and a
   **fresh** gateway-side management key in the gateway's protected storage.
   Keep each private key on its originating system.
3. **Stage:** place a new WSL tunnel service next to the old one, preserving
   the on-demand behavior. Limit the candidate tunnel credential to
   `permitlisten="127.0.0.1:10003"`. Pin the SSH host keys in both
   directions. The temporary candidate remains **pending/inactive** in the
   device registry; the registered `windows-wsl` continues to use old
   working credentials and port 10002.
4. **Verify:** over port 10003, test correct target identity, key mismatch
   refusal, non-root status, failure of unexpected sudo, file read/write,
   command timeouts and reconnect. Confirm user approval of **device
   pairing**, not privileges. The enforced initial profile is Restricted.
5. **Cut over atomically:** change the `windows-wsl` registry/policy to use
   the new port and management key; confirm normal ChatGPT `device_status`
   and `exec` work. Old SSH keys and old tunnel service remain available
   only as short-lived recovery during cutover and are then explicitly
   revoked/removed; no persistent duplicate device.
6. **Verify revocation:** try the old tunnel credential and management
   credential and confirm both are rejected. Check on-demand start/stop,
   restart behavior, and confirm other devices are unaffected.
7. **Only after successful enrollment:** test a separately requested
   Partial access grant and expiry. Do not mix initial identity pairing
   with admin permission grants.

## Deployment prerequisite

The Oracle `ai-maintenance` user's temporary root/sudo bootstrap has
already expired; `sudo -n` is no longer available via ordinary MCP `exec`.
Installing a root-owned pairing service, changing the gateway tunnel account's
authorized keys or editing protected runtime registry requires a **distinct,
human-authorized administrative deployment** (via the `ubuntu` Oracle
recovery account, or an explicitly whitelisted deployment mechanism).
Never try to reintroduce general passwordless sudo or use MCP operational
commands to bypass this boundary.

## Next steps

1. Implement a pairing API and target installer that support independent
   On-demand/Persistent connection mode and enforce Restricted access on
   enrollment.
2. Stage a fresh, separately generated SSH identity on an unused loopback
   port (proposed 10003), without touching the old functioning SSH keys.
3. Arrange a narrowly authorized Oracle administrative deployment to
   provision the protected device registry, SSH tunnel allowlist and
   management key. Do not reinstate general passwordless sudo.
4. Validate the new candidate tunnel (host identity, non-root user,
   rejection of unauthorized sudo, reconnect tests, on-demand start/stop).
5. Switch `windows-wsl` to the new connection and revoke old credentials
   only after verified successful cutover. Retain the existing Windows
   connect/disconnect shortcuts or replace them with equivalent
   one-click controls.

**No immediate manual action is required** while code and tests are
prepared. Keep the current WSL connection running for development.


## Piloto WSL existente — decisão do operador em 15/10/2026

**Não criar segunda distribuição WSL.** O Ubuntu WSL atual será o único
alvo do primeiro teste. O operador autoriza apagar a conexão antiga
*após* o novo caminho ter sido comprovado, incluindo substituição de
chaves e do serviço de túnel. A conexão v1 poderá ser usada somente
como canal temporário de preparação, sem que isso conte como teste
de onboarding de dispositivo virgem.

**Critério de produto para dispositivo virgem permanece obrigatório:**
o cliente v2 deve conseguir preparar as próprias chaves e fazer claim
HTTPS sem qualquer SSH prévio entre alvo e Gateway. O teste de aceitação
com Linux realmente virgem virá depois, quando houver provisionamento
totalmente automático.

Em 15/10 às 04:32 UTC a porta legada 10002 ainda estava desconectada
(exit SSH 255 `Connection refused`). ChatGPT solicitou ao operador
iniciar `ai-lab-wsl-tunnel.service` localmente. Nenhum dispositivo
foi removido, nenhuma chave foi substituída.

Novo código no Git:
- `scripts/ai-lab-device-pair-v2.py`: cliente independente de
  `prepare`/ `claim` HTTPS. Prepara chave ED25519 única no próprio
  Linux, valida host key, token e retorno `pending+restricted`,
  confere ambos os fingerprints, não pede sudo e não altera
  `authorized_keys`, `sudoers`, `systemd` nem túneis existentes.
  A preparação no WSL pode ser executada via SSH v1, mas a chamada
  HTTPS não depende desse túnel.
- `tests/test_device_pair_client.py`: cinco testes aprovados no
  laboratório Oracle em 15/10. São testes locais, sem afirmar
  provisionamento automático completo.

**Atenção:** o cliente requer OpenSSH/sshd já instalado e uma
conta Linux não-root existente. O instalador inicial de um Linux
virgem deverá provisionar esses pré-requisitos localmente, com sudo
concedido por seu administrador. A criação de uma chave/ticket pending
ainda não torna o dispositivo administrável pelo MCP.

Próximo objetivo operacional: ligar temporariamente o túnel antigo,
executar `prepare` da nova chave no WSL, solicitar convite autenticado
via MCP, fazer claim HTTPS, confirmar os fingerprints no painel humano,
provisionar credenciais exclusivas no Gateway, iniciar o candidato no
loopback 10003, validar `exec` com identidade nova e depois revogar
as credenciais v1 sem alterar Oracle ou Raspberry.


### Execução do desenvolvimento em 15/10/2026, 04:42 UTC

A implantação do servidor de pairing v2 já está ativa, mas o WSL
segue **offline** do ponto de vista da Oracle: `device_status` ainda
retorna SSH exit 255 e **nenhum** listener nas portas 10002/10003.
Não presumir que o operador ligou o serviço apenas por ter o WSL
aberto localmente. Ação necessária: iniciar localmente
`sudo systemctl start ai-lab-wsl-tunnel.service` ou o atalho
existente. Nenhuma credencial legada foi eliminada.

Código novo e testes verificados no Oracle staging:

- `scripts/ai-lab-device-pair-v2.py` (SHA256
  `b3e22d0a14adb6218393e3fda731b78ac5c408a3a36bd959213a2a524da11f6e`):
  cliente sem SSH prévio, prepara chave de túnel local nova e faz
  claim HTTPS com token escondido (TTY ou `--token-stdin`).
- `scripts/provision_wsl_pairing_candidate_oracle.py` (SHA256
  `b4b62735643d5bdc7a284d950f8aa5cdf540ccc761868296372a26f702aed18b`):
  provisionador root para o **candidato** WSL v2, reserva porta 10003,
  exige pedido aprovado recentemente e `restricted` /
  `persistent=false`, gera chave de gestão distinta sob proteção
  da Oracle, anexa a chave pública do túnel com `permitlisten`,
  fixa host key do alvo e produz backup. **Não** troca registro
  ativo 10002; não deve ser executado até aprovação humana real.
  Fonte foi estagiada root-owned 0600 na Oracle em
  `/root/ai-lab-v2-tools/provision_wsl_pairing_candidate_oracle.py`,
  hash validado. Nenhum comando `--apply` executado.
- `tests/test_device_pair_client.py` e
  `tests/test_provision_wsl_pairing_candidate.py`: **10 testes
  aprovados** no staging Oracle, incluindo execução do provisionador
  inteiramente em diretórios temporários com backups e comprovação
  de registry original intacto. Esses testes **não** comprovam
  o SSH final entre Oracle e WSL.

**Pendências:** reconectar WSL, criar e enviar convite pela
superfície OAuth do MCP (reconectar app se catálogo antigo), obter
claim real, aprovação humana da identidade, provisionar candidato,
instalar management pubkey no WSL, iniciar túnel v2 separado,
executar testes e só então substituir registry/chaves legadas.
Para um dispositivo virgem futuro, ainda falta um instalador
autossuficiente de pré-requisitos (conta Linux/sshd/systemd),
distribuição autenticada do material público e ativação totalmente
automatizada sem SSH anterior.


### WSL reconectado e candidato preparado — 15/10/2026 04:49 UTC

O operador reiniciou localmente o serviço v1; o MCP voltou a executar
comandos no WSL como `ai-gateway`. O listener antigo
`127.0.0.1:10002` voltou; a unidade permanece **active/disabled**
(sob demanda). O serviço SSH local está ativo.

Usando a conexão antiga **somente como canal de desenvolvimento**,
o MCP copiou `scripts/ai-lab-device-pair-v2.py` para
`/home/ai-gateway/ai-lab-device-pair-v2.py` e executou `prepare`.
Uma identidade de túnel **nova e independente** foi gerada em
`/home/ai-gateway/.ssh/ai-lab-v2/tunnel-windows-wsl-ed25519`
(mode 0600; diretório 0700). Fingerprints para comparação humana:

- novo túnel v2: `SHA256:WNQwcglksL5gtUlmVKWv1rByzFlJbffK1ZJeqbM8EPo`;
- chave SSH de host WSL existente: `SHA256:hh1guyo4yOa81Qj0zrf+XZlNpwaMlH0BfDAdo0SGwCw`.

HTTPS `https://gateway.debasti.com/pairing/health` respondeu `{"status":"ok"}`
do próprio WSL. Foi copiado também o utilitário
`scripts/wsl-v2-candidate-tunnel.sh` para
`/home/ai-gateway/wsl-v2-candidate-tunnel.sh`.
Verificação `bash -n` passou, `status` retornou corretamente
`candidate-disconnected`, e a conexão v1 permaneceu ativa.
**Não foi iniciado nenhum túnel novo ou alterada uma chave v1.**

O servidor Oracle possui funções MCP `pairing_invite`,
`pairing_requests` e `pairing_status` em seu código instalado,
porém **a conexão ChatGPT AI Lab Gateway 06 neste chat ainda tem o
catálogo antigo** de dez ferramentas; essas três ainda não aparecem
para chamada autenticada. Precisamos atualizar/recriar a conexão
MCP no ChatGPT para usar a solicitação legitimamente autenticada.
**Não criar convite direto no banco, não fingir sujeito Auth0,
não usar sudo para contornar essa separação.**

Após ferramenta disponível: emitir convite curto com OAuth,
enviar token confidencial ao cliente `claim` por stdin protegido,
verificar fingerprints via página humana
`https://gateway.debasti.com/approvals/pairing`,
provisionar o candidato com
`/root/ai-lab-v2-tools/provision_wsl_pairing_candidate_oracle.py`
(apenas request_id aprovado), instalar chave pública de gerenciamento
no WSL, abrir candidato 10003, verificar controle via novo SSH
e somente então realizar cutover/revogação antiga.
