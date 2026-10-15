# Checkpoint — AI Lab Gateway v2 / primeiro pareamento WSL

**Encerramento da sessão:** 14/10/2026, última consulta à Oracle às
**05:41:03 UTC** (02:41:03, Brasil / UTC-3).

**Aviso explícito do operador:** decidiu encerrar o trabalho por hoje.
**NÃO executou NENHUM dos comandos administrativos da última instrução**
(cópia para `/root`, `sha256sum` como `ubuntu`, `--check` ou `--apply`).
**Nenhuma instalação v2 em produção foi realizada.**
A retomada foi pedida para amanhã, mas NÃO há tarefa automática agendada.

## Objetivo e decisões de produto confirmadas

Entregar duas funcionalidades integradas, preservando o sistema v1:

1. **Cadastro simples de Linux novo** por um fluxo de convite/pareamento
   autenticado, gerando chaves SSH exclusivas, confirmação humana da identidade
   e provisionamento automático seguro no Gateway. Todo dispositivo nasce
   **Restrito** e não recebe `sudo` geral no cadastro.
2. **Gerenciador de permissões por dispositivo**, solicitado posteriormente
   conforme o trabalho: **exatamente três radio buttons** — Restrito,
   Irrestrito, Parcial. **Somente o Parcial** mostra dropdown para
   15 min / 30 min / 1 h / 2 h / 4 h / 8 h / 24 h. Prazo vencido => 
   novamente Restrito. Aprovação humana verificável, sem exigir
   Google Authenticator para cada comando ou para pareamento comum.
   A efetiva elevação de privilégio temporária **ainda não foi implementada**
   no Linux remoto.
3. **Flag de conexão independente** para TODOS os dispositivos Linux:
   `persistent: true/false`, livremente alterável depois pelo MCP
   (com ação de autorização `connection_manage` e auxiliar local protegido).
   `persistent=true` => systemd habilitado e reconexão automática quando
   o Linux estiver rodando; `false` => sem partida automática, Conectar /
   Desconectar localmente. Isto NÃO é a mesma coisa que estar online/offline
   nem que o nível de permissões Restrito/Parcial/Irrestrito.
   O MCP não pode reconectar um dispositivo após perder seu **único**
   túnel SSH, salvo por controle fora de banda; no WSL o sistema Linux
   precisa ser iniciado localmente para o serviço rodar.

Referências: [ADR-027/028](decisions.md) e
[especificação v2](v2-device-onboarding-access.md).

## Infraestrutura v1 validada e preservada

- **Oracle Gateway**: hostname `ai-lab-gateway-01`, URL pública
  `https://gateway.debasti.com`, MCP Auth0 e execução SSH reversa.
  Quatro serviços existentes, `ai-lab-gateway`, `ai-lab-privilege-broker`,
  `ai-lab-approval-web`, `caddy`, foram verificados **ativos**.
- **Raspberry**: `raspberry-lab`, porta loopback `127.0.0.1:10001`,
  último status **online**, hostname `fabiano-desktop`.
- **WSL do notebook**: registro existente `windows-wsl`,
  Ubuntu WSL em `LAPTOP-5RJJ0KBM`, usuário SSH não privilegiado
  `ai-gateway`, túnel original pela porta `127.0.0.1:10002`,
  unidade `ai-lab-wsl-tunnel.service`. Estava online e funcional durante
  implementação; o serviço é `disabled` e `Restart=on-failure`, portanto
  **sob demanda**.
- **Última verificação em 05:41:03 UTC:** WSL passou a estar **offline**
  (MCP `device_status` deu exit code 255, porta `10002` ausente).
  Isso pode ser só o encerramento do WSL/notebook; **não sabemos a causa
  exata** e não se deve atribuir a uma mudança v2. O Raspberry e os quatro
  serviços Oracle permaneceram online; **não** havia listener em `10003`
  nem novo serviço de pairing instalado. Sem alterações destrutivas no WSL.
- O `sudo` temporário de `ai-maintenance` na Oracle foi revogado
  automaticamente antes desta sessão: `sudo -n` continua negado.
  **Não tentar reabilitar sudo geral nem contornar bloqueios de segurança.**
- `list_devices` segue incluindo os três dispositivos v1:
  `raspberry-lab`, `windows-wsl`, `oracle-gateway`.
- O painel v1 de operações privilegiadas e Google Authenticator continua
  sendo um serviço distinto do pareamento. Login por senha é previsto para
  pareamento, com CSRF e aprovação humana; TOTP continua nas operações root.

## O que o código novo já faz (GITHUB; ainda NÃO implantado)

**Infraestrutura da flag persistente:**
- `src/ai_lab_gateway/connection_control.py`: estado real systemd,
  `persistent: bool`, disconnected != persistent=false.
- `scripts/device-connection.sh`: conectar/desconectar via administração
  Linux local, sem alterar SSH keys.
- `scripts/ai-lab-device-connectionctl`: helper root restrito a
  enable/disable de unidade AI Lab.
- `src/ai_lab_gateway/server.py`, `control.py`, `scope_stepup.py`:
  ferramentas MCP `device_connection_status`,
  `set_device_persistent`, escopo e política `connection_manage`.
- Ainda é necessário provisionar o helper/sudoers estrito no dispositivo
  e registrar seu `connection_unit` no registry protegido.

**Pareamento restrito:**
- `src/ai_lab_gateway/enrollment.py`: SQLite privado, convites aleatórios
  com validade de 10 minutos, hash armazenado (não token bruto), uso
  único, validação Ed25519, `persistent` independente, perfil inicial
  forçado Restrito, fases invited/pending/approved/denied/active.
- `src/ai_lab_gateway/enrollment_http.py`: rota HTTP de claim
  `POST /pairing/claim` e `GET /pairing/health` em localhost,
  sem endpoint de aprovação ou ativação.
- `scripts/pairing_service.py`: serviço não root com sockets Unix
  separados: MCP (emite convite/status, sem aprovar), aprovador
  (lista/revisa sem criar convite), root (consulta para provisionamento
  e marca ativação após validação). `SO_PEERCRED` identifica UID do
  processo; unidades systemd definidas em `deploy/ai-lab-pairing*`.
- `src/ai_lab_gateway/pairing_client.py`: interface do MCP para convites.
- `server.py`: futuras ferramentas `pairing_invite`,
  `pairing_requests`, `pairing_status`, com autorização
  `device_enroll` apenas para o operador explicitamente permitido.
- `scripts/approval_web.py`: atualização do painel existente para
  `/approvals/pairing` com confirmação de fingerprint SSH usando
  login/CSRF, sem OTP a cada pareamento.
- `scripts/install_pairing_pilot_oracle.py`: instalador administrativo
  com checksum fixado dos 14 arquivos, backup, checagens e tentativa de
  rollback. **Não executado**.
- **O provisionamento SSH real (chave de gestão nova na Oracle,
  authorized_keys restritos, listener candidato, host-key pinning,
  substituição atômica do registro) ainda é trabalho pendente**:
  um convite aprovado NÃO significa dispositivo operacional.
- **O gerenciamento remoto Restrito/Parcial/Irrestrito com sudo por tempo
  no alvo continua pendente**, separado do cadastro de dispositivos.

**Testes:** oito módulos focados foram executados no WSL e passaram,
**55 testes** no total
(11 connection_control + 5 helper + 11 enrollment + 7 lifecycle +
7 HTTP + 6 RPC + 3 web approval + 5 rollout).
São testes unitários/integrados locais e simulações; **não** comprovam
a instalação e o pareamento end-to-end em produção. Houve também um ensaio
com as chaves públicas reais do WSL, que permaneceu `pending` e não alterou
sistemas. Scripts Python copiados para uma área de teste
`/home/ai-gateway/v2-check/` no WSL.

## Chave candidata criada no WSL (PRESERVAR)

Foi gerada **somente** a nova chave de túnel para o piloto, sem
substituir a original:

- **Privada**: `/home/ai-gateway/.ssh/tunnel_v2_ed25519`, permanece no WSL.
  Nunca enviar sua chave privada ao chat, GitHub ou Oracle.
- **Pública**: `/home/ai-gateway/.ssh/tunnel_v2_ed25519.pub`.
- Fingerprint do túnel novo:
  `SHA256:wxsknp0UezA1nanxLBZ+ZHrwtZ2rHZomPfTFwP9IOSI`.
- Chave pública SSH do host:
  `/etc/ssh/ssh_host_ed25519_key.pub`.
- Fingerprint SSH do host:
  `SHA256:hh1guyo4yOa81Qj0zrf+XZlNpwaMlH0BfDAdo0SGwCw`.
- O túnel original `tunnel_ed25519` e a unidade v1 foram preservados.
  Nenhum par de chaves de gerenciamento novo foi instalado na Oracle.
  A porta candidata `10003` segue sem conexão e sem autorização de chave.

## Oracle: pacote staged pronto, mas nunca executado

**Origem preparada por `ai-maintenance`:**

```text
/home/ai-maintenance/ai-lab-v2-rollout/
```

Contém **15 arquivos** (14 componentes + instalador).
Foi conferido o SHA-256 do instalador na Oracle em 14/10/2026:

```text
1be09a37a0a558f951750d265103387e61f050c1d76733aba098b6afc629f18b
```

O instalador deveria ser copiado sob `/root/ai-lab-v2-rollout/`
pelo administrador `ubuntu`, e rodar `--check` antes de `--apply`,
conforme [runbook de implantação](pairing-v2-oracle-rollout.md).

**Estado real:** o operador informou expressamente que NÃO executou
nenhum comando dessa etapa, e a checagem em 05:41 UTC confirmou:
- `/etc/systemd/system/ai-lab-pairing.service` **ausente**;
- `127.0.0.1:8002` **não escutando**;
- Gateway v1, Caddy, broker e approvals **ativos**;
- nenhum novo listener `127.0.0.1:10003`;
- nenhuma atualização da política protegida v2 implementada na Oracle.

**Cuidado antes de executar:** refazer preflight amanhã, revisar o
script com atenção, obter o `--check` aprovado e conferir a integridade
dos arquivos. Não assumir que compilar/verificar SHA garante que o rollout
não tenha falhas. Em caso de alteração no script ou staging, **recalcular
e registrar o novo hash** antes de qualquer instrução de execução.

## Sequência de retomada (15/10/2026)

1. **Perguntar/validar o estado** antes de iniciar, em especial se o
   operador já aplicou algo manualmente desde este checkpoint.
   Usar MCP `gateway_status`, `list_devices`,
   `device_status` e `exec` de verificação na Oracle.
2. **WSL está offline na última checagem**: se necessário, solicitar
   que o operador inicie sua distribuição Ubuntu WSL localmente
   e execute `sudo systemctl restart ai-lab-wsl-tunnel.service`,
   ou `Conectar AI Lab.bat`, para restabelecer túnel `10002`.
   Não apagar a credencial antiga.
3. **Revisar e validar em segurança o rollout administrativo** usando
   [runbook](pairing-v2-oracle-rollout.md).
   Na Oracle, somente o `ubuntu` com sudo pode fazer a instalação root;
   **não** tentar dar sudo ilimitado a `ai-maintenance`. Se `--check`
   falhar, parar, investigar, preservar o backup.
4. **Depois da instalação e health checks** (NÃO antes):
   validar `https://gateway.debasti.com/pairing/health`,
   `https://gateway.debasti.com/approvals/health`,
   socket permissions, serviço no systemd e disponibilidade MCP
   (talvez seja preciso reconectar/recriar a app do ChatGPT devido
   a cache de descoberta).
5. Solicitar `pairing_invite` autenticado com escopo/política corretos.
   Enviar o token temporário ao instalador via canal HTTPS seguro;
   nunca publicar token em Git, logs ou como link público.
6. **Solicitar o pareamento real do WSL**, mantendo `persistent=false`,
   com chave candidata e fingerprint real. Conferir no painel
   `/approvals/pairing` e aprovar apenas se as fingerprints baterem.
7. **Provisionamento SSH candidato faltante:** criar chave de gestão
   exclusiva e autorização SSH reversa em `127.0.0.1:10003`,
   credenciais sem sudo, servidor conhecido/pinado, serviço sob demanda
   novo em paralelo ao anterior e testes positivos/negativos.
   Isso exige implementação e autorização administrativa específica
   na Oracle e instalação local no WSL.
8. Após teste ponta a ponta, passar o ID `windows-wsl` para o novo
   túnel, confirmar que funciona e **só então** revogar o par de
   credenciais v1 (com plano de rollback).
9. Próxima fase: implementar e testar o gerenciamento real das
   permissões Linux Restrito/Parcial/Irrestrito e a flag `persistent`
   pelo MCP por dispositivo, não confundir com pareamento.

## Referências rápidas para o novo chat

- [Guia de implantação Oracle v2](pairing-v2-oracle-rollout.md)
- [Migração controlada do WSL](wsl-v2-migration.md)
- [Contrato produto: cadastro e permissões](v2-device-onboarding-access.md)
- [Decisões ADR-027/028](decisions.md)
- [Issue #1 — Cadastro simplificado](https://github.com/fabianodebastiani/ai-lab-gateway/issues/1)
- [Issue #2 — Perfis de acesso](https://github.com/fabianodebastiani/ai-lab-gateway/issues/2)

**Primeira frase recomendada para retomar:** "Retomemos o AI Lab Gateway v2
pelo checkpoint de 14/10. Ainda não instalei nada na Oracle." Confirmar essa
última afirmação se algo tiver mudado fora do chat.


## Adendo — retomada 15/10/2026

O instalador Oracle foi reforçado com pré-verificação da política real de autorização e da rota Caddy proposta **antes** de qualquer mudança. A nova configuração Caddy foi validada em modo de teste sem gravar produção. O script preparado em `/home/ai-maintenance/ai-lab-v2-rollout/` foi atualizado e teve o novo SHA-256 registrado acima. O operador ainda não fez a instalação administrativa; a próxima etapa é o `--check` como `ubuntu` e somente depois o `--apply` se todas as validações forem satisfatórias.


## Atualização operacional — 15/10/2026, após o primeiro deploy

**Este adendo substitui o status operacional antigo de `--apply` não executado
para o dia 15/10; o histórico do encerramento de 14/10 acima permanece válido.**

- O operador `ubuntu` copiou o bundle para `/root/ai-lab-v2-rollout/`,
  verificou o SHA do instalador e concluiu `--check` com
  `BUNDLE_SHA256_VERIFIED; services active; no changes`.
- `--apply` foi executado e **falhou** na checagem de
  `http://127.0.0.1:8002/pairing/health` (curl status 7).
  Backup: `/var/backups/ai-lab-gateway/pairing-v2-20261015T033754Z`.
  Instalador informou `ROLLBACK_ATTEMPTED`.
- Verificação independente pós-rollback via MCP confirmou quatro serviços
  originais ativos (gateway, broker, approval-web, caddy), HTTPS Auth0/painel
  respondendo, `oracle-gateway` SSH `exec()` funcionando, e pareamento
  v2 ausente/desativado. O Raspberry voltou a responder; WSL permanece
  desconectado. Não repetir `--apply` sem descobrir a causa root.
- O projeto continua com mesmo escopo: enrollment Restrito, depois elevação
  separada Restrito/Parcial/Irrestrito; persistência independente por dispositivo.
- Para evitar repetição de comandos root, foi implementada e testada no Git
  uma **operação fixa de leitura do journal do pairing**, dependente de
  aprovação humana no broker atual. Ainda não implantada: consultar
  [runbook dedicado](broker-pairing-journal-rollout.md). **Não** concede
  `sudo` irrestrito a `ai-maintenance`.


## Adendo final — 15/10/2026 04:16 UTC: v2 server instalado com sucesso

**Estado mais recente prevalece sobre os relatos históricos acima.**
O administrador `ubuntu` concedeu explicitamente uma janela de
`sudo` de 60 minutos para o usuário operacional `ai-maintenance`.
O timer systemd root-owned `ai-lab-maintenance-60m-revoke.timer`
está ativo, com disparo em **2026-10-15 05:08:04 UTC**; a revogação
não desfaz alterações permanentes efetuadas durante a janela.
MCP confirmou `sudo -n id -u` = 0 e a continuidade dos serviços
originais. Acesso de recuperação `ubuntu` foi mantido.

Diagnóstico da instalação v2:
1. Journal completo da tentativa anterior indicou que o novo serviço
   iniciou e criou SQLite, mas health check da porta 8002 falhou
   muito cedo. Teste de serviço isolado, reproduzindo os sockets
   Unix reais, respondeu HTTP 200, sem alterações no Gateway v1.
2. Instalador revisado para usar retries de health por 30 segundos.
   A segunda tentativa passou local/HTTPS pairing, mas revelou que
   o health check do painel antigo retorna texto `ok`, não JSON;
   rollback ocorreu conforme previsto.
3. Corrigido parse da saúde do painel; 8 testes do instalador passaram
   e `--check` passou sem alterações. Script final SHA-256:
   `0bbef6572989ab5d7c14f4e38a4d31e62b2536ffafefb73638c09fdc7fa4a7ff`.
4. Terceira tentativa via `systemd-run` independente concluiu com
   `PAIRING_PILOT_DEPLOYED` e todos os health checks OK.
   Backup: `/var/backups/ai-lab-gateway/pairing-v2-20261015T041535Z`.

Pós-deploy:
- `ai-lab-pairing.service`, ambos sockets, MCP, broker, approvals
  e Caddy estão ativos.
- O serviço de pareamento roda como usuário próprio não-root,
  `NoNewPrivileges=yes`; DB 0600, diretório 0700.
  Sockets de MCP e aprovador têm grupos distintos, modo 0660,
  nenhum acessível diretamente por `ai-maintenance` (EACCES).
- Há exatamente um grant `device_enroll` na política protegida,
  sem expor identidade de operador.
- Oracle SSH e Raspberry online via MCP; WSL continua offline,
  e não houve rotação das chaves de nenhum dispositivo existente.
- **Servidor v2 instalado não equivale a onboarding completo.**
  Falta provisionamento SSH real pós-aprovação, instalador local
  Linux, teste de WSL/VM candidato, e aplicação remota da política
  Restrito/Parcial/Irrestrito.
- A conexão ChatGPT poderá precisar renovar descoberta OAuth/MCP
  para exibir `pairing_invite`, `pairing_requests` e
  `pairing_status`.
- O broker fixo de diagnóstico `pairing-service-journal` foi
  criado e testado no Git, mas **não** foi implantado; não
  é mais necessário para o troubleshooting atual com sudo temporário.

Próximo passo: confirmar ferramentas de onboarding pelo MCP, testar
o fluxo de convite em ambiente de teste e construir o provisionador
SSH completo com isolamento e rollback. Preservar v1 até
aceitação ponta a ponta. **Não repetir o instalador --apply
na instalação v2 agora ativa.**
