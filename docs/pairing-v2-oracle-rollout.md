# Pairing v2 — implantação supervisionada na Oracle (piloto WSL)

> **STATUS ATUAL — 15/10/2026 04:16 UTC: INSTALADO (PILOTO).**
> O instalador corrigido concluiu `PAIRING_PILOT_DEPLOYED` na Oracle.
> Serviços e sockets v2 ativos, endpoints `/pairing/health` e
> `/approvals/health` OK, v1 preservado, nenhum dispositivo migrado.
> **Não execute novamente este procedimento numa instalação já ativa**:
> o preflight rejeita intencionalmente uma rota Caddy de pairing existente.
> A seção de instalação abaixo é histórico/recovery de bootstrap.
> **Faltam o provisionamento SSH completo e os testes de pairing ponta a ponta.**
>
> **CHECKPOINT — 14/10/2026 (encerramento):** o operador informou que
> **não executou NENHUM** dos comandos Oracle abaixo (nem cópia para
> `/root`, nem hash, `--check` ou `--apply`). O novo serviço de
> pareamento **não está implantado em produção**. A última checagem
> às 05:41 UTC confirmou Oracle Gateway e Raspberry online, WSL offline
> (túnel sob demanda), e nenhum listener novo em `10003` ou `8002`.
> **Não executar nada apenas por ler este runbook.** Na próxima sessão,
> revisar o instalador, revalidar hash/serviços e seguir as instruções
> sob controle do operador. Consulte o
> [checkpoint completo](checkpoint-2026-10-14-pairing-v2.md).
>
Estado histórico em 2026-10-14 UTC: artefatos preparados, ainda não instalados.\nEstado confirmado em 2026-10-15 04:16 UTC: infraestrutura v2 implantada e validada.

## Objetivo e limites

Preparar um servidor de cadastro de dispositivos Linux com token efêmero,
revisão humana separada e perfil inicial sempre **Restrito**. Manter
`windows-wsl` conectado em `127.0.0.1:10002` até que um novo túnel
independente (candidato `10003`) passe todos os testes. Não revogar
credenciais antigas, não conceder `sudo` irrestrito à conta MCP.

A nova flag `persistent` pode ser ligada/desligada por qualquer Linux;
o cadastro usa a preferência informada, independente de hardware e de
permissões administrativas.

## Artefatos preparados

Na Oracle, como `ai-maintenance`:

`/home/ai-maintenance/ai-lab-v2-rollout/`

Esse diretório contém 14 arquivos de origem/unidades systemd e um instalador
root supervisionado `install_pairing_pilot_oracle.py`. Os arquivos Python
do pacote passaram em compilação sintática. O script de implantação contém
manifests de SHA-256 **fixados**, backups, checagens de serviços, e rollback.

**SHA-256 atual do instalador (revalidado em 15/10; confirmar independentemente antes de executar):**

```text
0bbef6572989ab5d7c14f4e38a4d31e62b2536ffafefb73638c09fdc7fa4a7ff
```

## Única intervenção do administrador Oracle (conta `ubuntu`)

No terminal SSH/console conectado à Oracle usando a conta administrativa
`ubuntu`, execute:

```bash
sudo install -d -o root -g root -m 0700 /root/ai-lab-v2-rollout
sudo find /home/ai-maintenance/ai-lab-v2-rollout -maxdepth 1 -type f -exec cp -t /root/ai-lab-v2-rollout -- {} +
sudo find /root/ai-lab-v2-rollout -maxdepth 1 -type f -exec chown root:root -- {} +
sudo find /root/ai-lab-v2-rollout -maxdepth 1 -type f -exec chmod 0600 -- {} +
sudo sha256sum /root/ai-lab-v2-rollout/install_pairing_pilot_oracle.py
```

**Compare** o hash exibido ao valor acima. Se não coincidir, pare e não execute.
As duas chamadas `find` em `/root` são intencionais: evitam que o shell
do usuário `ubuntu` tente expandir um `*` sem permissão de leitura.

**Fase 1:** execute somente este bloco de preparação e o `--check`.
Envie a saída do `--check` antes de seguir para a **fase 2** (`--apply`).

Em seguida:

```bash
sudo python3 -I /root/ai-lab-v2-rollout/install_pairing_pilot_oracle.py --check
```

Só após receber `BUNDLE_SHA256_VERIFIED; services active; no changes`
execute:

```bash
sudo python3 -I /root/ai-lab-v2-rollout/install_pairing_pilot_oracle.py --apply
```

O modo isolado `-I` impede importação de módulos inesperados do diretório
temporário. O script recusa arquivos excedentes, symlinks e hashes errados,
e guarda os backups de arquivos privados em
`/var/backups/ai-lab-gateway/pairing-v2-<data>` com acesso root.

O instalador cria a identidade Unix sem sudo `ai-lab-pairing`, instala
os sockets segregados por UID/grupo, o serviço local de claims
(`127.0.0.1:8002`), a rota Caddy `/pairing/*` e novas operações MCP
`pairing_invite`, `pairing_requests` e `pairing_status`.
Acrescenta `device_enroll` **somente** ao operador que já dispõe
explicitamente de `privilege_request` sobre `oracle-gateway`.
Preserva a identidade e permissões originais de arquivos de política.

Atualiza o painel HTTPS existente em
`https://gateway.debasti.com/approvals/pairing` com revisão de
fingerprints via sessão autenticada/CSRF. O cadastro **não exige TOTP**;
operações do broker root continuam exigindo TOTP.

Não cria chave de gerenciamento do dispositivo nem ativa automaticamente
SSH novo antes da revisão humana e da verificação independente. Um
pareamento aprovado fica `approved` até o provisionamento root
realmente concluído.

## Próximo teste após implantação

1. Confirmar serviços/rotas `pairing/health` e `approvals/health`.
2. Atualizar descoberta das novas ferramentas da conexão MCP, se necessário.
3. Solicitar token temporário `pairing_invite`.
4. Reivindicar convite no WSL usando apenas a chave pública nova
   `~ai-gateway/.ssh/tunnel_v2_ed25519.pub` e a chave de host
   `/etc/ssh/ssh_host_ed25519_key.pub`, `persistent=false`.
5. Conferir no painel a fingerprint do túnel
   `SHA256:wxsknp0UezA1nanxLBZ+ZHrwtZ2rHZomPfTFwP9IOSI` e do host
   `SHA256:hh1guyo4yOa81Qj0zrf+XZlNpwaMlH0BfDAdo0SGwCw`.
6. Aprovar o cadastro. Ainda não confundir approval com ativação.
7. Gerar chave de gerenciamento nova na Oracle sob root, estabelecer
   confiança SSH pinada em ambas as pontas, abrir somente a nova porta
   loopback e validar a conexão candidata antes de qualquer cutover.
8. Somente depois revogar chaves antigas, mantendo o ID lógico
   `windows-wsl` e o modo não persistente.

## Evidências e limitações

Ensaios no WSL com chave pública real passaram, incluindo rejeição de
token reutilizado e impossibilidade de ativar sem aprovação.
Aparelho `windows-wsl` seguia online no túnel original após os testes.
HTTP, revisão humana e isolamento de papéis foram validados com dados
sintéticos e em ambiente não produtivo. A integração MCP atual ainda
não inclui as novas ferramentas até a aplicação root e possível refresh
da conexão no cliente.

**Não cole senhas, códigos TOTP, tokens de pareamento nem chaves privadas**
no chat ou no GitHub. Se o instalador retornar erro, interrompa, copie
somente mensagens não sensíveis e preserve os backups para diagnóstico.


## Implantação concluída em 15/10/2026

Tentativa 1, usando instalador original: rollback após falha de
`curl` status 7 para `127.0.0.1:8002`. Logs root confirmaram que
o serviço chegou a iniciar e criar o SQLite, mas uma checagem imediata
não encontrou a porta pronta. Reprodução isolada com os dois sockets
systemd e o próprio serviço respondeu 200. O instalador passou a
aguardar readiness por até 30 segundos, com retry.

Tentativa 2: a saúde local e a saúde HTTPS de pairing passaram, mas
a saúde da interface antiga de aprovação devolve texto `ok`, não
JSON, causando rollback; o instalador foi corrigido e testado.

Tentativa 3 (sucesso): no serviço transitório independente
`ai-lab-pairing-v2-rollout-final-20261015`, depois de
`--check` e 8 testes unitários aprovados, o instalador informou:

```text
BACKUP=/var/backups/ai-lab-gateway/pairing-v2-20261015T041535Z
HEALTH_OK=http://127.0.0.1:8002/pairing/health
HEALTH_OK=https://gateway.debasti.com/pairing/health
HEALTH_OK=https://gateway.debasti.com/approvals/health
PAIRING_PILOT_DEPLOYED; existing SSH keys untouched
```

Verificação MCP independente confirmou que Oracle e Raspberry
respondem por SSH, e os quatro serviços v1 e serviço v2 estão ativos.
Banco local: `/var/lib/ai-lab-pairing/pairing.sqlite3` 0600,
UID exclusivo. Sockets `/run/ai-lab-pairing/mcp.sock` com
grupo `ai-lab-gateway` e
`/run/ai-lab-pairing/approver.sock` com
grupo `ai-lab-approver`, ambos 0660. A conta `ai-maintenance`
não conseguiu conectar a nenhum deles (EACCES).

**Próximo marco:** publicar/testar as ferramentas MCP de pairing
no catálogo do cliente, testar claim e aprovação com identidade
legítima, implementar provisionamento SSH completo isolado e
avaliar integração end-to-end em Linux descartável. Permissões
Restrito/Parcial/Irrestrito ainda não ativadas em alvos reais.
