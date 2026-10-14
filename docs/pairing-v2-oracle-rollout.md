# Pairing v2 — implantação supervisionada na Oracle (piloto WSL)

Estado em 2026-10-14 UTC: **artefatos compilados e preparados; NÃO instalado em produção**.

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

**SHA-256 do instalador (confirmar independentemente antes de executar):**

```text
55e1fe5880ad0aa94527d1bd2be9b49e300ba955d9cc1a8593508c9b46d5e01a
```

## Única intervenção do administrador Oracle (conta `ubuntu`)

No terminal SSH/console conectado à Oracle usando a conta administrativa
`ubuntu`, execute:

```bash
sudo install -d -o root -g root -m 0700 /root/ai-lab-v2-rollout
sudo find /home/ai-maintenance/ai-lab-v2-rollout -maxdepth 1 -type f -exec cp -t /root/ai-lab-v2-rollout -- {} +
sudo chown root:root /root/ai-lab-v2-rollout/*
sudo chmod 0600 /root/ai-lab-v2-rollout/*
sudo sha256sum /root/ai-lab-v2-rollout/install_pairing_pilot_oracle.py
```

**Compare** o hash exibido ao valor acima. Se não coincidir, pare e não execute.

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
