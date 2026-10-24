# D-Mark Studio Oracle → AI Lab Gateway (M4.2) — 24/10/2026

**Objetivo:** reaproveitar o endpoint existente e comprovado `https://gateway.debasti.com/mcp`, o Auth0 já configurado e o túnel SSH privado existente até `ai-lab-experiments-01-fd3dab34`, SEM criar outro servidor OAuth ou porta pública no Oracle 2.

**Estado REAL:** código da ponte e testes implementados, mas **NÃO implantado** no serviço root-owned do Gateway. A instalação inicial e a edição da política precisam de uma intervenção administrativa autorizada/independente. Não há operações de implantação liberadas no broker de privilégio atual. Não contornar o root-owned `/opt/ai-lab-gateway` ou `/etc/ai-lab-gateway` por meio do MCP `exec`.

## Arquitetura

```text
ChatGPT — conector existente AI Lab Gateway 06
   |
   | OAuth Auth0 vigente; scope gateway:read
   v
https://gateway.debasti.com/mcp
   |
   | policy.require(subject, Oracle2, studio_read)
   v
AI Lab Gateway: studio_bridge.query
   |
   | SSH gerenciado existente (127.0.0.1:<porta reversa>)
   | fixed command (NÃO generic exec)
   v
Oracle2: studio_bridge_cli.py [ação allowlisted, IDs validados]
   |
   v
PostgreSQL local (read-only transaction) + /srv/dmark/data (read-only)
```

## Superfície proposta

- `studio_list_products(limit=10)` → produtos recentes, contagens e caracteres de contexto.
- `studio_get_product(product_key)` → descrição do vendedor + `research_text` completo.
- `studio_list_media(product_key)` → imagens/vídeos UUID, tipos, papéis; sem paths privados ou URLs públicas.
- `studio_get_media_preview(product_key,media_id)` → bloco MCP `Image` JPEG com validação de vínculo e SHA-256. Não inclui MP4; vídeo será trabalhado no M5.

Comandos remotos construídos apenas a partir de ações constantes, SHOP_ID:ITEM_ID numérico e UUID rigorosamente analisado. Limites de resposta, tempo e tamanho de imagem. Auditoria registra apenas sujeito, ação, resultado e latência, não conteúdo do produto ou imagem.

## Autorização — condição de implantação

O wrapper verifica **ambos**: OAuth `gateway:read` **e** permissão privada distinta `studio_read` para o ID do dispositivo Oracle 2 no `/etc/ai-lab-gateway/authorization.json`. Ações legadas `exec`, `status` e `read_file` **não** concedem acesso ao Studio. O administrador habilita `studio_read` somente aos sujeitos OAuth corretos, operador e Simone, depois de confirmar suas identidades por procedimento independente. Nunca publicar o valor dos sujeitos nem sobrescrever a política inteira com exemplo de teste. Em ausência de grant, deny-by-default. A autenticação por usuário não equivale a isolamento dos dados dentro de um workspace compartilhado; este MVP compartilha o catálogo somente entre sujeitos expressamente autorizados.

## Evidência

- CLI Oracle 2 instalado em `/home/ai-gateway/labs/dmark-mcp-v1/studio_bridge_cli.py`, testado de verdade com produtos de catálogo: binóculos `1461429714:58252535082`, 2.222 chars de texto e 10 mídias; inputs de path traversal rejeitados. Nenhum schema alterado.
- 7 testes diretos PASS no Gateway para construção segura de comandos, negação sem `studio_read`, negação sem scope, auditoria, JPEG e erros fechados.
- Conectividade SSH para Oracle 2 já demonstrada pelo AI Lab Gateway 06 no ChatGPT, sem um novo túnel.
- O servidor MCP original Oracle 2 permanece ativo apenas em `127.0.0.1:8787`. O Gateway chama o bridge CLI pelo canal SSH, não necessita expor/proxy dessa porta.
- Regressões de produção do Gateway e teste ChatGPT OAuth **pendentes**, pois o serviço de produção do Gateway é root-owned e não foi modificado.

## Implantação administrativa (NÃO executada)

1. Revisar PR da ponte do AI Lab Gateway e o CLI do repositório Studio; auditar versão, dependências e comandos fixos.
2. Executar suíte completa do Gateway na área de staging utilizando o `venv` legítimo de deploy; validar o registro das quatro ferramentas. Fazer snapshot da versão anterior.
3. Por procedimento ROOT aprovado, atualizar o código sob `/opt/ai-lab-gateway`, sem alterar Auth0/audience/issuer/Caddy nem as ferramentas anteriores.
4. Após confirmar os dois sujeitos por via independente, conceder a cada um **somente** `studio_read` na entrada Oracle 2 da política privada, preservando grants anteriores; backup da política e checksum antes/depois. Sem inscrição pública nem grant wildcard.
5. Reiniciar `ai-lab-gateway` apenas após testes; confirmar `active` e `https://gateway.debasti.com/mcp` continua autenticado.
6. Homologar, com clientes MCP reais, `studio_list_products`, `studio_get_product`, `studio_list_media` e `studio_get_media_preview`, incluindo negação para usuário sem `studio_read`. Se o conector ChatGPT antigo não atualizar o catálogo, reconectar e, se necessário, criar um novo snapshot da integração **usando a mesma URL e Auth0**; evitar refazer scopes sem causa.
7. Regressões AI Lab: `list_devices`, `device_status` e demais ferramentas anteriores preservadas; confirmar Telegram e PostgreSQL Oracle 2 ativos. Só então marcar M4.2 VERIFIED.

**Rollback:** restaurar a release anterior do Gateway e o backup da política, reiniciar e conferir `/mcp`; CLI na Oracle é aditivo e pode permanecer sem exposição. Nenhuma chave, token nem sujeito OAuth está no Git.
