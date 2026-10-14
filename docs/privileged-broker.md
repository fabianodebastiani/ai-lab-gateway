# Privileged broker — arquitetura e estado de implementação

Atualizado: 2026-10-14 UTC. Projeto experimental independente.

## Estado comprovado em produção

- VM `ai-lab-gateway-01` (Ubuntu), Gateway MCP rodando via systemd como `ai-lab-gateway` (não-root), protegido por Auth0 OAuth e autorização por sujeito/dispositivo/ação.
- Dispositivos `raspberry-lab`, `windows-wsl` e `oracle-gateway`.
- `oracle-gateway`: SSH para `127.0.0.1:22`, conta `ai-maintenance`, chave de gestão própria em `/var/lib/ai-lab-gateway/keys/oracle-maintenance`; fingerprint do host verificado; execução, criação/leitura de arquivo e estado systemd testados via MCP.
- `ai-maintenance` sem sudo permanente. Durante bootstrap de 2026-10-14 foi concedido sudo irrestrito TEMPORÁRIO em `/etc/sudoers.d/90-ai-lab-bootstrap`. Revogação agendada para ~02:21:58 UTC via temporizador transitório e `ai-lab-bootstrap-revoke-persistent.timer` persistente. **Confirmar remoção da regra após prazo e não confiar na autogestão como recuperação fora de banda.**
- Esqueleto local instalado em `/usr/local/libexec/ai-lab-privilege-broker`, arquivo de auditoria `/var/lib/ai-lab-privilege-broker/audit.jsonl`, status permitido, execução não implementada e negada por padrão. Testes: status OK, `exec` negado (77).
- Código do esqueleto foi commitado no checkout local em `3eeb316`; push Git via Oracle falhou por falta de credenciais HTTPS. **Não considerar esse commit publicado até confirmar remotamente.**

## Requisitos e decisões

1. Separar identidade operacional SSH (`ai-gateway` ou `ai-maintenance`) da autoridade administrativa. Conta `tunnel` é exclusiva para transporte SSH reverso; não deve executar comandos.
2. Perfil por dispositivo: restrito; sudo por operação específica; broker supervisionado; janela temporária; laboratório irrestrito opt-in explícito.
3. Autorizações administrativas: comando/operação e argumentos exatos com nonce de uso único, ou prazo selecionável de 15min, **30min padrão**, 1h, 4h, 8h, 24h, ou permanente mediante confirmação reforçada.
4. O broker não deve aceitar shell arbitrário, argumentos livres para `sudo`, edição de `sudoers` ou pedidos de grant gerados pela própria identidade operacional. Aprovação autenticada fora do fluxo operacional, protegida contra replay, com escopo, dispositivo, expiração, revogação e auditoria.
5. Ideal: broker root local com interface estreita (socket Unix ou executor com subcomandos fixos), controle de autorização independente do consentimento MCP, armazenamento root-only e lista positiva de operações. Não expor root através do `exec` MCP genérico.
6. Expiração deve funcionar sem ChatGPT e resistir a reboot; prazo limita novos comandos, não necessariamente encerra processos já iniciados. Root pode persistir privilégios: o modelo protege principalmente contra erros e uso indevido acidental, não contra um adversário que já obteve root.
7. `ubuntu` e acesso OCI devem permanecer como recuperação fora de banda. Backups antes de modificar configuração, validação de testes, rollback de service e política.
8. Acesso administrativo de 24h NÃO equivale a trabalho autônomo por 24h; fila/worker persistente é etapa separada.
9. Vercel UI futura: inventário, políticas, solicitações, aprovações, revogações, auditoria. Aprovação sensível validada no servidor/broker, não apenas no navegador.
10. Nunca commitar tokens, segredos, identificadores OAuth privados, chaves SSH ou arquivos de produção.

## Plano incremental

- [x] SSH local Oracle e cadastro no MCP.
- [x] Sudo de bootstrap com expiração persistente.
- [x] Esqueleto deny-by-default e auditoria local.
- [ ] Publicar código do broker no GitHub e adicionar testes automatizados.
- [ ] Definir contrato de operações fixas e modelo de grants assinado/autenticado.
- [ ] Implementar broker com armazenamento root-only, verificação de identidade e autorização independente.
- [ ] Implementar API MCP de solicitação/status/revogação, com scopes e audit.
- [ ] Implantar fluxo seguro de aprovação humana e testes positivos/negativos.
- [ ] Revogar sudo irrestrito de bootstrap; validar ausência de root via `exec` genérico.

## Progresso v0.2 — 2026-10-14 UTC

Implementado e testado diretamente na Oracle: `/usr/local/libexec/ai-lab-privilege-broker`. Fonte publicada em `scripts/privilege_broker.py` (commit `417670c`).

- Interface local exclusivamente root, sem endpoint MCP de concessão de privilégios.
- Banco de grants root-only em `/var/lib/ai-lab-privilege-broker/grants.json`, atualização atômica e auditoria JSONL.
- `issue OPERATION --ttl SECONDS`: cria grant aleatório de uso único, validade entre 1 e 86400 segundos; default 1800 segundos.
- `execute GRANT_ID`: verifica ativo/não expirado e consome **antes** da execução, impedindo replay.
- `revoke GRANT_ID`: invalida o grant.
- Lista positiva inicial: `gateway-service-status` e `gateway-service-enabled`, ambas somente leitura, executadas via argv fixo sem shell.
- Testes reais: emissão OK, execução OK, replay bloqueado, revogação OK, execução revogada bloqueada, TTL >24h bloqueado, operação desconhecida bloqueada.
- **Limitações conhecidas:** emissão via sudo root bootstrap ainda não possui aprovador humano autenticado; banco JSON não oferece exclusão mútua para chamadas concorrentes; grant não está vinculado a sujeito OAuth/dispositivo/argumentos variáveis; revogação não encerra processos já iniciados. Não expor issue/execute diretamente ao MCP, nem usar para operações mutáveis antes de corrigir.
- O `sudo` bootstrap permanece temporário e deve ser revogado; testes locais não significam que o sistema de aprovação remota está concluído.
