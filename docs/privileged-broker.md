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

## Versão v0.3 — validada na Oracle (2026-10-14)

- `scripts/privilege_broker.py` usa `fcntl.flock` no armazenamento local e vincula o grant ao `subject`; mantém escopo de operações somente leitura e consumo antes da execução.
- Resultados reais: operação correta, sujeito incorreto negado, replay negado, revogação, expiração, TTL inválido, operação desconhecida; seis execuções paralelas de um mesmo grant, apenas uma bem-sucedida.
- Arquivos de estado são `root:root`: diretório 0700, `grants.json`, `audit.jsonl`, `lock` 0600.

## Versão v0.4 — daemon e integração MCP (2026-10-14)

### Componentes

- `scripts/privilege_broker_daemon.py`: daemon independente rodando como root pela unidade `deploy/ai-lab-privilege-broker.service`.
- Socket local `/run/ai-lab-privilege-broker/broker.sock`, diretório `root:ai-lab-gateway` 0750, socket `root:ai-lab-gateway` 0660.
- Cada conexão é conferida via `SO_PEERCRED`; **apenas o UID Unix `ai-lab-gateway`** pode solicitar operações pela API local. O SSH operacional `ai-maintenance` não pode conectar ao socket.
- `src/ai_lab_gateway/broker_client.py`: cliente de socket usado pelo servidor MCP.
- `src/ai_lab_gateway/server.py`: quatro ferramentas adicionais (`privilege_request`, `privilege_status`, `privilege_execute`, `privilege_revoke`). Todas exigem token OAuth com `gateway:control` e ação explícita `privilege_request` para dispositivo `oracle-gateway`. O `subject` é derivado exclusivamente do contexto OAuth verificado — não é argumento de ferramenta.
- A política de produção (`/etc/ai-lab-gateway/authorization.json`) recebeu a nova ação apenas na autorização já existente para `oracle-gateway`, com backup `authorization.json.before-privilege-broker-v04`. O arquivo de política e os sujeitos OAuth nunca devem ir ao GitHub.

### Fluxo de uso

1. Solicitante autenticado chama `privilege_request(operation, ttl_seconds)`. O broker cria solicitação `pending` e retorna `request_id`; prazo para aprovação: 1 hora.
2. Administrador local com acesso root, **fora do canal MCP**, revisa via `sudo /usr/local/libexec/ai-lab-privilege-brokerd --list` e confirma usando `--approve <request_id>` ou `--deny <request_id>`.
3. Após a aprovação, começa o TTL escolhido (30 minutos padrão; máximo 24 horas).
4. O mesmo `subject` autenticado consulta e executa a solicitação uma única vez, ou a revoga. Consumo é persistido antes de executar.
5. Pedidos expirados, revogados, não aprovados, de sujeito errado ou já consumidos são negados; eventos relevantes ficam em `/var/lib/ai-lab-privilege-broker/requests-audit.jsonl` (root-only).

### Segurança / estado atual

- Operações permitidas: `gateway-service-status` e `gateway-service-enabled`. Comandos são vetores argv fixos via `subprocess.run(shell=False)`, sem argumentos de shell.
- `flock` e escrita atômica protegem o banco JSON root-only `requests.json`; corridas de consumo são serializadas.
- Gateway MCP e broker systemd estão ativos após restart. `ai-maintenance` não conseguiu acessar socket; `ai-lab-gateway` conseguiu.
- Teste de integração: antes de aprovar, execução negada; após aprovação de **teste via root**, sujeito diferente negado, execução única permitida, replay negado.
- Suíte pytest do projeto: **37 passed** em 2026-10-14 na Oracle. Inclui `tests/test_privilege_broker.py` (aprovação, expiração, vínculo a sujeito, revogação, validação e corrida de concorrência).
- **Limitação de interface:** a instalação do código MCP e reinício do Gateway foram concluídos; o catálogo de ferramentas já carregado na conexão ChatGPT ainda exibe a versão anterior de seis ferramentas. Poderá ser necessário atualizar/reconectar o plugin para disponibilizar as quatro novas operações neste chat.
- **Limitação de segurança:** a aprovação ainda é por CLI root local, não existe painel/UI com segundo fator. Enquanto `ai-maintenance` tiver sudo irrestrito temporário de bootstrap, a separação administrativa é bypassável por essa conta; retirar a regra até o fim da janela de bootstrap. O socket confia no Gateway como intermediário OAuth, não valida tokens OAuth diretamente.
- O controle atual atende teste supervisonado de *operações somente leitura*, não habilita sudo arbitrário nem promete proteção contra um invasor que já tenha root. Antes de operações mutáveis: aprovação humana autenticada e independente, proteção contra spam/DoS, rotação/retenção de logs, testes de recuperação e política por operação.

### Verificações operacionais

```bash
sudo systemctl is-active ai-lab-gateway ai-lab-privilege-broker
sudo systemctl status ai-lab-privilege-broker --no-pager
sudo /usr/local/libexec/ai-lab-privilege-brokerd --list
sudo stat -c '%a %U:%G %n' /run/ai-lab-privilege-broker/broker.sock
# Verificar ausência de regra irrestrita após término do bootstrap:
sudo test ! -e /etc/sudoers.d/90-ai-lab-bootstrap && echo bootstrap_revoke_ok
```

Não publicar dumps de `authorization.json`, conteúdos de `gateway.env`, logs reais de autenticação, chaves de gestão ou conteúdos do diretório privado de estado.
