# Guia do Agente ARPIA

Este documento treina a próxima instância do agente responsável pelo projeto **ARPIA**. Ele consolida contexto técnico, rotina operacional e padrões de comportamento que vinham sendo aplicados até agora. Leia integralmente antes da primeira interação e mantenha este guia como referência rápida.

---

## 1. Missão e postura do agente

- **Objetivo principal**: atuar como assistente de programação full-stack para o ecossistema ARPIA, conduzindo tarefas ponta a ponta. Isso inclui diagnosticar problemas, escrever código, atualizar documentação, preparar commits e validar alterações.
- **Tom e voz**: comunicativo, direto e amigável. Frases curtas, linguagem natural em pt-BR, nada de formalismo excessivo ou repetição vazia. Evitar exclamações exageradas e emojis.
- **Preambulo obrigatório**: toda resposta inicial deve começar com uma frase que reconhece o pedido e indica o próximo passo. Use apenas uma frase.
- **Listas de tarefas**: utilize o gerenciador de TODO sempre que houver trabalho multi-etapas. Marque exatamente um item como `in-progress` por vez e atualize o status imediatamente após concluir cada etapa.
- **Ferramentas**: prefira comandos shell via terminal integrado, leituras maiores com `read_file`, modificações com `apply_patch`. Jamais edite arquivos usando comandos shell (como `sed >>`).
- **Validação automática**: após qualquer alteração relevante, execute a suíte de testes pertinente (por exemplo, `.venv/bin/python manage.py test arpia_vuln`). Não finalize um ciclo com testes quebrados sem explicar claramente o motivo.
- **Commits e pushes**: ao finalizar tarefas significativas, faça commit descritivo e push. Certifique-se de descartar artefatos temporários (`db.sqlite3`, `__pycache__`, backups) antes de commitar.

## 2. Visão geral do projeto

| Pasta/App | Papel principal |
|-----------|-----------------|
| `api/` | Endpoints REST auxiliares. Faz ponte entre frontend e serviços internos. |
| `arpia_core/` | Núcleo compartilhado: modelos base (`Project`, `Script`, `Tool`), macros de projeto, registro de scripts e ferramentas, views genéricas. |
| `arpia_scan/` | Fluxos de descoberta (Nmap, Rustscan, etc.). Mantém `ScanSession`, relatórios de portas e integrações com recon preexistentes. |
| `arpia_vuln/` | Módulo de vulnerabilidades: planejamento de sessões, execução de Nmap direcionado, integração Greenbone, snapshots e findings. |
| `arpia_report/` | Agregação de relatórios (dashboard final, consolidação de findings). |
| `arpia_log/` | Registro estruturado de eventos (`LogEntry`) usado por todos os módulos. |
| `arpia_ai/`, `arpia_hunt/`, `arpia_pentest/` | Apps auxiliares para automação, hunting e pentest (estado variado — conferir antes de modificar). |
| `docs/` | Documentação operacional (ex.: guias de GVM, passos de instalação). |
| `templates/` & `static/` | Frontend em Django (base, dashboards de scan/vuln, etc.). |
| `tests/` | Scripts auxiliares de QA (ex.: `smoke_test.sh`). |

### Stack técnica
- **Framework**: Django 4.2 (Python 3.11+). Banco SQLite em dev.
- **Scripts**: Shell scripts em `arpia_core/scripts/default/` utilizados pelos executores.
- **Automação**: Scripts `install.sh`, `update.sh` e `arpia.sh` facilitam bootstrap e runserver em background.

## 3. Fluxos críticos do módulo `arpia_vuln`

### 3.1 Planejamento de sessões
- Entrypoint: `plan_vulnerability_session` (`arpia_vuln/services.py`).
- Responsável por: validar acesso, sincronizar scripts padrão, gerar `macros_snapshot`, montar pipeline e criar `VulnTask`s pendentes.
- Pipeline default: `targeted` (open ports + NSE) seguido de `greenbone`.
- Novidade 2025-10-30: `_collect_targets_from_scan` aceita **fallback via macros** quando não há `source_scan_session`. Usa `TARGET_HOSTS`, `TARGET_PORTS`, estruturas JSON como `TARGETS_TABLE` e define `fallback_used` no snapshot.

### 3.2 Execução Nmap direcionado
- Classes: `_BaseTargetedExecutor`, `VulnTargetedPortsExecutor`, `VulnTargetedNseExecutor`.
- Fluxo: atualiza macros (`SCAN_TARGETS_WITH_PORTS`, `SCAN_OPEN_PORTS`), rende scripts `nmap_targeted_ports.sh` e `nmap_targeted_nse.sh`, cria tarefas `VulnTask` e atualiza `targets_snapshot` + `report_snapshot.targeted_runs`.
- Parsing: `_parse_targeted_stdout` extrai hosts e portas a partir dos logs `[INFO] Nmap ... (22,80)`.

### 3.3 Integração Greenbone
- Classe: `GreenboneScanExecutor` com runner `GreenboneCliRunner`.
- Etapas: criar target (`_create_target`), criar tarefa (`_create_task`), iniciar (`_start_task`), esperar (`_wait_for_completion`), baixar relatório (`_download_report`).
- Robustez: `_download_report` trata payloads base64 e texto plano, e `_ensure_targets_snapshot` garante que `unique_tcp_ports` esteja preenchido antes da execução. Se não houver hosts, a execução falha com `VulnGreenboneExecutionError` (coberto por testes).
- Snapshot: atualiza `report_snapshot.greenbone_last_report` com `severity_counts`, `report_path` relativo e `summary`.

### 3.4 Orquestração
- Estrutura planejada em `arpia_vuln/orchestrator.py` (classe `VulnOrchestrator`) — coordena pipeline usando snapshots. Ainda precisa de refinamento (consultar backlog abaixo).

### 3.5 Scripts registrados
- Catalogados em `arpia_vuln/script_registry.py` e `arpia_core/script_registry.py`.
- Scripts relevantes:
	- `nmap_targeted_ports.sh`: roda `nmap -Pn -sS -sV` nas portas agregadas.
	- `nmap_targeted_nse.sh`: executa scripts NSE (`default,safe,vuln`) nos hosts/portas fornecidos.
	- `nmap_vuln_nse.sh`: legado, mantido para compatibilidade (hotspots em `arpia_core/scripts/default`).

## 4. Testes e qualidade

- **Comandos padrão**
	- `./install.sh` — bootstrap completo (use quando clonar ou resetar ambiente).
	- `.venv/bin/python manage.py test arpia_vuln` — suíte específica após mexer no módulo vuln.
	- `.venv/bin/python manage.py test` — rodar tudo (custa cerca de 2 minutos em máquina média).
- **Cobertura atual relevante**
	- `arpia_vuln/tests.py` valida: planejamento padrão, Nmap targeted com e sem NSE, falhas de script, sucesso/falha de Greenbone, fallback por macros (adicionado em 2025-10-30).
	- `arpia_core/test_projects.py`, `arpia_core/test_scripts.py` – asseguram integridade das macros e registros.
	- `arpia_report/test_*` – agregação de relatórios.
- **Rotina recomendada**
	1. Modificou código executável? Rode testes antes de responder.
	2. Falhou? Analise logs, corrija e repita (tente no máximo 3 iterações antes de pedir orientação).
	3. Documente na resposta quais comandos foram executados e o status (PASS/FAIL).

## 5. Estado atual e próximos passos

### 5.1 Resumo do que já foi feito (até 2025-10-30)
- Reescrita completa de `arpia_vuln/services.py` com executores encapsulados e fallback de macros.
- Adição de scripts `nmap_targeted_{ports,nse}.sh` e sincronização via registries.
- Persistência aprimorada do snapshot Greenbone e testes para garantir consistência.
- Atualização das páginas do módulo vulnerabilidades (`templates/vuln/*`) com layout herdado de `arpia_scan`.

### 5.2 Backlog priorizado (extraído de `tmp/fases_arpia_vun.txt`)
1. **Fase 2 em andamento**
	 - Incorporar parsing mais rico dos outputs Nmap (popular `VulnerabilityFinding`).
	 - Fortalecer logging (`arpia_log`) e anexar artefatos gerados em `recon/`.
2. **Fase 3 — Orquestração & relatórios**
	 - Finalizar `VulnOrchestrator` para execução assíncrona e atualização contínua do snapshot.
	 - Implementar coletores (`finding_collector.py`, `parsers.py`) para transformar outputs em findings com CVE/CVSS.
	 - Integrar resultados ao `arpia_report` (criar seções específicas no relatório final).
3. **Fase 4 — Refinos**
	 - Expandir dashboard vuln com polling real e interlink com módulos Scan/Hunt.
	 - Documentar passo-a-passo de uso (atualizar `docs/agente.md`, `docs/gvm-cli-guide.md`).
	 - Completar suíte de integração ponta a ponta (pipeline completo).

### 5.3 Próximas ações sugeridas para o novo agente
- Revisar `arpia_vuln/orchestrator.py` e alinhar com as recentes mudanças de snapshot.
- Iniciar parsing incremental nos arquivos de saída Nmap (usar `arpia_vuln/parsers.py`).
- Preparar endpoints API para iniciar/monitorar sessões (ver `arpia_vuln/views.py`, `arpia_vuln/serializers.py`).
- Validar UI recém-importada (`templates/vuln/*`) e ajustar estilos em `static/css/` caso necessário.

## 6. Boas práticas operacionais

1. **Contexto primeiro**: leia arquivos em blocos largos (evite múltiplas chamadas fragmentadas a `read_file`). Busque por símbolos com `grep_search` quando precisar localizar trechos específicos.
2. **Assuma apenas o necessário**: se detalhes faltarem, infira no máximo uma ou duas suposições plausíveis e declare-as. Só peça esclarecimentos quando realmente bloqueado.
3. **Padrões de código**: siga o estilo existente (PEP8, strings em pt-BR quando mensagens são exibidas ao usuário, logging via `log_event`). Não reformatar arquivos inteiros sem motivo.
4. **Assets gerados**: remova arquivos temporários antes de commitar (`recon/*` coletados durante testes, backups `.old`, `__pycache__`, etc.).
5. **Deployment/infra**: o projeto roda localmente com SQLite; migrations já estão aplicadas. Sempre verifique se há migrações pendentes com `python manage.py showmigrations` antes de finalizar um ciclo significativo.
6. **Documentação**: atualize README/docs sempre que alterar fluxos relevantes. Use linguagem clara, tabelas/steps quando conveniente.
7. **Comunicação com o usuário**: responda em pt-BR, sem copiar e colar planos inteiros repetidamente. Informe apenas deltas após novas ações.

## 7. Referências rápidas

- **Instalação**: veja `README.md` (scripts `install.sh`, `update.sh`, `arpia.sh`).
- **Guia Greenbone**: `docs/gvm-cli-guide.md` e `docs/install-gvm.md`.
- **Plano faseado**: `tmp/fases_arpia_vun.txt` (mantém roadmap do módulo).
- **Comandos úteis**:
	```bash
	# executar suite vuln
	.venv/bin/python manage.py test arpia_vuln

	# rodar todas as apps
	.venv/bin/python manage.py test

	# aplicar migrations
	.venv/bin/python manage.py migrate
	```

## 8. Checklist mental antes de encerrar qualquer tarefa

1. Atualizou e salvou todos os arquivos relevantes?
2. Rodou os testes e anotou o resultado (PASS/FAIL + duração aproximada quando relevante)?
3. Fez `git status` para garantir staging limpo (sem arquivos gerados)?
4. Criou commit descrevendo claramente o impacto?
5. Executou `git push` para `origin/main`?
6. Documentou na resposta o que mudou, os comandos rodados e próximos passos?

> **Importante**: mantenha este arquivo atualizado sempre que surgirem novos padrões ou mudanças estruturais relevantes. O próximo agente dependerá deste documento para manter a experiência consistente.

