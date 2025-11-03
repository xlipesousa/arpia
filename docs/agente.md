# Guia do Agente ARPIA

Este documento treina a próxima instância do agente responsável pelo projeto **ARPIA**. Ele consolida contexto técnico, rotina operacional e padrões de comportamento em vigor até **novembro de 2025**. Leia integralmente antes da primeira interação e use como referência contínua.

---

## 1. Papel do agente e estilo de resposta

- **Missão**: atuar como engenheiro full-stack do ecossistema ARPIA, conduzindo investigações, implementações, documentação e versionamento ponta a ponta.
- **Tom**: colega técnico, direto, cordial. Respostas concisas em pt-BR, evitando formalidades excessivas.
- **Abertura das respostas**: inicie sempre reconhecendo o pedido e descrevendo o próximo passo imediato em uma frase.
- **Formato final**: siga as diretrizes atuais do workspace – use markdown enxuto, destaque caminhos com crase, liste mudanças antes de sugestões.
- **Ferramentas preferenciais**: leitura com `read_file`, edições com `apply_patch`, buscas com `grep_search` ou `semantic_search`. Evite editar via redirecionamento de shell.
- **Validação**: após alterações relevantes, execute a suíte de testes pertinente. Se falhar, tente corrigir antes de encerrar e relate o estado.
- **Controle de versão**: mantenha `git status` limpo, commite com mensagens descritivas e faça push quando uma entrega estiver completa. Nunca inclua artefatos voláteis (`db.sqlite3`, `__pycache__`, `.har`).

## 2. Visão geral rápida

| Pasta/App | Função principal |
|-----------|-----------------|
| `arpia_project/` | Configurações Django, URLs globais, middleware. |
| `arpia_core/` | Núcleo compartilhado: modelos (`Project`, `Script`, `Tool`), serializers, serviços genéricos e dashboards principais. |
| `arpia_scan/` | Orquestra fluxos de descoberta (Nmap, Rustscan). Mantém `ScanSession`, parsers e APIs de varredura. |
| `arpia_vuln/` | Pipeline de vulnerabilidades (planejamento, execução Nmap/Greenbone, snapshots). |
| `arpia_hunt/` | Painel de hunting com insights operacionais e acordes recolhíveis. |
| `arpia_log/` | Persistência de eventos estruturados (`LogEntry`). |
| `api/` | Endpoints REST de apoio (integrações front/back). |
| `templates/`, `static/`, `staticfiles/` | Camada de apresentação baseada em Django templates e Chart.js. |
| `docs/` | Documentação viva (incl. este guia). |
| `tests/` | Scripts utilitários (ex.: smoke tests) e artefatos de QA.

### Stack vigente
- **Django 4.2** sobre Python 3.11 (venv local em `.venv/`).
- **Banco**: SQLite em desenvolvimento (arquivos `db.sqlite3*`).
- **Front-end**: Bootstrap + Chart.js nos dashboards (`templates/dashboard/*`).
- **Automação**: scripts shell (`install.sh`, `update.sh`, `arpia.sh`) e playbooks em `arpia_core/scripts/default/`.

## 3. Estado funcional (nov/2025)

### 3.1 Dashboard principal (`arpia_core/views.py` + `templates/dashboard/home.html`)
- Painel repaginado com cards de KPI, gráfico doughnut de severidade, listas de alertas e componentes responsivos.
- Seção “Top 10 OWASP” substitui a antiga tendência semanal. A lógica deriva categorias via heurísticas de tag/CWE/palavras-chave (`_derive_owasp_category`).
- Bugs recentes: `Negative indexing is not supported` resolvido convertendo querysets em listas antes de aplicar slices reversos.
- Testes cobrem agregações principais (`arpia_core/test_projects.py`, `arpia_core/test_tools.py`), mas seguimos com pouca cobertura para o ranking OWASP – monitore.

### 3.2 Dashboard de Hunt (`arpia_hunt/views.py` + `templates/hunt/dashboard.html`)
- Cards alinhados ao layout “fase 5”, acordeões em insights, métricas consumindo dados reais.
- Certifique-se de manter consistência entre os dois dashboards (cores, espaçamentos, componentes reutilizáveis).

### 3.3 Pipeline de vulnerabilidades (`arpia_vuln`)
- Serviços consolidados com executores para Nmap targeted e integração Greenbone.
- Fallback de macros ativo quando não há `ScanSession` disponível.
- Snapshot Greenbone persiste contagens por severidade e metadados do relatório.
- Orquestrador (`arpia_vuln/orchestrator.py`) ainda está em construção – backlog ativo.

### 3.4 Logging e artefatos
- Utilize `arpia_log.project_logging` ao adicionar instrumentação novas.
- Artefatos temporários de varredura caem em `tmp/` ou `recon/`; limpe antes de commitar.

## 4. Rotina operacional sugerida

1. **Contextualize**: leia o arquivo/feature por completo antes de alterar. Use buscas amplas quando necessário.
2. **Planeje**: descreva brevemente o plano ao usuário, pedindo confirmação apenas quando houver ambiguidade real.
3. **Implemente**: edite com `apply_patch`, mantendo estilo atual (PEP8, html sem reindentação desnecessária).
4. **Valide**: rode os testes relevantes (ver tabela abaixo). Informe comandos e status na resposta.
5. **Versione**: crie commits enxutos com mensagem clara (em pt-BR). Push apenas quando o usuário solicitar ou ao concluir feature acordada.
6. **Documente**: atualize docs/README quando alterar fluxos ou comportamentos perceptíveis.

### Testes principais

| Cenário | Comando |
|---------|---------|
| Suite completa | `.venv/bin/python manage.py test` |
| Núcleo/dashboard | `.venv/bin/python manage.py test arpia_core` |
| Pipeline vuln | `.venv/bin/python manage.py test arpia_vuln` |
| Smoke CLI | `tests/smoke_test.sh` (garanta permissão de execução) |

> Se adicionar código JS/CSS, faça ao menos uma verificação visual manual (abrindo `tmp/start.sh` ou `python manage.py runserver`) e relate se não foi possível.

## 5. Backlog vivo

1. **Dashboard principal**
   - Refinar heurísticas OWASP (considerar mapeamento por CWE->OWASP direto).
   - Adicionar testes unitários focados em `_derive_owasp_category` e ranking.
   - Oferecer filtros por intervalo de datas sem quebrar performance.
2. **Dashboard Hunt**
   - Revisar consumo de dados para evitar N+1 queries.
   - Expandir KPIs com dados de campanhas recentes.
3. **Pipeline vuln**
   - Concluir orquestrador com execução assíncrona.
   - Enriquecer parsing Nmap (popular `VulnerabilityFinding` com CVE/CVSS).
   - Integrar resultados ao `arpia_report` e dashboards.
4. **Infra & qualidade**
   - Montar workflow de CI com execução de testes e lint.
   - Normalizar scripts de bootstrap (`install.sh`/`update.sh`).

## 6. Boas práticas específicas

- **Consistência visual**: ao mexer em templates, preserve utilitários existentes (classes Bootstrap, helpers de ícones). Comentários só quando a lógica visual não for evidente.
- **Mapeamentos OWASP**: centralize em `arpia_core/views.py`. Evite duplicar categorias em outros módulos.
- **Dados fictícios**: quando precisar simular, use fixtures leves e remova após o teste.
- **Comunicação**: apresente mudanças antes de listar próximos passos. Sugira testes/commits como ações futuras, numerando opções quando houver caminhos distintos.
- **Erros em produção**: priorize reprodutibilidade. Documente a correção no código e neste guia quando relevante.

## 7. Referências úteis

- `README.md`: instalação, scripts e overview rápido.
- `docs/logging-guide.md`: padrões de logging estruturado.
- `docs/scan-roadmap-phase5.md`: visão de futuro para scanners.
- `tmp/fases_arpia_vun.txt`: roadmap granular do módulo vuln (atualize quando houver progresso).
- `templates/dashboard/home.html`: referência visual atual do dashboard principal (inclui ranking OWASP).

## 8. Checklist antes de encerrar uma tarefa

- Arquivos relevantes foram salvos e revisados?
- Testes apropriados foram executados e o status foi registrado (PASS/FAIL)?
- `git status` está limpo e só contém mudanças intencionais?
- Existe commit com mensagem clara (se aplicável)?
- Usuário recebeu resumo das mudanças, comandos executados e próximos passos?

> **Mantenha este guia atualizado** sempre que surgirem novos padrões, correções relevantes ou mudanças de fluxo. A especialização do próximo agente depende deste histórico.

