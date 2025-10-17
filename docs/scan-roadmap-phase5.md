# ARPIA Scan — Roadmap Fases 5 a 7

## Contexto atual (até Fase 4)
- Sessões de scan podem ser criadas/iniciadas pela dashboard com presets de tarefas simuladas.
- Página de detalhe acompanha status em tempo real via polling, exibindo progresso, saída das etapas e achados.
- Serviço de orquestração gera logs centralizados (`arpia_log`) para cada sessão e tarefa.
- Testes automatizados (`arpia_scan/tests.py`) garantem regressão básica da API e do fluxo UI → serviço.

## Fase 5 — Telemetria e persistência avançada
- **Objetivo:** transformar a simulação em uma base sólida para ingestão real de resultados.
- **Itens propostos:**
  - Persistir stdout/artefatos relevantes em um storage dedicado (ex.: `ScanArtifact`).
  - Mapear achados por host/porta/serviço, relacionando com módulos `arpia_vuln` e `arpia_report`.
  - Expor endpoint para streaming incremental de logs por tarefa (paginado ou SSE).
  - Popular `arpia_log` com correlação para assets, permitindo filtros por alvo.

## Fase 6 — Integração com ferramentas reais
- **Objetivo:** conectar scripts/ferramentas cadastradas ao orchestrator.
- **Itens propostos:**
  - Implementar adaptadores para execução real (ex.: containers, Celery workers ou subprocessos).
  - Definir contrato de entrada/saída para cada `ScanTask` (parâmetros, arquivos temporários, macros).
  - Adicionar mecanismos de cancelamento/retry e watchdog de tempo máximo.
  - Atualizar UI para exibir comandos executados e progresso granular (percentuais por etapa interna).

## Fase 7 — Relatórios e automação contínua
- **Objetivo:** fechar ciclo com relatórios consumíveis e automação.
- **Itens propostos:**
  - Gerar resumo PDF/HTML com achados, logs principais e estatísticas de varredura.
  - Integrar com `arpia_report` para vincular sessões a relatórios de clientes.
  - Disponibilizar agendamento recorrente de scans e notificações (email/webhook) ao concluir ou falhar.
  - Criar dashboards sintéticos (ex.: tempo médio de execução, taxa de falhas, hosts mais críticos).

## Pré-requisitos transversais
- Expandir suíte de testes (unit + integração + UI) a cada fase.
- Documentar APIs públicas (OpenAPI ou schema DRF) e usos esperados.
- Monitorar desempenho: logging estruturado, métricas de tempo e consumo por tarefa.

## Próximas ações imediatas
1. Conectar `ScanOrchestrator` ↔ `arpia_log` (já iniciado na Fase 4).
2. Mapear dados de host/porta em `ScanFinding` para futura integração com módulos de vulnerabilidade.
3. Avaliar abordagem tecnológica para execução real (subprocesso vs. job queue) antes de iniciar a Fase 6.
