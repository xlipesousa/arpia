# Planejamento de Migrações Complementares — Fase 4

## Objetivo

Mapear ajustes estruturais necessários após a ingestão completa do catálogo ATT&CK e o crescimento das recomendações automatizadas. As mudanças abaixo devem ser avaliadas com dados reais de staging antes da implementação.

## ÍNDICES E BUSCA

1. **Filtro por confiança**
   - Índice composto em `CveAttackTechnique (cve, source, confidence)` já existente; avaliar adicionar `technique_id` para acelerar drill-down em APIs públicas.

2. **Recomendações automatizadas**
   - Índice parcial `idx_hunt_rec_auto_recent (recommendation_type, created_at)` com condição `generated_by='automation'` criado para priorizar recortes Blue/Red em listagens recentes.
   - Índice parcial `idx_hunt_rec_playbook (playbook_slug)` garante busca rápida por playbooks nomeados (condição `playbook_slug > ''`).

## CAMPOS COMPLEMENTARES

- `HuntRecommendation.confidence_note`: `CharField` (512) opcional para contextualizar alterações manuais nas recomendações automatizadas.
- `HuntRecommendation.playbook_slug`: `CharField` (128) curto que referencia playbooks reutilizáveis (integração planejada para a Fase 5).
- `AttackTechnique`: manter backlog para cache textual apenas se surgir necessidade; como não migraremos para PostgreSQL, priorizar abordagens leves (índices parciais + pesquisa incremental em SQLite).

## SEQUÊNCIA DE EXECUÇÃO PROPOSTA

1. Adicionar campos opcionais (`confidence_note`, `playbook_slug`).
2. Criar índices condicionais para recomendações automatizadas.
3. Atualizar serializers e testes (`tests/api/test_hunt_endpoints.py`, `arpia_hunt/tests.py`) assim que os novos campos forem expostos.
4. Registrar que a busca full-text permanece em backlog até a adoção de PostgreSQL.
   - Status: backlog reclassificado como "não planejado" enquanto permanecermos em SQLite; revisitar apenas se surgir requisito explícito de busca textual.

## VALIDAÇÃO

- Reexecutar `python manage.py test arpia_hunt` e `python manage.py test tests.api` após aplicar as migrações.
   - `tests/api/test_hunt_endpoints.py` já cobre `confidence_note` e `playbook_slug` nas respostas dos endpoints; manter fixtures sincronizadas com os novos campos.
   - `arpia_hunt/tests.py` valida o detalhamento do template `finding-detail` e as ações do comando `import_attack_catalog` com pyattck (incluindo `--matrix all`).
- 2025-11-02 · `EXPLAIN QUERY PLAN` em SQLite:
   - Findings: `SEARCH arpia_hunt_huntfinding USING INDEX idx_hunt_finding_project_sev (project_id=?)`.
   - Recomendações (automation + filtro por tipo): `SEARCH arpia_hunt_huntrecommendation USING INDEX idx_hunt_rec_auto_recent (recommendation_type=?)`.
- Avaliar `EXPLAIN QUERY PLAN` das consultas-chave (filtros combinados de findings/recommendations) diretamente no SQLite para garantir que os novos índices sejam usados.
- Monitorar impacto na replicação do banco e na janela de deploy.
- Registrar checklist de verificação pós-deploy no runbook de operações (monitorar métricas `hunt.api.latency` e erros das integrações).
   - Resultado de referência documentado em `docs/hunt-runbook.md` (inclui SQL, plano e interpretação).

## CHECKLIST DE DEPLOY

- [x] Confirmar criação dos índices condicionais via `python manage.py showmigrations` e inspeção do schema (`.schema hunt_huntrecommendation`).
- [x] Executar smoke test manual nos endpoints `/api/hunt/findings/` e `/api/hunt/recommendations/` verificando os campos `confidence_note` e `playbook_slug`.
- [x] Validar filtros multi-valor (CSV) nos parâmetros `project`, `technique`, `confidence`, `type`, `generated_by` e `finding`, garantindo alinhamento com a OpenAPI regenerada.
- [ ] Monitorar métricas em produção nas primeiras 24h: `hunt.api.latency`, `hunt.recommendations.db_time`, `hunt.api.error_rate`.
- [x] Validar que dashboards internos refletem os novos campos (painéis Grafana/Metabase atualizados) e anexar evidências no runbook.

## Integrações Externas

- Contratos automatizados adicionados em `arpia_hunt/tests/test_integrations.py`, cobrindo NVD, Vulners e searchsploit (erros, timeouts e parsing de JSON).
- Fixtures reutilizam `nvd_cve.json`, `vulners_cve.json` e `exploitdb_results.json`; mantê-las atualizadas conforme novos cenários emerjam em staging.
- Documentar variáveis de ambiente (`ARPIA_HUNT_NVD_API_KEY`, `ARPIA_HUNT_VULNERS_API_KEY`, `ARPIA_HUNT_SEARCHSPLOIT_PATH`, timeouts) no manual operacional e validar presença no pipeline de deploy.

## Entregáveis da Fase 4 (Atualização)

- Migrations e campos opcionais disponíveis; serializers e APIs expõem `confidence_note`, `playbook_slug` e filtros combinados.
- Testes de contrato para integrações e endpoints REST centralizados nos módulos `tests/api/` e `arpia_hunt/tests/`.
- Especificação OpenAPI publicada em `docs/api/hunt-openapi.yaml`, alinhada com filtros multi-valor e resposta detalhada de recomendações.

## Revisão pré-staging

- [x] Revisar a migration `0006_attacktechnique_search_vector` para confirmar que os campos e índices mencionados continuam opcionais em bancos com dados legados.
- [x] Registrar evidências da execução dos testes (`arpia_hunt.tests`, `tests.api`) anexando logs ao checklist de deploy.
- [x] Validar que o dashboard (`templates/hunt/dashboard.html`) referencia `findings/<uuid>/` em todos os cards relevantes, garantindo cobertura funcional antes do push para staging.
