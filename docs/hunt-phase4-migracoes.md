# Planejamento de Migrações Complementares — Fase 4

## Objetivo

Mapear ajustes estruturais necessários após a ingestão completa do catálogo ATT&CK e o crescimento das recomendações automatizadas. As mudanças abaixo devem ser avaliadas com dados reais de staging antes da implementação.

## ÍNDICES E BUSCA

1. **Filtro por confiança**
   - Índice composto em `CveAttackTechnique (cve, source, confidence)` já existente; avaliar adicionar `technique_id` para acelerar drill-down em APIs públicas.

2. **Recomendações automatizadas**
   - Índice parcial em `HuntRecommendation (generated_by, recommendation_type)` para acelerar listagens separadas (Blue/Red).
   - Considerar campo `created_at` no índice para ordenação por recência.

## CAMPOS COMPLEMENTARES

- `HuntRecommendation.confidence_note`: campo `TextField` opcional para comentar alterações manuais nas recomendações.
- `HuntRecommendation.playbook_slug`: `CharField` curto que referencia playbooks reutilizáveis (integração com Fase 5).
- `AttackTechnique`: manter backlog para cache textual apenas se surgir necessidade; como não migraremos para PostgreSQL, priorizar abordagens leves (índices parciais + pesquisa incremental em SQLite).

## SEQUÊNCIA DE EXECUÇÃO PROPOSTA

1. Adicionar campos opcionais (`confidence_note`, `playbook_slug`).
2. Criar índices condicionais para recomendações automatizadas.
3. Atualizar serializers e testes (`tests/api/test_hunt_endpoints.py`) assim que os novos campos forem expostos.
4. Registrar que a busca full-text permanece em backlog até a adoção de PostgreSQL.
   - Status: backlog reclassificado como "não planejado" enquanto permanecermos em SQLite; revisitar apenas se surgir requisito explícito de busca textual.

## VALIDAÇÃO

- Reexecutar `python manage.py test arpia_hunt` e `python manage.py test tests.api` após aplicar as migrações.
   - `tests/api/test_hunt_endpoints.py` já cobre `confidence_note` e `playbook_slug` nas respostas dos endpoints; manter fixtures sincronizadas com os novos campos.
- Avaliar `EXPLAIN QUERY PLAN` das consultas-chave (filtros combinados de findings/recommendations) diretamente no SQLite para garantir que os novos índices sejam usados.
- Monitorar impacto na replicação do banco e na janela de deploy.
- Registrar checklist de verificação pós-deploy no runbook de operações (monitorar métricas `hunt.api.latency` e erros das integrações).
   - Resultado de referência documentado em `docs/hunt-runbook.md` (inclui SQL, plano e interpretação).

## CHECKLIST DE DEPLOY

- Confirmar criação dos índices condicionais via `python manage.py showmigrations` e inspeção do schema (`.schema hunt_huntrecommendation`).
- Executar smoke test manual nos endpoints `/api/hunt/findings/` e `/api/hunt/recommendations/` verificando os campos `confidence_note` e `playbook_slug`.
- Monitorar métricas em produção nas primeiras 24h: `hunt.api.latency`, `hunt.recommendations.db_time`, `hunt.api.error_rate`.
- Validar que dashboards internos refletem os novos campos (painéis Grafana/Metabase atualizados) e anexar evidências no runbook.

## Integrações Externas

- Contratos automatizados adicionados em `arpia_hunt/tests/test_integrations.py`, cobrindo NVD, Vulners e searchsploit (erros, timeouts e parsing de JSON).
- Fixtures reutilizam `nvd_cve.json`, `vulners_cve.json` e `exploitdb_results.json`; mantê-las atualizadas conforme novos cenários emerjam em staging.
- Documentar variáveis de ambiente (`ARPIA_HUNT_NVD_API_KEY`, `ARPIA_HUNT_VULNERS_API_KEY`, `ARPIA_HUNT_SEARCHSPLOIT_PATH`, timeouts) no manual operacional e validar presença no pipeline de deploy.

## Entregáveis da Fase 4 (Atualização)

- Migrations e campos opcionais disponíveis; serializers e APIs expõem `confidence_note`, `playbook_slug` e filtros combinados.
- Testes de contrato para integrações e endpoints REST centralizados nos módulos `tests/api/` e `arpia_hunt/tests/`.
- Especificação OpenAPI publicada em `docs/api/hunt-openapi.yaml`, alinhada com filtros e parâmetros atuais.
