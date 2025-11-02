# Runbook Operacional — Hunt API

## Consultas críticas e índices

### Recomendações (filtros combinados)

- Consulta de referência:
  ```sql
  SELECT "arpia_hunt_huntrecommendation"."id", "arpia_hunt_huntrecommendation"."finding_id", "arpia_hunt_huntrecommendation"."technique_id",
         "arpia_hunt_huntrecommendation"."recommendation_type", "arpia_hunt_huntrecommendation"."title", "arpia_hunt_huntrecommendation"."summary",
         "arpia_hunt_huntrecommendation"."confidence", "arpia_hunt_huntrecommendation"."evidence", "arpia_hunt_huntrecommendation"."tags",
         "arpia_hunt_huntrecommendation"."generated_by", "arpia_hunt_huntrecommendation"."confidence_note",
         "arpia_hunt_huntrecommendation"."playbook_slug", "arpia_hunt_huntrecommendation"."source_enrichment_id",
         "arpia_hunt_huntrecommendation"."created_at", "arpia_hunt_huntrecommendation"."updated_at"
  FROM "arpia_hunt_huntrecommendation"
  INNER JOIN "arpia_hunt_huntfinding" ON ("arpia_hunt_huntrecommendation"."finding_id" = "arpia_hunt_huntfinding"."id")
  WHERE ("arpia_hunt_huntfinding"."project_id" IS NOT NULL
         AND "arpia_hunt_huntrecommendation"."technique_id" IS NOT NULL
         AND "arpia_hunt_huntrecommendation"."confidence" IN ('high','medium')
         AND "arpia_hunt_huntfinding"."project_id" IN (...)
         AND "arpia_hunt_huntrecommendation"."finding_id" IN (...)
         AND "arpia_hunt_huntrecommendation"."generated_by" IN ('automation','analyst')
         AND "arpia_hunt_huntrecommendation"."recommendation_type" IN ('blue','red')
         AND "arpia_hunt_huntrecommendation"."technique_id" IN (...))
  ORDER BY "arpia_hunt_huntrecommendation"."updated_at" DESC, "arpia_hunt_huntrecommendation"."created_at" DESC;
  ```
- `EXPLAIN QUERY PLAN` (SQLite 3.45):
  - `SEARCH arpia_hunt_huntfinding USING INDEX sqlite_autoindex_arpia_hunt_huntfinding_1 (id=?)`
  - `SEARCH arpia_hunt_huntrecommendation USING INDEX idx_hunt_rec_finding_type (finding_id=? AND recommendation_type=?)`
  - `USE TEMP B-TREE FOR ORDER BY`
- Interpretação: o índice parcial `idx_hunt_rec_finding_type` está sendo usado. O fallback para ordenação cria B-Tree temporário; caso o volume cresça, considerar índice em `(updated_at, created_at)` condicionado para `generated_by='automation'` (já mapeado na migration `idx_hunt_rec_auto_recent`).

### Findings (filtros combinados)

- Consulta de referência:
  ```sql
  SELECT DISTINCT "arpia_hunt_huntfinding"."id", "arpia_hunt_huntfinding"."project_id", "arpia_hunt_huntfinding"."vulnerability_id",
         "arpia_hunt_huntfinding"."vuln_session_id", "arpia_hunt_huntfinding"."scan_session_id", "arpia_hunt_huntfinding"."asset_id",
         "arpia_hunt_huntfinding"."host", "arpia_hunt_huntfinding"."service", "arpia_hunt_huntfinding"."port",
         "arpia_hunt_huntfinding"."protocol", "arpia_hunt_huntfinding"."cve", "arpia_hunt_huntfinding"."severity",
         "arpia_hunt_huntfinding"."cvss_score", "arpia_hunt_huntfinding"."cvss_vector", "arpia_hunt_huntfinding"."summary",
         "arpia_hunt_huntfinding"."context", "arpia_hunt_huntfinding"."tags", "arpia_hunt_huntfinding"."source_hash",
         "arpia_hunt_huntfinding"."is_active", "arpia_hunt_huntfinding"."detected_at", "arpia_hunt_huntfinding"."last_synced_at",
         "arpia_hunt_huntfinding"."blue_profile", "arpia_hunt_huntfinding"."red_profile", "arpia_hunt_huntfinding"."profile_version",
         "arpia_hunt_huntfinding"."last_profiled_at", "arpia_hunt_huntfinding"."state_version",
         "arpia_hunt_huntfinding"."last_state_snapshot_at", "arpia_hunt_huntfinding"."created_at",
         "arpia_hunt_huntfinding"."updated_at"
  FROM "arpia_hunt_huntfinding"
  INNER JOIN "arpia_hunt_huntrecommendation" ON ("arpia_hunt_huntfinding"."id" = "arpia_hunt_huntrecommendation"."finding_id")
  WHERE ("arpia_hunt_huntfinding"."project_id" IS NOT NULL
         AND "arpia_hunt_huntfinding"."project_id" IN (...)
         AND "arpia_hunt_huntrecommendation"."confidence" IN ('high','medium')
         AND "arpia_hunt_huntrecommendation"."recommendation_type" IN ('blue','red')
         AND "arpia_hunt_huntrecommendation"."technique_id" IN (...))
  ORDER BY "arpia_hunt_huntfinding"."last_profiled_at" DESC,
           "arpia_hunt_huntfinding"."detected_at" DESC,
           "arpia_hunt_huntfinding"."created_at" DESC;
  ```
- `EXPLAIN QUERY PLAN`:
  - `SEARCH arpia_hunt_huntrecommendation USING INDEX idx_hunt_rec_technique (technique_id=?)`
  - `SEARCH arpia_hunt_huntfinding USING INDEX sqlite_autoindex_arpia_hunt_huntfinding_1 (id=?)`
  - `USE TEMP B-TREE FOR DISTINCT`
  - `USE TEMP B-TREE FOR ORDER BY`
- Interpretação: filtros combo usam o índice `idx_hunt_rec_technique` e a PK de `HuntFinding`. Em cenários de dados grandes, avalie materializar tabela de apoio ou índice composto (`project_id`, `last_profiled_at`) para reduzir a B-Tree temporária.

## Procedimento de verificação

1. Garantir dataset mínimo (finding + recomendações Blue/Red) executando o snippet Python descrito acima via `python manage.py shell` em ambientes vazios.
2. Rodar novamente o trecho `EXPLAIN QUERY PLAN` (mesmo snippet) e arquivar a saída no pipeline de observabilidade.
3. Registrar novas observações neste runbook sempre que índices forem alterados ou quando o banco migrar para outro back-end.

## Métricas a monitorar

- `hunt.api.latency` (emitida no `HuntBetaFeatureMixin`).
- Contagem de `IntegrationError` nas integrações externas (NVD/Vulners/searchsploit).
- Tamanho do conjunto de recomendações por finding (`recommendation_total`) para antecipar necessidade de ajustes na paginação.
