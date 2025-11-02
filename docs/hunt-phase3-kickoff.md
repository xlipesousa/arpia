# Kickoff da Fase 3 — Mapeamento ATT&CK & Perfis

Snapshot de referência: `antes Kickoff da Fase 3` (registrado em 2025-11-02).

## Atualizações recentes (2025-11-02)

- Comando `python manage.py import_attack_catalog --pyattck --matrix all` consolida matrizes enterprise/ics/mobile utilizando merge automático (log: 40 táticas, 1018 técnicas importadas).
- Fixtures/mocks para NVD, Vulners e searchsploit garantem contratos de integração cobertos por testes.
- Dashboard Hunt passou a consumir componentes reutilizáveis para abas Blue/Red alimentados por dados reais do pipeline.
- Documentação de modelagem (`docs/hunt-phase3-modelagem.md`) registra o diagrama de entidades e relacionamentos ATT&CK ↔ recomendações.
- Template inicial `templates/hunt/findings/detail.html` criado com tabs Blue/Red reutilizando componentes, servindo de base para Fase 4.

## Objetivos imediatos

1. **Integração de biblioteca ATT&CK**
   - Avaliar `pyattck` e `mitreattack-python` quanto a cobertura de técnicas, tamanho de dados e licenciamento.
   - Definir estratégia de carregamento (local cache vs. download dinâmico) alinhada às limitações de produção.
2. **Modelagem de dados**
   - Especificar as classes `HuntRecommendation` (blue/red) e entidades pivô `CveAttackTechnique`.
   - Mapear relacionamentos com `HuntFinding`, `HuntEnrichment` e futuros insights ATT&CK.
3. **Heurísticas iniciais**
   - Elaborar regras baseada em CVE/CWE/keywords para vincular técnicas ATT&CK.
   - Identificar fontes de dados existentes (NVD payload, Vulners) que podem alimentar as heurísticas.

## Plano de exploração técnica

- **Inventário de dados atuais**: revisar campos dos modelos `HuntFinding`, `HuntEnrichment` e perfis gerados para entender quais atributos já podem alimentar heurísticas.
- **Dependências externas**: validar impacto de adicionar `pyattck` (tamanho de pacote, atualização de dados MITRE) e definir versão alvo.
- **Estratégia de cache**: decidir se armazenaremos o dataset ATT&CK em banco (tabelas dedicadas) ou se uma camada em disco/JSON é suficiente para Fase 3.
- **População inicial do catálogo**: validar processo com fixture `arpia_hunt/fixtures/attack_catalog.json` (carregada via `python manage.py loaddata`). Gestão de pipeline final decidirá entre fixture versionada ou comando que consome `pyattck` para gerar/atualizar o catálogo.
- **Ferramenta de importação**: o comando `python manage.py import_attack_catalog` importa a fixture local (`attack_catalog.json`) por padrão e aceita os parâmetros `--from-file` (para apontar outro JSON) ou `--pyattck` (carregar direto da biblioteca, quando disponível).

## Avaliação de Bibliotecas ATT&CK

- **pyattck**: aprovado como fonte principal. Possui licença MIT compatível, inclui cache local por versão e expõe matrizes enterprise/ics/mobile com metadados suficientes para heurísticas. O tempo de importação ficou em ~18s com warm cache.
- **mitreattack-python**: mantido como fallback. Documentação mais granular para relacionamentos, porém sem cache embutido. Optamos por não empacotá-lo por padrão para evitar duplicidade de dependências.
- **Decisão**: `pyattck` será instalado no ambiente padrão; `mitreattack-python` permanece documentado apenas para cenários onde seja necessário comparar UUIDs internos ou obter campos não expostos pelo `pyattck`.

## Plano de Enriquecimento Incremental

- **Delta contínuo**: `enrich_finding` consulta `HuntEnrichment` mais recente e só dispara `sync_recommendations_for_finding` quando `finding.state_version` aumenta ou quando o catálogo ATT&CK muda (`attack_catalog_version` registrado no cache).
- **Reprocessamento programado**: job `hunt_enrich_diff` executa diariamente e revalida apenas findings com CVEs alteradas nas últimas 24h (dados provenientes do NVD delta feed armazenado em `tmp/nvd-diff.json`).
- **Auditoria**: logs estruturados (`project_logging.get_logger("hunt.enrichment")`) gravam decisões de atualização, incluindo justificativa quando uma heurística é removida ou rebaixada.
- **Fallback manual**: operador pode acionar `python manage.py hunt_reprocess --finding <uuid>` para forçar um enriquecimento completo, útil após atualizações fora de janela.

## Tarefas próximas

- Planejar migrações incrementais para eventuais campos extras (subtécnicas, matrizes adicionais) e registrar backlog de busca full-text para quando PostgreSQL estiver disponível.
- Validar recomendações automáticas com casos reais (importação do catálogo completo + findings do ambiente de staging).
- Atualizar documentação (`docs/`) com fluxo de dados ATT&CK e plano de rollout para APIs/UI.
- Preparar protótipos finais das abas Blue/Red (wireframes) e alinhar padrão com a squad de UI antes da Fase 4.
- Conectar nova view de detalhe de finding e definir contratos de contexto para consumo dos componentes Blue/Red.

## Desenho dos novos modelos

### Catálogo ATT&CK

- `AttackTactic`
   - `id`: chave natural (ex.: `TA0001`).
   - `name`: nome amigável da tática.
   - `short_description`: resumo para UI/tooltips.
   - `matrix`: enum/text (`enterprise`, `ics`, `mobile`).
   - `order`: pequeno inteiro para preservar a ordem oficial da matriz.
   - Índices: (`matrix`, `order`).

- `AttackTechnique`
   - `id`: chave natural (ex.: `T1059`).
   - `name`: título oficial da técnica/subtécnica.
   - `description`: texto completo (Markdown) carregado do dataset.
   - `is_subtechnique`: booleano.
   - `parent`: FK opcional para `AttackTechnique` (quando `is_subtechnique=True`).
   - `tactic`: FK para `AttackTactic` (principal tática associada).
   - `platforms`: JSONField (lista de sistemas).
   - `datasources`: JSONField (lista de data sources do ATT&CK).
   - `external_references`: JSONField (URLs, IDs externos, CAPEC, CWE, etc.).
   - `version`: string para acompanhar updates de conteúdo.
   - Índices: (`tactic`, `is_subtechnique`). Busca full-text ficará em backlog dependendo da adoção futura de PostgreSQL.

### Pivôs ATT&CK ↔ CVE

- `CveAttackTechnique`
   - `id`: UUID.
   - `cve`: string normalizada (uppercase).
   - `technique`: FK para `AttackTechnique`.
   - `source`: enum (`heuristic`, `dataset`, `manual`).
   - `confidence`: choices (`low`, `medium`, `high`).
   - `rationale`: texto curto explicando a associação (ex.: trecho das heurísticas, referência NVD).
   - `created_at`/`updated_at`.
   - Restrições: `unique_together = ("cve", "technique", "source")`.
   - Índice adicional em (`cve`, `confidence`) para buscas por CVE.

### Recomendações Hunt

- `HuntRecommendation`
   - `id`: UUID.
   - `finding`: FK para `HuntFinding` (nullable enquanto recomendação é construída).
   - `technique`: FK opcional para `AttackTechnique` (suporta recomendações genéricas).
   - `recommendation_type`: enum (`blue`, `red`).
   - `title`: curta para UI.
   - `summary`: texto com ações sugeridas (blue) ou oportunidades (red).
   - `confidence`: choices alinhadas ao pivô (propagar heurística).
   - `evidence`: JSONField (fragmentos de enrichment, links).
   - `tags`: Array/JSON para filtros (ex.: `containment`, `detection`).
   - `generated_by`: enum (`automation`, `analyst`, `import`).
   - `source_enrichment`: FK opcional para `HuntEnrichment` (auditar origem).
   - `created_at`/`updated_at`.
   - Índices: (`finding`, `recommendation_type`), `technique` isolado para listar por ATT&CK.

### Relações previstas

- `HuntFinding` ↔ `HuntRecommendation`: 1:N; recomendações são revisadas/atualizadas a cada execução do pipeline.
- `CveAttackTechnique` alimenta heurísticas para gerar `HuntRecommendation` (blue/red) e atualizar perfis existentes.
- Perfis `blue_profile`/`red_profile` podem incluir referências a recomendações geradas (ID + resumo) para rastreabilidade.

### Heurísticas iniciais implementadas

- `python manage.py import_attack_catalog` + `sync_recommendations_for_finding` sincronizam táticas/técnicas e criam recomendações automáticas (Blue: mitigar, Red: simular) para cada `CveAttackTechnique` do CVE associado ao finding.
- `sync_heuristic_mappings` executa heurísticas (keywords + CWE) antes de gerar recomendações, garantindo que o pivô `CveAttackTechnique` esteja sempre alinhado ao conteúdo mais recente de enriquecimento.
- Recomendações automáticas são atualizadas/excluídas a cada nova execução de `enrich_finding`, garantindo aderência ao catálogo vigente.

### Cobertura de heurísticas (atualizado em 2025-11-02)

- **Regras por keywords**: combinações como `"remote code execution" + "public"` (→ `T1190` com confiança alta), menções a "command execution" e "privilege escalation" (→ `T1059`, `T1548` com confiança média).
- **Regras por CWE**: mapeamentos de `CWE-79/89/352` (injeções web) para `T1190` com confiança média; `CWE-94/119` (execução arbitrária/estouro) para `T1203`.
- **Fixtures de validação**: `arpia_hunt/tests/fixtures/heuristic_cases.json` mantém exemplos canônicos de CVEs e respectivas expectativas para testes automatizados.
- **Resultados**: logs via `logger` registram vínculos criados e limpezas; testes (`AttackHeuristicsTests`) cobrem criação, atualização e remoção de vínculos heurísticos.

### Fluxo de sincronização ATT&CK

1. `import_attack_catalog --pyattck --matrix <...>` importa matrizes enterprise/mobile/ics. Técnicas mobile sem tática oficial são vinculadas à tática sintética `MOB-UNASSIGNED`.
2. `enrich_finding` baixa/atualiza NVD, Vulners e searchsploit; na sequência executa `sync_heuristic_mappings`, atualiza perfis (`derive_profiles`) e consolida recomendações automatizadas.
3. `sync_recommendations_for_finding` reaproveita enriquecimentos recentes (NVD → Blue, Vulners/searchsploit → Red) e mantém `HuntRecommendation` consistente com o catálogo e heurísticas.

### Integrações externas — contratos e configuração

- Serviços foram modularizados em `arpia_hunt/integrations/{nvd_service,vulners_service,exploitdb_service}.py` com testes (`IntegrationContractTests`) que validam cabeçalhos, parâmetros, timeouts e tratamento de erros.
- Variáveis de ambiente suportadas:
   - `ARPIA_HUNT_NVD_URL`, `ARPIA_HUNT_NVD_API_KEY`, `ARPIA_HUNT_NVD_TIMEOUT` (fallback em `NVD_API_KEY`).
   - `ARPIA_HUNT_VULNERS_URL`, `ARPIA_HUNT_VULNERS_API_KEY`, `ARPIA_HUNT_VULNERS_TIMEOUT` (fallback em `VULNERS_API_KEY`).
   - `ARPIA_HUNT_SEARCHSPLOIT_PATH`, `ARPIA_HUNT_SEARCHSPLOIT_TIMEOUT` para execução local do searchsploit.
- Em ambientes de testes os contratos utilizam `mock.patch.dict` e stubs (`requests`, `subprocess`) evitando chamadas externas.

### Planejamento inicial da Fase 4 (APIs/UI)

- **Endpoints REST** (draft):
   - `GET /api/hunt/findings/<uuid>/profiles` → retorna perfis Blue/Red, enriquecimentos vinculados e heurísticas aplicadas.
   - `GET /api/hunt/recommendations` com filtros por `project`, `technique`, `confidence`.
   - `GET /api/hunt/recommendations/<uuid>/` → payload detalhado com contexto do finding, perfis atuais e heurísticas correlatas.
   - `GET /api/hunt/catalog/techniques` com suporte a busca textual e facetas por tática/matriz.
- **Views/Templates**: criar páginas `templates/hunt/findings/detail.html` (abas Blue/Red) e `templates/hunt/recommendations/list.html` com componentes reutilizáveis para listas de técnicas e recomendações.
- **Índices e busca**: registrar backlog de busca textual (depende de PostgreSQL) e manter índice composto (`cve`, `source`) em `CveAttackTechnique` para acelerar filtros na API.
- **Extensões futuras**: considerar endpoint de export (`/reports/hunt/<project>.pdf`) e dashboards combinando métricas de severidade × técnicas ATT&CK.

#### Backlog priorizado (Fase 4)

1. **API pública**
   - Contratos OpenAPI para findings/profiles/recommendations com exemplos reais (fixtures → `api/tests/fixtures`).
   - Paginação consistente (cursor) e filtros combinados (`technique`, `confidence`, `project`).
   - Serializer dedicado para heurísticas aplicadas (`applied_heuristics`) expondo confiança e rationale.
2. **Camada de serviço**
   - Adaptar `derive_profiles` e `sync_recommendations_for_finding` para retornarem DTOs reutilizáveis no serializer.
   - Otimizar queries (prefetch + aggregation) para evitar N+1 na listagem de recomendações.
   - Feature flag `ARPIA_HUNT_API_BETA` para liberar endpoints gradualmente.
3. **UI/UX**
   - Wireframes para abas Blue/Red (Figma → exportar preview estático em `docs/ui/`).
   - Componentes reutilizáveis (`templates/hunt/components/`) para cards ATT&CK, com cores alinhadas a guidelines existentes.
   - Interações assíncronas (HTMX/Alpine) para atualizar recomendações sem reload completo.
4. **Integração e QA**
   - Testes de contrato (`tests/api/test_hunt_endpoints.py`) garantindo compatibilidade com consumidores externos.
   - Smoke tests UI (`tests/ui/test_hunt_flows.py`) cobrindo navegação principal.
   - Monitoramento inicial com métricas `hunt.api.latency` e `hunt.ui.render_time` via `project_logging`.

#### Roteiro incremental

- **Sprint 1**: CRUD read-only (API + serializers) e protótipo UI estático para detail view do finding.
- **Sprint 2**: Recomendações interativas, filtros avançados e testes de contrato automatizados.
- **Sprint 3**: Dashboards iniciais + export PDF, ajustes de performance e telemetria.

#### Dependências & riscos

- Alinhar com squad de UI para padrão de componentes (Design System ainda em revisão).
- Validar impacto de índices extras na replicação do banco antes do deploy.
- Confirmar política de autenticação (token vs session) com equipe de plataforma para expor API pública.

## Riscos e pontos de atenção

- Possível aumento de tempo de deploy e memória ao carregar datasets ATT&CK completos.
- Necessidade de alinhar licenciamento MITRE ATT&CK com políticas do projeto.
- Garantir que heurísticas sejam configuráveis e auditáveis (logs, rationale).

---
Este documento será atualizado conforme o trabalho avança na Fase 3.
