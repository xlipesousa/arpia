# Kickoff da Fase 3 — Mapeamento ATT&CK & Perfis

Snapshot de referência: `antes Kickoff da Fase 3` (registrado em 2025-11-02).

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

## Tarefas próximas

- Elaborar diagrama simplificado dos novos modelos e relações.
- Preparar proposta de migração inicial (`models` + `migrations`) para estrutura ATT&CK.
- Escrever testes de contrato para as heurísticas (fixtures contendo CVEs conhecidas ↔ técnicas).
- Atualizar documentação (`docs/`) com fluxo de dados ATT&CK e plano de rollout.

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
   - Índices: (`tactic`, `is_subtechnique`) e texto completo (via SearchVector) a considerar na Fase 4.

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

## Riscos e pontos de atenção

- Possível aumento de tempo de deploy e memória ao carregar datasets ATT&CK completos.
- Necessidade de alinhar licenciamento MITRE ATT&CK com políticas do projeto.
- Garantir que heurísticas sejam configuráveis e auditáveis (logs, rationale).

---
Este documento será atualizado conforme o trabalho avança na Fase 3.
