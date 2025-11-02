# Design Detalhado — Hunt Finding Detail (Fase 4)

## Objetivo

Definir a estrutura inicial da página `templates/hunt/findings/detail.html`, servindo como blueprint para a squad de UI refinar estilos e interações, mantendo compatibilidade com os componentes `{% include %}` criados na Fase 3.

## Expectativa de Contexto (View)

- `finding`: instância `HuntFinding` com `project`, `vulnerability`, `blue_profile`, `red_profile` prefetchados.
- `blue_profile`, `red_profile`: dicionários serializados (resultado de `derive_profiles`).
- `blue_recommendations`, `red_recommendations`: queryset filtrado por tipo e ordenado por recência/confiança.
- `blue_heuristics`, `red_heuristics`: lista de `CveAttackTechnique` (fonte heurística) usada para os chips.
- `enrichments`: queryset de `HuntEnrichment` relacionado ao finding (ordenado por `updated_at` desc).
- `recent_logs`: últimos eventos do `emit_hunt_log` relacionados ao finding (filtrados por `details.finding_id`).
- `project_url`, `vulnerability_url`: links resolvidos para navegação rápida ao projeto e sessão de vulnerabilidade.
- `profiles_api_url`, `recommendations_api_url`: endpoints REST exibidos na seção de ações rápidas.

## Layout Resumido

1. **Cabeçalho** — título do finding, projeto, CVE, link de retorno para o projeto.
2. **Resumo do finding** — severidade, host, porta, CVSS e resumo textual.
3. **Tabs Blue/Red** — reutilizam `hunt/components/heuristic_chips.html` e `hunt/components/recommendation_list.html`.
4. **Contexto adicional** — listas de enriquecimentos recentes e logs operacionais.
5. **Ações rápidas** — atalhos para módulos relacionados (scan, vuln, APIs).
6. **Breadcrumbs** — navegação contextual de volta ao dashboard/projeto.

## Estrutura de Estilos

- Estilos dedicados estão centralizados em `static/css/hunt-detail.css`, carregados via bloco `{% block extra_css %}`.
- Tokens de cor e espaçamento são provisórios; substituir quando o hand-off oficial fornecer valores finais.
- O JavaScript responsável pelas tabs (`extra_js`) permanece vanilla e isolado para facilitar eventual migração para componentes do Design System.
- O arquivo CSS já define tokens base (`--hunt-surface`, `--hunt-blue`, `--hunt-panel-radius`, etc.) que devem ser mapeados para os futuros design tokens assim que o hand-off entregar os nomes definitivos.
- Próxima iteração deverá apenas trocar os valores desses tokens ou mover as variáveis para o pacote global do Design System, evitando alterar seletores.

### Checklist de hand-off quando tokens finais chegarem

1. Receber a tabela de cores/spacing oficial da squad de UI (preferencialmente em formato JSON ou Figma Tokens).
2. Atualizar apenas os valores das variáveis declaradas no `:root` de `static/css/hunt-detail.css`; não mexer em seletores ou layouts.
3. Validar visualmente a página `templates/hunt/findings/detail.html` em breakpoints desktop e mobile (≤768px).
4. Registrar no PR links para o hand-off (mock final + tabela de tokens) e, se necessário, abrir follow-up para propagar os mesmos tokens a outros módulos (`hunt-dashboard`, etc.).

## Próximos Ajustes de Design

- Validar espaçamento, tipografia e esquema de cores quando os assets oficiais forem recebidos.
- Integrar gráficos/estatísticas (ex.: distribuição de confiança) utilizando componentes do Design System.
- Definir comportamento responsivo nas tabs (stack horizontal → vertical em telas pequenas).

## Hand-off para UI

Quando os wireframes estiverem disponíveis:

1. Atualizar `docs/ui/hunt-blue-red-wireframes.png` com a versão final.
2. Complementar este documento com tokens de design (cores, spacing) e guidelines de interação.
3. Criar checklist de QA visual comparando template vs. mock.
