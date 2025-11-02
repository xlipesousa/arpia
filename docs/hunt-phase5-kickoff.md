# Plano de Preparação — Fases 5 e 6

## Objetivos

- Alinhar escopo e dependências para automações/alertas (Fase 5) e rollout/qualidade (Fase 6).
- Garantir que o usuário Hunt (perfil híbrido Blue/Red) esteja alinhado com Engenharia e Observabilidade antes da liberação em staging.

## Workshop de Kick-off (Fase 5)

1. **Participantes**: usuários Hunt (perfil híbrido Blue/Red), Engenharia (Hunt), Observabilidade.
2. **Agenda sugerida (90 min)**:
   - Revisão rápida das entregas atuais (APIs, UI, OpenAPI, integrações).
   - Priorização das regras de alerta (CVSS, exploit público, criticidade do ativo, exposição externa).
   - Definição de canais de notificação (e-mail, webhook, integrações SIEM) e SLAs.
   - Mapeamento de playbooks ofensivos/defensivos que podem ser automatizados.
   - Atribuição de responsáveis e próximos passos.
3. **Pré-requisitos**:
   - Checklist de staging concluído.
   - Logs de testes (`arpia_hunt.tests`, `tests.api`) anexados ao runbook.
   - Relatório de métricas iniciais do deploy (24h) disponível.

## Ações Preparatórias

- [ ] Consolidar critérios de alerta propostos (baseline de CVSS, tags de exposição, heurísticas ATT&CK).
- [ ] Catalogar playbooks existentes (mitigações e simulações) e identificar lacunas para automação.
- [ ] Definir template para notificações (payload, contexto, links para dashboards, dados da API).

## Monitoramento Pós-Deploy (Fase 4 → Fase 5)

- Métricas prioritárias:
  - `hunt.api.latency`
  - `hunt.recommendations.db_time`
  - `hunt.api.error_rate`
- Responsáveis devem registrar observações durante as primeiras 24h após o deploy.
- Anexar export dos dashboards no runbook (`docs/hunt-runbook.md`).

## Roadmap Pós-Workshop

1. Implementar camada GraphQL após estabilização em staging (reutilizar filtros multi-valor e serializer detalhado).
2. Iniciar desenvolvimento das regras de priorização e notificações (Fase 5).
3. Elaborar checklist de rollout e segurança (Fase 6) incluindo plano de comunicação e treinamento.
