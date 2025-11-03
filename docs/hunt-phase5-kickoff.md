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

- [x] Consolidar critérios de alerta propostos (baseline de CVSS, tags de exposição, heurísticas ATT&CK).
- [ ] Catalogar playbooks existentes (mitigações e simulações) e identificar lacunas para automação.
- [x] Definir template para notificações (payload, contexto, links para dashboards, dados da API).

### Estado atual da automação

- Serviço `arpia_hunt.services.alerts` avalia thresholds operacionais:
   - Prioridade crítica: `cvss_score ≥ 9.0` e recomendações Red > 0.
   - Alerta imediato: recomendações geradas por automação com confiança `high`.
   - Revisão Blue: severidade ≥ `medium` com ≥2 recomendações Blue.
- Alertas persistem em `HuntAlert`, disparam logs via `arpia_log` e, se configurado, notificações por e-mail/webhook.
- Comando `python manage.py hunt_alerts [--finding UUID | --project UUID | --limit N]` permite reprocesso batch (agendamento sugerido via cron/Celery).
- Configuração de canais, destinatários e SLA em `settings.HUNT_ALERTS` (`HUNT_ALERT_*` no `.env`).

### SLA e canais

- `priority_critical`: SLA padrão 30 min — notifica Blue & Red, marcador `team:blue`, `team:red`.
- `automation_high`: SLA padrão 60 min — foco Red, integra playbooks ofensivos.
- `blue_review`: SLA padrão 240 min — acompanhamento de mitigação Blue.
- Webhook padrão publica evento `hunt.alert.<estado>` com payload JSON (finding, SLA, metadados). Ajustar `HUNT_ALERT_WEBHOOK_URL` para integrar SIEM ou orquestradores.

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
