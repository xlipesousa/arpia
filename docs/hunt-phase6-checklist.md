# Checklist Fase 6 — Qualidade, Segurança e Rollout

## 1. Desempenho & Observabilidade

- [ ] Executar teste de carga nos endpoints REST/GraphQL do Hunt (baseline em staging).
- [ ] Validar métricas chave em produção (`hunt.api.latency`, `hunt.alerts.triggered`, uso de cache ORM).
- [ ] Confirmar alarmes no observability stack (latência, erros HTTP, fila de alertas).

## 2. Segurança & Conformidade

- [ ] Revisar armazenamento de secrets (`HUNT_ALERT_*`, tokens externos) e garantir rotação documentada.
- [ ] Rodar SAST/DAST atualizado para módulos Hunt (incluindo GraphQL) e registrar findings.
- [ ] Verificar hardening do banco (roles, índices sensíveis, criptografia em repouso se aplicável).

## 3. Migração & Dados

- [ ] Planejar migração inicial de HuntFindings/HuntAlerts para staging → produção (scripts, downtime, rollback).
- [ ] Documentar mapeamento de IDs (projects, findings, assets) e dependências externas.
- [ ] Definir estratégia de limpeza/arquivamento para alertas resolvidos.

## 4. Treinamento & Comunicação

- [ ] Atualizar runbook (`docs/hunt-runbook.md`) com novos fluxos de alerta e comandos (`hunt_alerts`).
- [ ] Elaborar guia rápido para usuário híbrido (Blue/Red) com SLAs e canais de notificação.
- [ ] Calendarizar sessões de treinamento + período de piloto controlado.

## 5. Go/No-Go

- [ ] Checklist preenchido e assinado por Engenharia, Segurança e Operações.
- [ ] Todos os SLAs monitorados (dashboards + alertas operacionais).
- [ ] Backup dos dados e plano de rollback testado.
