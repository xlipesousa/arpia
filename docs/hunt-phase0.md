# ARPIA Hunt — Fase 0 (Planejamento & Setup)

Snapshot de referência: **"arpia_vul pronto"**

## Objetivos da fase

1. Consolidar contratos de dados entre `arpia_scan`, `arpia_vuln` e o futuro pipeline de Hunt.
2. Inventariar e validar acesso às fontes externas (NVD, Vulners, Exploit-DB/searchsploit, MITRE ATT&CK via pyattck).
3. Especificar como os perfis Blue-Team (protetores) e Red-Team (atacantes) irão consumir as informações geradas.
4. Definir estrutura básica do módulo Hunt (rotas, templates, autenticação) para suportar as próximas fases.

## Entregáveis

- Documento de arquitetura inicial (este arquivo) descrevendo integrações, taxonomias e próximos passos.
- Dashboard inicial em `/hunt/` com visão consolidada da fase e dos perfis-alvo.
- Registro da ferramenta padrão `searchsploit` no inventário de ferramentas do ARPIA (via `DEFAULT_TOOLS`).

## Fluxo de dados previsto

```
arpia_scan ─┐
            ├─┐ normalização → Hunt Ingestor
arpia_vuln ─┘ │
              ├─ Enriquecimento externo → NVD / Vulners / Searchsploit / MITRE ATT&CK
              └─ Perfis orientados (Blue/Red) → Dashboards, APIs, alertas
```

### Camadas planejadas

| Camada | Responsabilidade | Notas |
| --- | --- | --- |
| Ingestão | Coletar achados e contexto de projetos/ativos já existentes | Uso de ORM e APIs internas; suporte a incrementos. |
| Normalização | Garantir esquema unificado (host, serviço, CVE, CWE, evidências) | Preparar base para scoring e correlações. |
| Enriquecimento | Agregar dados externos (CVSS, exploits, ATT&CK) com cache e rate-limits | Implementar adapters por fonte. |
| Perfis | Organizar recomendações Blue-Team e caminhos Red-Team | Exportáveis para Pentest e relatórios. |

## Considerações de segurança

- Limitar exposição de PoCs/exploits a usuários autorizados.
- Armazenar chaves de API (Vulners) em settings seguros (env/secret manager).
- Monitorar consumo de APIs externas (NVD) para evitar bloqueio.

## Próximas fases

1. **Fase 1 – Ingestão & Normalização:** criar modelos `HuntFinding`, agendamentos e testes.
2. **Fase 2 – Enriquecimento externo:** adapters NVD/Vulners/Searchsploit com cache.
3. **Fase 3 – Correlação ATT&CK e perfis detalhados Blue/Red.**
4. **Fase 4+ – UI avançada, alertas, integrações Pentest.**

---
Documento atualizado em 2025-10-31.
