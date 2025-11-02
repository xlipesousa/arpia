# Arpia Hunt — Fase 2 · Enriquecimento Externo

## Objetivos
- Enriquecer `HuntFinding` com metadados da NVD (CVSS, CWE, referências oficiais) com respeito a rate-limit.
- Correlacionar exploits públicos (Vulners, Exploit-DB/searchsploit) para priorização de riscos.
- Persistir dados normalizados em cache local reutilizável pelos módulos Blue/Red.
- Centralizar auditoria das execuções de enriquecimento via `arpia_log`.

## Componentes

### Modelos
- `HuntEnrichment`: guarda o payload de cada fonte (`nvd`, `vulners`, `exploitdb`), status da coleta e janela de expiração.
- `HuntFindingEnrichment`: vincula enrichments a findings, indicando em qual perfil (Blue, Red, Exploit) ele é usado.
- `HuntFindingSnapshot`: versiona os perfis Blue/Red gerados para cada finding.

### Serviços
- `arpia_hunt.enrichment.enrich_cve(cve_id, ...)`
  - Respeita a flag `ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT` (default: desativado).
  - Usa TTL configurável (`ARPIA_HUNT_ENRICHMENT_TTL_HOURS`, default 12h).
  - Integrações:
    - **NVD** (`ARPIA_HUNT_NVD_URL`, `ARPIA_HUNT_NVD_API_KEY` ou `NVD_API_KEY`).
    - **Vulners** (`ARPIA_HUNT_VULNERS_URL`, `ARPIA_HUNT_VULNERS_API_KEY` ou `VULNERS_API_KEY`).
    - **Searchsploit** (`ARPIA_HUNT_SEARCHSPLOIT_PATH`).
  - Emite eventos no `arpia_log` em cada sucesso, erro ou operação ignorada.
- `arpia_hunt.enrichment.enrich_finding(finding, ...)` realiza o enriquecimento completo e atualiza os perfis Blue/Red.
- `management command` `python manage.py hunt_enrich` roda lote de findings (com filtros `--project`, `--limit`, `--force`, `--remote`).

### Logs centralizados
- Eventos `hunt.enrichment.*` e `hunt.sync.*` são gravados via `arpia_hunt.log_events.emit_hunt_log`.
- Painel Hunt agora apresenta os últimos registros provenientes do `arpia_log`.

## Execução
1. Ative o enrichment remoto (`export ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT=1`).
2. Configure credenciais (NVD / Vulners) conforme necessário.
3. Execute `python manage.py hunt_enrich --limit 20` para gerar perfis iniciais (use `--dry-run` para testar a seleção).
4. Consulte `templates/hunt/dashboard.html` (rota `/hunt/`) para Blue/Red insights e `GET /hunt/api/findings/` para consumir os metadados via API.

### Agendamento sugerido

Adicione ao cron (exemplo Ubuntu) — ou utilize o comando `python manage.py hunt_schedule --install` para gerar/instalar automaticamente:

```
*/30 * * * * /home/kali/arpia/.venv/bin/python /home/kali/arpia/manage.py hunt_sync --no-log
0 * * * * /home/kali/arpia/.venv/bin/python /home/kali/arpia/manage.py hunt_enrich --limit 100
```

Ou crie tarefas Celery chamando `arpia_hunt.enrichment.enrich_finding` em lote.

Eventos de cada execução ficam disponíveis no `arpia_log` (`hunt.enrichment.batch`, `hunt.profile.updated`).

## Próximos passos
- Expandir heurísticas ATT&CK para os perfis.
- Preparar testes de contrato com fixtures de respostas externas.
- Conectar recomendações Blue/Red ao módulo de relatórios.
