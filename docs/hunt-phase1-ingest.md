# ARPIA Hunt — Fase 1 (Ingestão & Normalização)

## Objetivo

Estabelecer a sincronização automática entre os módulos existentes (`arpia_scan`, `arpia_vuln`) e o repositório interno do Hunt, garantindo que cada achado de vulnerabilidade possua uma representação normalizada para uso pelos perfis Blue-Team e Red-Team.

## Componentes implementados

- **Modelos**
  - `HuntFinding`: espelha as principais informações da vulnerabilidade (host, porta, CVE, severidade, contexto) com metadados para correlação futura.
  - `HuntFindingState`: versiona a camada de ingestão (hash de origem, payload normalizado) para auditoria e diff rápido.
  - `HuntSyncLog`: registra execuções de sincronização, facilitando auditoria e troubleshooting.
- **Serviço de sincronização** `synchronize_findings` (`arpia_hunt.services`)
  - Consolida achados a partir de `VulnerabilityFinding` (módulo `arpia_vuln`).
  - Aplica hashing determinístico para identificar mudanças relevantes e evitar atualizações desnecessárias.
  - Normaliza tags e contexto (host, serviço, dados crus) para consumo posterior.
  - Gera snapshots de estado (`HuntFindingState`) sempre que um hash inédito é detectado.
- **Comando de management** `python manage.py hunt_sync`
  - Permite executar a ingestão manualmente, com filtros opcionais por projeto e limite de findings.
  - Registra `HuntSyncLog` por padrão.
- **Agendador auxiliar** `python manage.py hunt_schedule`
  - Exibe e (opcionalmente) instala entradas de cron para `hunt_sync` e `hunt_enrich` com um único comando.
  - Suporta export de variáveis via `ARPIA_HUNT_CRON_ENV` e emite eventos `hunt.scheduler.*` no `arpia_log`.
- **Dashboard `/hunt/`**
  - Exibe contadores de achados, histórico de sincronizações e mantém a visão estratégica da fase.

## Fluxo resumido

1. `VulnerabilityFinding` atualizado/ingresso.
2. `hunt_sync` (job/manual) consolida dados → `HuntFinding`.
3. `HuntFinding` alimenta dashboards e servirá de base para o enriquecimento (Fase 2).

## Próximos passos (Fase 2)

- Criar adapters para NVD, Vulners, Searchsploit e MITRE ATT&CK com caching.
- Expandir modelo para armazenar evidências de exploits públicos e recomendações táticas.
- Expor APIs para consumo externo (Blue/Red) com filtros por projeto, severidade e técnicas.

Atualizado em 2025-11-02.
