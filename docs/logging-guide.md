# Guia de Integração de Logs Centralizados

Este documento descreve o contrato padronizado para que as aplicações do ARPIA enviem
logs para o app `arpia_log`. O objetivo é permitir correlação entre módulos, geração de
relatórios e consultas uniformes.

## Visão geral

- **Ponto central**: modelos e APIs do app `arpia_log`.
- **Formato**: payload JSON versionado (`version`), com campos obrigatórios e opcionais.
- **Canais suportados**: serviço Python (`log_event`) e API REST (`POST /logs/api/ingest/`).
- **Autenticação**: token opcional definido via `ARPIA_LOG_INGEST_TOKEN` (Authorization: `Token <valor>`). Se o token não estiver configurado, apenas sessões autenticadas poderão enviar dados.

## Estrutura do modelo `LogEntry`

| Campo               | Tipo                 | Obrigatório | Descrição |
|---------------------|----------------------|-------------|-----------|
| `version`           | inteiro              | Não (default = 1) | Versão do contrato de log. |
| `timestamp`         | datetime (UTC)       | Não (default: atual) | Momento do evento. |
| `source_app`        | string (<=64)        | Sim         | Identificador do app emissor (`arpia_core`, `arpia_scan` etc.). |
| `component`         | string (<=128)       | Não         | Nome de módulo/classe para granularidade. |
| `event_type`        | string (<=128)       | Sim         | Nome do evento (e.g. `PROJECT_CREATED`). |
| `severity`          | enum (`DEBUG`, `INFO`, `NOTICE`, `WARN`, `ERROR`, `CRITICAL`) | Não (default = `INFO`) | Severidade do evento. |
| `message`           | string (<=512)       | Sim         | Breve descrição. |
| `details`           | JSON                 | Não         | Dados adicionais pujantes (resultado de scan, stacktrace). |
| `context`           | JSON                 | Não         | Estrutura livre para enriquecer dashboards (ex.: `{"actor": {...}}`). |
| `correlation`       | JSON                 | Não         | Chaves para correlação (IDs de projeto, ativo, usuário). |
| `tags`              | lista de strings     | Não         | Tags livres normalizadas. |
| `project_ref`       | string               | Gerado      | Referência resolvida automaticamente a partir de `correlation` quando possível. |
| `asset_ref`         | string               | Gerado      | Referência a ativo/host quando informada. |
| `user_ref`          | string               | Gerado      | Referência a usuário/ator. |
| `ingestion_channel` | enum (`internal`, `api`, `batch`) | Não | Canal utilizado para ingestão. |
| `ingested_at`       | datetime             | Automático | Momento do armazenamento. |

> Observação: `context.actor` e `correlation.user_id` são preenchidos automaticamente
quando `log_event` é chamado com `request` autenticado.

## Serviço Python (`log_event`)

Uso interno nos apps Django:

```python
from arpia_log.services import log_event

def registrar_criacao_projeto(project, actor):
    log_event(
        source_app="arpia_core",
        event_type="PROJECT_CREATED",
        severity="INFO",
        message=f"Projeto {project.name} criado",
        context={
            "project": {"id": project.id, "name": project.name},
            "actor": {"id": actor.id, "username": actor.username},
        },
        correlation={"project_id": project.id},
        tags=["project", "create"],
    )
```

Parâmetros relevantes:

- `source_app`, `event_type`, `message`: obrigatórios.
- `severity`: padrão `INFO`; valores aceitos em `LogEntry.Severity`.
- `timestamp`: aceita `datetime` ou string ISO; default `timezone.now()`.
- `context`/`correlation`: dicionários opcionais.
- `tags`: lista de strings (deduplicadas automaticamente).
- `request`: opcional para enriquecer com ator autenticado.
- `channel`: um de `LogEntry.Channel` (default `internal`).

## API REST

### Ingestão simples

```
POST /logs/api/ingest/
Authorization: Token <ARPIA_LOG_INGEST_TOKEN>
Content-Type: application/json

{
  "version": 1,
  "source_app": "arpia_scan",
  "component": "scans.nmap",
  "event_type": "SCAN_FINISHED",
  "severity": "NOTICE",
  "message": "Execução do perfil Fast completa",
  "timestamp": "2025-10-13T10:22:00Z",
  "context": {
    "scan_id": 501,
    "duration_seconds": 42
  },
  "correlation": {
    "project_id": 42,
    "asset_id": "10.0.0.5"
  },
  "tags": ["scan", "nmap"]
}
```

Resposta (`201 Created`): payload salvo com campos derivados (`project_ref`, `ingested_at`, etc.).

### Ingestão em lote

```
POST /logs/api/bulk/
Authorization: Token <ARPIA_LOG_INGEST_TOKEN>
Content-Type: application/json

[
  { ... evento 1 ... },
  { ... evento 2 ... }
]
```

- Limite: 500 itens por requisição.
- Retorno `207 Multi-Status` quando houver mistura de sucessos e falhas.
- Cada erro inclui índice do item original.

### Consultas e estatísticas

- `GET /logs/api/` — lista paginada com filtros (`q`, `level`, `source`, `project`, `from`, `to`).
- `GET /logs/api/stats/` — agregados (contagem por severidade, origem, top eventos) e timeline
horária das últimas `hours` horas (padrão: 24). Requer usuário autenticado ou token.

## Autenticação

Configurar o token em `.env`:

```
ARPIA_LOG_INGEST_TOKEN=supersecreto123
```

Headers aceitos: `Authorization: Token supersecreto123`.
Se o token não for definido, apenas sessões autenticadas via Django poderão realizar ingestão.

## Boas práticas

1. **Enumeração de eventos**: registre em cada app uma lista curta (`EVENT_TYPES`) para facilitar
   auditoria e busca.
2. **Consistência**: normalize `source_app` (`arpia_core`, `arpia_vuln`, etc.).
3. **IDs externos**: sempre que possível, informe `correlation.project_id`, `correlation.asset_id`,
   `correlation.user_id` para viabilizar relatórios.
4. **Dados sensíveis**: evite inserir credenciais em `details`. Prefira referências ou hashes.
5. **Testes**: utilize `log_event` em ambientes de desenvolvimento e adicione asserts nas suítes
   das apps integradas.

## Fluxo de integração sugerido

1. Atualize o app para importar `log_event` e registrar eventos-chave.
2. Configure o token (quando necessário) e valide ingestão com `POST /logs/api/ingest/`.
3. Verifique dados em `/logs/` e na API `/logs/api/`.
4. Ajuste relatórios/dashboards para consumir agregados de `/logs/api/stats/`.

## Próximos passos

- Implementar políticas de retenção (management command `prune_logs`).
- Expandir `event_type` com enum compartilhado entre os apps.
- Integrar geração de relatórios ao novo modelo de logs.
