# Integracoes do Arpia Hunt

Este guia resume como configurar e testar as integracoes usadas pelo pipeline de enriquecimento do Hunt e pela importacao do catalogo MITRE ATT&CK.

## Enriquecimento remoto (Fase 2)

- **Flag principal**: defina `ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT=1` para permitir chamadas externas. Sem esse valor, registros sao criados com status `skipped` e nenhum request e enviado.
- **TTL dos registros**: ajuste com `ARPIA_HUNT_ENRICHMENT_TTL_HOURS` (default `12`). Valores invalidos sao ignorados e o TTL volta para 12 horas.
- **NVD**
  - `ARPIA_HUNT_NVD_URL` (default `https://services.nvd.nist.gov/rest/json/cves/2.0`).
  - `ARPIA_HUNT_NVD_API_KEY` ou `NVD_API_KEY` para autenticação opcional.
  - `ARPIA_HUNT_NVD_TIMEOUT` em segundos (aceita float, default `12`).
- **Vulners**
  - `ARPIA_HUNT_VULNERS_URL` (default `https://vulners.com/api/v3/search/id/`).
  - `ARPIA_HUNT_VULNERS_API_KEY` ou `VULNERS_API_KEY` para o header `X-ApiKey`.
  - `ARPIA_HUNT_VULNERS_TIMEOUT` em segundos (default `10`).
- **ExploitDB/searchsploit**
  - `ARPIA_HUNT_SEARCHSPLOIT_PATH` (default `searchsploit`).
  - `ARPIA_HUNT_SEARCHSPLOIT_TIMEOUT` em segundos (default `15`).
  - Erros de binario ausente ou timeouts geram `IntegrationError` com `retriable=False`.

### Fixtures e testes

- Arquivos de fixture usados nos testes unitarios residem em `arpia_hunt/tests/fixtures/` (`nvd_cve.json`, `vulners_cve.json`, `exploitdb_results.json`, `heuristic_cases.json`, `attack_mapping.json`, `attack_catalog.json`).
- Os testes em `arpia_hunt/tests/test_integrations.py` validam parametros, headers e tratamento de erros das chamadas externas (NVD, Vulners, searchsploit), garantindo que os `IntegrationError` sejam levantados corretamente em cenarios de falha.
- Para mocks adicionais em integracoes novas, mantenha o padrao de utilizar `mock.patch` para `load_requests` (HTTP) ou `subprocess.run` (searchsploit).

## Catálogo ATT&CK e heurísticas (Fase 3)

- Execute `python manage.py import_attack_catalog` para carregar a fixture local (`arpia_hunt/fixtures/attack_catalog.json`). Use `--from-file <caminho>` para apontar outro JSON no formato de fixture do Django.
- Para consumir o dataset direto do MITRE utilizando pyattck, instale `pyattck>=4` e execute `python manage.py import_attack_catalog --pyattck --matrix enterprise` (ou `ics`/`mobile`, ou ainda `--matrix all` para importar as tres matrizes em uma unica passada). O comando normaliza automaticamente taticas/tecnicas e cria taticas sinteticas `ENT-UNASSIGNED`, `MOB-UNASSIGNED` ou `ICS-UNASSIGNED` quando o dataset nao informa uma tatica.
- As heuristicas CVE/CWE/keywords sao executadas por `sync_heuristic_mappings`. Os testes em `AttackHeuristicsTests` garantem que os vinculos sejam criados, atualizados e removidos conforme esperado.
- Recomendacoes automatizadas sao geradas por `sync_recommendations_for_finding`, que cria pares Blue/Red vinculando enriquecimentos NVD (Blue) e Vulners/ExploitDB (Red). O teste `test_sync_recommendations_removes_obsolete_entries` cobre a remocao de recomendacoes obsoletas.

## Checklist de validação

1. `python manage.py test arpia_hunt` — deve passar validando contratos de integracao, heuristicas e recomendacoes.
2. `python manage.py import_attack_catalog --pyattck --matrix enterprise` — apos os testes, confirma a ingestao via pyattck (quando a dependencia estiver disponivel).
3. Verificar logs no painel (`hunt.enrichment.*`) para confirmar que o pipeline registra sucessos, falhas e skips conforme as flags de ambiente.
