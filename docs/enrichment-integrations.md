# Enrichment Integrations

This document describes how ARPIA Hunt talks to external enrichment services (NVD, Vulners, Exploit DB/searchsploit), which settings control those calls, and what errors the pipeline can surface.

## Remote enrichment toggle

- `ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT`: enables external calls when set to `1`, `true`, `yes`, or `on`. Default is disabled.
- `ARPIA_HUNT_ENRICHMENT_TTL_HOURS`: number of hours a fetched payload stays fresh. Defaults to `12`. Values lower than `1` are coerced to `1`.

When remote enrichment is disabled new `HuntEnrichment` entries are created with status `skipped` and an explanatory message.

## NVD service

The helper `arpia_hunt.integrations.nvd_service.fetch_cve` queries the NVD REST API.

| Setting | Default | Notes |
| --- | --- | --- |
| `ARPIA_HUNT_NVD_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Override to point at a mirror if required. |
| `ARPIA_HUNT_NVD_API_KEY` / `NVD_API_KEY` | unset | API key used for authenticated access and higher rate limits. |
| `ARPIA_HUNT_NVD_TIMEOUT` | `12` (seconds) | Non-numeric values fall back to `12`. |

Error handling:

- Missing `requests` library raises `IntegrationError` with `retriable=False`.
- Non-2xx responses or network issues raise `IntegrationError` with context in the message.

## Vulners service

The helper `arpia_hunt.integrations.vulners_service.fetch_cve` calls the Vulners Search API.

| Setting | Default | Notes |
| --- | --- | --- |
| `ARPIA_HUNT_VULNERS_URL` | `https://vulners.com/api/v3/search/id/` | Override for on-premise proxies. |
| `ARPIA_HUNT_VULNERS_API_KEY` / `VULNERS_API_KEY` | unset | Required for authenticated plans. Sent via `X-ApiKey`. |
| `ARPIA_HUNT_VULNERS_TIMEOUT` | `10` (seconds) | Non-numeric values fall back to `10`. |

Potential errors mirror the NVD service: missing `requests` (non-retriable) or HTTP issues (retriable).

## Exploit DB service

The helper `arpia_hunt.integrations.exploitdb_service.search_cve` shells out to `searchsploit`.

| Setting | Default | Notes |
| --- | --- | --- |
| `ARPIA_HUNT_SEARCHSPLOIT_PATH` | `searchsploit` | Provide an absolute path when `searchsploit` is not on `PATH`. |
| `ARPIA_HUNT_SEARCHSPLOIT_TIMEOUT` | `15` (seconds) | Non-numeric values fall back to `15`. |

Error handling:

- `FileNotFoundError` becomes `IntegrationError` with `retriable=False` (binary missing).
- `TimeoutExpired` and `CalledProcessError` become retriable `IntegrationError` instances.
- Invalid JSON output raises `IntegrationError` with `retriable=False`.

## Observing failures

All integration failures are caught in `arpia_hunt.enrichment._resolve_enrichment`, logged through `hunt.enrichment.error`, and stored on the `HuntEnrichment` record. The log payload contains:

- `error`: human readable detail from the `IntegrationError`.
- `retriable`: `false` when the run should not be retried automatically.

Non-retriable errors leave the enrichment record in `error` status until manual intervention.

## Test fixtures

JSON fixtures representing typical responses live under `arpia_hunt/fixtures/`:

- `nvd_cve.json`
- `vulners_cve.json`
- `exploitdb_results.json`

Unit tests (`arpia_hunt/tests.py`) load these fixtures to validate profile generation and batch reprocessing flows. Extend the directory with additional samples as new integration cases are covered.
