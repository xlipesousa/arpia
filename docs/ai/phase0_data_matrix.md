# IA Module - Data Matrix (Phase 0)

| Fonte ARPIA | Descrição | Campos/Artefatos | Uso na Demo | Sensibilidade | Aprovação |
|-------------|-----------|------------------|-------------|---------------|-----------|
| `VulnerabilityFinding` | Achados consolidados por CVE/projeto | `title`, `summary`, `severity`, `cve`, `data.summary_hint` | **Sim** – base para recomendações | Média (sanitizar PII) | Responsável: Operações ARPIA |
| `VulnScanSession` | Relatórios das sessões de vulnerabilidade | `title`, `report_snapshot.summary`, `timeline` | **Sim** – contexto histórico | Alta (pode citar hosts) | Responsável: Operações ARPIA |
| `ScanSession` | Resultados de scans de rede | `tasks.stdout`, `findings`, `connectivity` | **Sim** – vetores de exploração | Alta (endereços reais) | Responsável: Operações ARPIA |
| `Project` | Metadados do projeto/cliente | `name`, `description`, macros filtradas (`HOSTS`, `PORTS`) | **Sim** – identificação do cenário | Média (remover nomes reais) | Responsável: PMO |
| Scripts (`Script`/`script_registry`) | Conteúdo de scripts default ou customizados | `name`, `description`, `content` (redigido para demo) | **Sim** – sugerir automações | Baixa (conteúdo público) | Responsável: Engenharia |
| Artefatos externos | Logs anexados, PDFs | **Não** – manter fora da POC inicial | n/a | n/a |

## Notas
- Sanitizar nomes de clientes e IPs reais antes de ingestão.
- Garantir que `tasks.stdout` não contenha credenciais em claro (rodar scrub). 
- Atualizar a coluna de “Aprovação” quando cada responsável der o ok formal.
