from __future__ import annotations

from typing import Any, Iterable


def _format_findings(findings: Iterable[dict[str, Any]]) -> str:
    items = list(findings)
    if not items:
        return "- Nenhuma vulnerabilidade registrada ainda."
    lines = ["- Vulnerabilidades recentes:"]
    for entry in items[:5]:
        cve = entry.get("cve") or "Sem CVE"
        severity = entry.get("severity", "unknown").upper()
        title = entry.get("title") or "(sem titulo)"
        summary = entry.get("summary") or "Resumo indisponivel"
        lines.append(f"  - {cve} ({severity}): {title} - {summary}")
    return "\n".join(lines)


def _format_scripts(scripts: Iterable[dict[str, Any]]) -> str:
    items = list(scripts)
    if not items:
        return "- Nenhum script relevante disponivel."
    lines = ["- Scripts sugeridos:"]
    for entry in items[:5]:
        requires_tool = " (requer ferramenta)" if entry.get("requires_tool") else ""
        lines.append(f"  - {entry.get('name')}:{requires_tool} {entry.get('description')}")
    return "\n".join(lines)


def _format_sessions(sessions: Iterable[dict[str, Any]]) -> str:
    items = list(sessions)
    if not items:
        return "- Nenhuma sessao de scan recente registrada."
    lines = ["- Historico de scans:"]
    for entry in items[:3]:
        status = entry.get("status", "unknown")
        lines.append(
            f"  - {entry.get('title')} (status: {status}, ref: {entry.get('reference')})"
        )
    return "\n".join(lines)


def render_internal_summary(*, context: dict[str, Any], question: str) -> str:
    project_info = context.get("project", {})
    findings_text = _format_findings(context.get("vulnerability_findings", []))
    scripts_text = _format_scripts(context.get("available_scripts", []))
    sessions_text = _format_sessions(context.get("recent_scan_sessions", []))

    answer_lines = [
        f"Projeto: {project_info.get('name')} (cliente: {project_info.get('client') or 'nao informado'})",
        "Pergunta recebida: " + (question.strip() or "(sem pergunta)"),
        "Resumo com base no que o ARPIA ja coletou:",
        findings_text,
        scripts_text,
        sessions_text,
        "Proximos passos sugeridos:",
        "- Priorizar as vulnerabilidades criticas/altas com mitigacao imediata.",
        "- Avaliar execucao dos scripts recomendados para aprofundar exploracao controlada.",
        "- Atualizar o relatorio executivo apos aplicar as acoes, mantendo o cliente informado.",
    ]

    return "\n".join(answer_lines)
