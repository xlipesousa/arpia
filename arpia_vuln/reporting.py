from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from django.db import transaction
from django.utils import timezone

from arpia_report.models import VulnerabilityReportEntry

from .models import VulnScanSession, VulnerabilityFinding

SEVERITY_ORDER = {
	VulnerabilityFinding.Severity.CRITICAL: 0,
	VulnerabilityFinding.Severity.HIGH: 1,
	VulnerabilityFinding.Severity.MEDIUM: 2,
	VulnerabilityFinding.Severity.LOW: 3,
	VulnerabilityFinding.Severity.INFO: 4,
	VulnerabilityFinding.Severity.UNKNOWN: 5,
}

MAX_EVIDENCE_LENGTH = 1200


@dataclass(frozen=True)
class VulnerabilityReportResult:
	entry: VulnerabilityReportEntry
	created: bool


def upsert_vulnerability_report_entry(
	session: VulnScanSession,
	summary: Optional[Dict[str, object]] = None,
	*,
	include_closed: bool = True,
) -> VulnerabilityReportResult:
	"""Cria ou atualiza uma entrada agregada de relatório para a sessão."""
	if summary is None:
		summary = {}

	findings = _load_findings(session, include_closed=include_closed)
	payload = _build_report_payload(session, summary, findings)
	severity_distribution = dict(summary.get("by_severity") or {})
	cves = list(summary.get("cves") or [])
	open_total = int(summary.get("open_total") or 0)
	total = int(summary.get("total") or len(findings))

	title = f"Relatório de Vulnerabilidades — {session.title}"
	summary_text = _compose_summary_text(total, open_total, severity_distribution)
	tags = _build_tags(session, findings)

	defaults = {
		"title": title,
		"summary": summary_text,
		"payload": payload,
		"tags": tags,
		"severity_distribution": severity_distribution,
		"cves": cves,
	}

	with transaction.atomic():
		entry, created = VulnerabilityReportEntry.objects.update_or_create(
			project=session.project,
			source_identifier=f"vuln-session:{session.pk}",
			defaults=defaults,
		)

	return VulnerabilityReportResult(entry=entry, created=created)


def _load_findings(
	session: VulnScanSession,
	*,
	include_closed: bool,
) -> List[VulnerabilityFinding]:
	query = session.findings.select_related("source_task", "source_task__script", "source_task__tool")
	if not include_closed:
		query = query.filter(status=VulnerabilityFinding.Status.OPEN)
	return sorted(query, key=_finding_sort_key)


def _finding_sort_key(finding: VulnerabilityFinding) -> Tuple[int, float, str]:
	severity_rank = SEVERITY_ORDER.get(finding.severity, 5)
	cvss_score = float(finding.cvss_score or 0) * -1
	return (severity_rank, cvss_score, finding.title.lower())


def _build_report_payload(
	session: VulnScanSession,
	summary: Dict[str, object],
	findings: Iterable[VulnerabilityFinding],
) -> Dict[str, object]:
	findings_list = list(findings)
	payload = {
		"generated_at": timezone.now().isoformat(),
		"session": {
			"id": str(session.pk),
			"reference": session.reference,
			"title": session.title,
			"status": session.status,
			"started_at": session.started_at.isoformat() if session.started_at else None,
			"finished_at": session.finished_at.isoformat() if session.finished_at else None,
		},
		"summary": {
			"totals": {
				"total": int(summary.get("total") or len(findings_list)),
				"open": int(summary.get("open_total") or 0),
			},
			"severity": dict(summary.get("by_severity") or {}),
			"cves": list(summary.get("cves") or []),
			"hosts_impacted": int(summary.get("hosts_impacted") or 0),
			"sources": list(summary.get("sources") or []),
			"max_cvss": summary.get("max_cvss"),
		},
		"artifacts": list(summary.get("artifacts") or []),
		"findings": [_serialize_finding(finding) for finding in findings_list],
	}

	return json.loads(json.dumps(payload, ensure_ascii=False))


def _serialize_finding(finding: VulnerabilityFinding) -> Dict[str, object]:
	data = finding.data if isinstance(finding.data, dict) else {}
	source_task = finding.source_task
	artifact = data.get("file_path")
	references = data.get("references") or []
	evidence = data.get("raw_output") or data.get("evidence") or ""
	if evidence:
		evidence = evidence.strip()
		if len(evidence) > MAX_EVIDENCE_LENGTH:
			evidence = evidence[:MAX_EVIDENCE_LENGTH] + "…"

	serialized = {
		"id": str(finding.pk),
		"title": finding.title,
		"summary": finding.summary,
		"severity": finding.severity,
		"status": finding.status,
		"host": finding.host,
		"service": finding.service,
		"port": finding.port,
		"protocol": finding.protocol,
		"cve": finding.cve,
		"cves": data.get("cves", []),
		"sources": {
			"primary": data.get("source_kind") or data.get("source"),
			"scanner": data.get("scanner"),
		},
		"references": references,
		"artifact": artifact,
		"cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
		"cvss_vector": finding.cvss_vector or "",
		"collected_at": data.get("collected_at"),
		"evidence_excerpt": evidence or None,
	}

	if source_task:
		serialized["task"] = {
			"id": str(source_task.pk),
			"name": source_task.name,
			"kind": source_task.kind,
			"status": source_task.status,
		}

	return serialized


def _compose_summary_text(total: int, open_total: int, severity_distribution: Dict[str, int]) -> str:
	if total <= 0:
		return "Nenhuma vulnerabilidade consolidada até o momento."

	critical = int(severity_distribution.get(VulnerabilityFinding.Severity.CRITICAL, 0))
	high = int(severity_distribution.get(VulnerabilityFinding.Severity.HIGH, 0))
	return (
		f"{total} vulnerabilidade(s) consolidadas — {open_total} permanecem abertas. "
		f"Críticas: {critical}, Altas: {high}."
	)


def _build_tags(session: VulnScanSession, findings: Iterable[VulnerabilityFinding]) -> List[str]:
	tag_set = {"vuln", "auto", f"session:{session.reference}"}
	for finding in findings:
		if finding.severity:
			tag_set.add(f"severity:{finding.severity}")
		if finding.cve:
			tag_set.add(f"cve:{finding.cve}".lower())
	return sorted(tag_set)
