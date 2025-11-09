from __future__ import annotations

from typing import Any

from django.db.models import Q

from arpia_core.models import Project, Script
from arpia_core.views import build_project_macros
from arpia_scan.models import ScanSession
from arpia_vuln.models import VulnerabilityFinding

SAFE_MACRO_BLOCKLIST = {"CREDENTIAL", "PASSWORD", "SECRET", "TOKEN"}
MACRO_VALUE_MAX_LENGTH = 800


class ProjectAccessError(Exception):
	"""Raised when a user does not have access to the requested project."""


def _truncate(value: str | None, limit: int = 280) -> str:
	if not value:
		return ""
	text = str(value).strip()
	if len(text) <= limit:
		return text
	return text[: limit - 1].rstrip() + "…"


def _sanitize_macros(macros: dict[str, Any]) -> dict[str, Any]:
	sanitized: dict[str, Any] = {}
	for key, value in (macros or {}).items():
		upper_key = key.upper()
		if any(block in upper_key for block in SAFE_MACRO_BLOCKLIST):
			continue
		if isinstance(value, str) and len(value) > MACRO_VALUE_MAX_LENGTH:
			sanitized[key] = value[: MACRO_VALUE_MAX_LENGTH - 1].rstrip() + "…"
		else:
			sanitized[key] = value
	return sanitized


def build_project_context(
	*,
	project: Project | None,
	user=None,
	limit_findings: int = 5,
	limit_sessions: int = 3,
	limit_scripts: int = 5,
) -> dict[str, Any]:
	if project is None:
		return {}

	macros = build_project_macros(user, project) if project else {}
	sanitized_macros = _sanitize_macros(macros)

	findings_qs = (
		VulnerabilityFinding.objects.filter(session__project=project)
		.select_related("session")
		.order_by("-detected_at", "-created_at")[:limit_findings]
	)
	findings: list[dict[str, Any]] = []
	for finding in findings_qs:
		data_block = finding.data if isinstance(finding.data, dict) else {}
		summary_source = finding.summary or data_block.get("summary_hint") or data_block.get("raw_output")
		findings.append(
			{
				"id": str(finding.pk),
				"title": finding.title,
				"cve": finding.cve,
				"severity": finding.severity,
				"summary": _truncate(summary_source),
				"detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
				"session_id": str(finding.session_id),
			}
		)

	scan_sessions_qs = ScanSession.objects.filter(project=project).order_by("-created_at")[:limit_sessions]
	scan_sessions = [
		{
			"id": str(session.pk),
			"title": session.title,
			"status": session.status,
			"reference": session.reference,
			"started_at": session.started_at.isoformat() if session.started_at else None,
			"finished_at": session.finished_at.isoformat() if session.finished_at else None,
		}
		for session in scan_sessions_qs
	]

	scripts_qs = (
		Script.objects.filter(Q(owner=project.owner) | Q(owner__isnull=True))
		.order_by("name")[:limit_scripts]
	)
	scripts = [
		{
			"slug": script.slug,
			"name": script.name,
			"description": _truncate(script.description, 220),
			"requires_tool": bool(script.required_tool_slug),
		}
		for script in scripts_qs
	]

	return {
		"project": {
			"id": str(project.pk),
			"name": project.name,
			"description": _truncate(project.description, 400),
			"client": project.client_name,
		},
		"macros": sanitized_macros,
		"vulnerability_findings": findings,
		"recent_scan_sessions": scan_sessions,
		"available_scripts": scripts,
	}
