import json
import re

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import urlencode
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from arpia_core.models import Project
from arpia_scan.models import ScanSession
from arpia_core.views import build_project_macros
from arpia_log.models import LogEntry

from .models import VulnerabilityFinding, VulnScanSession, VulnTask
from .services import (
	cancel_vulnerability_session,
	VulnGreenboneExecutionError,
	plan_vulnerability_session,
	run_greenbone_scan,
	run_vulnerability_pipeline_async,
)


def _user_projects(user):
	return (
		Project.objects.filter(Q(owner=user) | Q(memberships__user=user))
		.distinct()
		.order_by("name")
	)


def _user_has_access(user, project: Project) -> bool:
	return project.owner_id == user.id or project.memberships.filter(user=user).exists()


def _macro_entries(macros: dict | None) -> list[dict]:
	entries: list[dict] = []
	for key, value in (macros or {}).items():
		if isinstance(value, (list, dict)):
			display = json.dumps(value, indent=2, ensure_ascii=False)
			entries.append({"key": key, "value": display, "is_pre": True})
		else:
			display = str(value or "")
			entries.append({"key": key, "value": display, "is_pre": "\n" in display})
	return entries


def _project_ids(projects) -> list:
	return [project.pk for project in projects]


def _load_dashboard_sessions(project, project_ids: list[str], *, limit: int = 10):
	qs = VulnScanSession.objects.select_related("project", "owner")
	if project:
		qs = qs.filter(project=project)
	elif project_ids:
		qs = qs.filter(project_id__in=project_ids)
	else:
		return []
	return list(qs.order_by("-created_at")[:limit])


def _finding_queryset(project, project_ids: list[str]):
	qs = VulnerabilityFinding.objects.select_related("session")
	if project:
		qs = qs.filter(session__project=project)
	elif project_ids:
		qs = qs.filter(session__project_id__in=project_ids)
	else:
		qs = qs.none()
	return qs


VULNERS_TOKEN_SPLIT = re.compile(r"\s{2,}|\t")
VULNERS_URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)
SUMMARY_COLLAPSE_THRESHOLD = 220


def _load_dashboard_findings(project, project_ids: list[str], *, limit: int = 6):
	qs = _finding_queryset(project, project_ids)
	findings = list(qs.order_by("-detected_at", "-created_at")[:limit])
	for finding in findings:
		setattr(finding, "vulners_entries", _extract_vulners_entries(getattr(finding, "data", {})))
		summary_info = _prepare_dashboard_summary(getattr(finding, "summary", "") or "")
		setattr(finding, "summary_preview", summary_info["preview"])
		setattr(finding, "summary_full", summary_info["full"])
		setattr(finding, "summary_collapsible", summary_info["collapsible"])
	return findings


def _prepare_dashboard_summary(summary: str) -> dict:
	text = (summary or "").strip()
	if not text:
		return {"preview": "Sem descrição adicional.", "full": "", "collapsible": False}

	collapse = False
	if len(text) > SUMMARY_COLLAPSE_THRESHOLD or "http" in text or "\n" in text:
		collapse = True

	preview = text
	if collapse:
		preview = _truncate_summary(text)

	return {
		"preview": preview,
		"full": text,
		"collapsible": collapse,
	}


def _truncate_summary(text: str) -> str:
	if len(text) <= SUMMARY_COLLAPSE_THRESHOLD:
		return text
	cutoff = SUMMARY_COLLAPSE_THRESHOLD
	newline_pos = text.find("\n")
	if newline_pos != -1 and newline_pos < cutoff:
		return text[:newline_pos].strip()
	for delimiter in (". ", "; ", " "):
		pos = text.find(delimiter, 160, cutoff)
		if pos != -1:
			return (text[: pos + len(delimiter.strip())].strip()) + "…"
	return text[:cutoff].rstrip() + "…"


def _extract_vulners_entries(data) -> list[dict]:
	if not isinstance(data, dict):
		return []

	values = data.get("values")
	if not isinstance(values, dict):
		return []

	raw_entries = values.get("vulners")
	if not raw_entries:
		return []

	if not isinstance(raw_entries, (list, tuple)):
		raw_entries = [raw_entries]

	entries: list[dict] = []

	for raw in raw_entries:
		text = str(raw or "").strip()
		if not text:
			continue

		tokens = [token.strip() for token in VULNERS_TOKEN_SPLIT.split(text) if token and token.strip()]
		url_match = VULNERS_URL_PATTERN.search(text)
		url = url_match.group(0).rstrip(")]") if url_match else ""

		score = None
		tags: list[str] = []

		for token in tokens[1:]:
			normalized = token.replace(",", ".")
			if score is None:
				try:
					score = float(normalized)
					continue
				except ValueError:
					pass
			if token.startswith("http") and not url:
				url = token
				continue
			cleaned_tag = token.strip("*")
			if cleaned_tag:
				tags.append(cleaned_tag)

		entry = {
			"label": tokens[0] if tokens else text,
			"raw": text,
			"url": url,
			"score": score,
			"tags": tags,
			"is_context": bool(tokens and tokens[0].lower().startswith("cpe:")),
		}
		entries.append(entry)

	return entries


def _serialize_session_for_dashboard(session: VulnScanSession) -> dict:
	started_at = session.started_at or session.created_at
	started_iso = started_at.isoformat() if started_at else None
	started_display = started_at.strftime("%Y-%m-%d %H:%M") if started_at else ""
	return {
		"id": str(session.pk),
		"title": session.title,
		"status": session.status,
		"status_display": session.get_status_display(),
		"reference": session.reference,
		"owner": session.owner.get_username() if session.owner else "",
		"started_at": started_iso,
		"started_display": started_display,
		"detail_url": reverse("arpia_vuln:session_detail", args=[session.pk]),
	}


def _serialize_finding_for_dashboard(finding: VulnerabilityFinding) -> dict:
	detected_at = finding.detected_at
	detected_iso = detected_at.isoformat() if detected_at else None
	detected_display = detected_at.strftime("%d/%m/%Y %H:%M") if detected_at else ""
	vulners_entries = _extract_vulners_entries(getattr(finding, "data", {}))
	summary_info = _prepare_dashboard_summary(getattr(finding, "summary", "") or "")
	return {
		"id": str(finding.pk),
		"title": finding.title,
		"summary": finding.summary,
		"summary_preview": summary_info["preview"],
		"summary_collapsible": summary_info["collapsible"],
		"summary_full": summary_info["full"],
		"severity": finding.severity,
		"severity_display": finding.get_severity_display(),
		"status": finding.status,
		"status_display": finding.get_status_display(),
		"cve": finding.cve,
		"host": finding.host,
		"service": finding.service,
		"port": finding.port,
		"protocol": finding.protocol,
		"session_id": str(finding.session_id),
		"session_detail_url": reverse("arpia_vuln:session_detail", args=[finding.session_id]),
		"detected_at": detected_iso,
		"detected_display": detected_display,
		"vulners": vulners_entries,
	}


def _serialize_task_for_api(task) -> dict:
	return {
		"id": str(task.pk),
		"order": task.order,
		"name": task.name,
		"kind": task.kind,
		"status": task.status,
		"script": task.script.slug if task.script else None,
		"tool": task.tool.slug if task.tool else None,
		"parameters": task.parameters or {},
	}


def _serialize_session_for_api(session: VulnScanSession) -> dict:
	config_snapshot = session.config_snapshot or {}
	return {
		"id": str(session.pk),
		"reference": session.reference,
		"title": session.title,
		"status": session.status,
		"status_display": session.get_status_display(),
		"project_id": str(session.project_id),
		"owner": session.owner.get_username() if session.owner else "",
		"created_at": session.created_at.isoformat() if session.created_at else None,
		"detail_url": reverse("arpia_vuln:session_detail", args=[session.pk]),
		"pipeline": config_snapshot.get("pipeline", []),
		"playbook": config_snapshot.get("playbook", []),
		"macros_snapshot": session.macros_snapshot or {},
		"tasks": [
			_serialize_task_for_api(task)
			for task in session.tasks.order_by("order", "id")
		],
	}


TERMINAL_SESSION_STATUSES = {
	VulnScanSession.Status.COMPLETED,
	VulnScanSession.Status.FAILED,
	VulnScanSession.Status.CANCELED,
}


def _serialize_session_overview(session: VulnScanSession) -> dict:
	return {
		"id": str(session.pk),
		"reference": session.reference,
		"title": session.title,
		"status": session.status,
		"status_display": session.get_status_display(),
		"project_id": str(session.project_id),
		"project_name": session.project.name,
		"owner": session.owner.get_username() if session.owner else "",
		"created_at": session.created_at.isoformat() if session.created_at else None,
		"started_at": session.started_at.isoformat() if session.started_at else None,
		"finished_at": session.finished_at.isoformat() if session.finished_at else None,
		"last_error": session.last_error or "",
		"notes": session.notes or "",
		"detail_url": reverse("arpia_vuln:session_detail", args=[session.pk]),
		"report_url": reverse("arpia_vuln:session_report_preview", args=[session.pk]),
		"is_terminal": session.is_terminal,
	}


def _normalize_progress(value) -> float:
	try:
		numeric = float(value or 0.0)
	except (TypeError, ValueError):
		numeric = 0.0
	if numeric < 0:
		numeric = 0.0
	if numeric > 1.0 and numeric <= 100.0:
		return numeric
	if numeric <= 1.0:
		return numeric * 100.0
	return min(numeric, 100.0)


def _serialize_vuln_task(task: VulnTask) -> dict:
	progress_percent = int(round(_normalize_progress(task.progress)))
	progress_percent = max(0, min(100, progress_percent))
	return {
		"id": str(task.pk),
		"order": task.order,
		"name": task.name,
		"kind": task.kind,
		"kind_display": task.get_kind_display(),
		"status": task.status,
		"status_display": task.get_status_display(),
		"progress": float(task.progress or 0.0),
		"progress_percent": progress_percent,
		"tool": task.tool.slug if task.tool else None,
		"tool_name": task.tool.name if task.tool else None,
		"script": task.script.slug if task.script else None,
		"script_name": task.script.name if task.script else None,
		"started_at": task.started_at.isoformat() if task.started_at else None,
		"finished_at": task.finished_at.isoformat() if task.finished_at else None,
		"started_at_display": timezone.localtime(task.started_at).strftime("%d/%m %H:%M") if task.started_at else "—",
		"finished_at_display": timezone.localtime(task.finished_at).strftime("%d/%m %H:%M") if task.finished_at else "—",
		"stdout": task.stdout,
		"stderr": task.stderr,
	}


def _collect_cves(data: dict, primary: str | None) -> list[str]:
	cves: list[str] = []
	if primary:
		cves.append(str(primary).strip())
	extra = data.get("cves") if isinstance(data, dict) else []
	if isinstance(extra, (list, tuple)):
		for item in extra:
			code = str(item or "").strip()
			if code and code not in cves:
				cves.append(code)
	return cves


def _format_port_display(port, protocol: str | None) -> str:
	if port is None:
		return ""
	try:
		numeric = int(port)
	except (TypeError, ValueError):
		numeric = port
	proto = (protocol or "").strip()
	return f"{numeric}/{proto}" if proto else str(numeric)


def _serialize_finding_for_live(finding: VulnerabilityFinding) -> dict:
	data = finding.data if isinstance(finding.data, dict) else {}
	cves = _collect_cves(data, finding.cve)
	port_display = _format_port_display(finding.port, finding.protocol)
	try:
		cvss_value = float(finding.cvss_score) if finding.cvss_score is not None else None
	except (TypeError, ValueError):
		cvss_value = None
	calculated_summary = finding.summary or data.get("summary_hint") or ""
	summary_info = _prepare_dashboard_summary(calculated_summary)
	top_cves = data.get("top_cves") if isinstance(data.get("top_cves"), list) else []
	cvss_samples = data.get("cvss_samples") if isinstance(data.get("cvss_samples"), list) else []
	raw_output = data.get("raw_output") if isinstance(data.get("raw_output"), str) else ""
	source_kind = data.get("source_kind") or data.get("source") or ""
	scanner = data.get("scanner") or ""
	file_path = data.get("file_path") or ""
	return {
		"id": str(finding.pk),
		"title": finding.title,
		"summary": finding.summary or "",
		"summary_preview": summary_info["preview"],
		"summary_full": summary_info["full"],
		"summary_collapsible": summary_info["collapsible"],
		"summary_hint": data.get("summary_hint") or "",
		"severity": finding.severity,
		"severity_display": finding.get_severity_display(),
		"status": finding.status,
		"status_display": finding.get_status_display(),
		"cves": cves,
		"primary_cve": cves[0] if cves else "",
		"cvss": cvss_value,
		"cvss_display": f"{cvss_value:.1f}" if cvss_value is not None else "",
		"host": finding.host,
		"service": finding.service,
		"port_display": port_display,
		"detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
		"created_at": finding.created_at.isoformat() if finding.created_at else None,
		"detected_at_display": timezone.localtime(finding.detected_at).strftime("%d/%m/%Y %H:%M") if finding.detected_at else "",
		"source_task": {
			"id": str(finding.source_task_id) if finding.source_task_id else "",
			"name": finding.source_task.name if finding.source_task else "",
			"kind": finding.source_task.kind if finding.source_task else "",
			"status": finding.source_task.status if finding.source_task else "",
			"status_display": finding.source_task.get_status_display() if finding.source_task else "",
		},
		"references": data.get("references") if isinstance(data.get("references"), list) else [],
		"top_cves": top_cves,
		"cvss_samples": cvss_samples,
		"raw_output": raw_output,
		"source_label": source_kind,
		"scanner": scanner,
		"artifact_path": file_path,
		"data": data,
	}


def _calculate_overall_progress(session_status: str, tasks: list[dict]) -> int:
	if not tasks:
		return 100 if session_status in TERMINAL_SESSION_STATUSES else 0
	total = 0
	for task in tasks:
		try:
			percent = int(round(float(task.get("progress_percent", 0))))
		except (TypeError, ValueError):
			percent = 0
		total += max(0, min(100, percent))
	average = int(round(total / max(1, len(tasks))))
	if session_status in TERMINAL_SESSION_STATUSES:
		return 100
	return max(0, min(100, average))


def _format_datetime(value) -> str:
	if not value:
		return ""
	if isinstance(value, str):
		parsed = parse_datetime(value)
		if parsed is None:
			return value
		value = parsed
	if timezone.is_naive(value):
		value = timezone.make_aware(value, timezone.get_current_timezone())
	return timezone.localtime(value).strftime("%d/%m/%Y %H:%M:%S")


def _build_overview_metrics(session: VulnScanSession, snapshot: dict, tasks: list[dict], findings: list[dict]) -> list[dict]:
	metrics: list[dict] = []
	stats = snapshot.get("stats", {}) if isinstance(snapshot, dict) else {}
	if isinstance(stats, dict) and stats:
		for key, value in stats.items():
			label = str(key).replace("_", " ").title()
			metrics.append({"label": label, "value": value})
	if metrics:
		return metrics

	total_tasks = len(tasks)
	completed_tasks = sum(1 for task in tasks if task.get("status") == VulnTask.Status.COMPLETED)
	metrics.append(
		{
			"label": "Etapas concluídas",
			"value": f"{completed_tasks}/{total_tasks}",
			"note": "Execuções dentro da sessão",
		}
	)
	open_findings = sum(1 for item in findings if item.get("status") == VulnerabilityFinding.Status.OPEN)
	total_findings = len(findings)
	metrics.append(
		{
			"label": "Findings abertos",
			"value": open_findings,
			"note": f"Total coletado: {total_findings}",
		}
	)
	if session.started_at:
		metrics.append(
			{
				"label": "Início",
				"value": timezone.localtime(session.started_at).strftime("%d/%m %H:%M"),
			}
		)
	if session.finished_at:
		metrics.append(
			{
				"label": "Término",
				"value": timezone.localtime(session.finished_at).strftime("%d/%m %H:%M"),
			}
		)
	return metrics


def _serialize_log_entry(entry: LogEntry) -> dict:
	timestamp = entry.timestamp
	localized = timezone.localtime(timestamp) if timestamp else None
	return {
		"id": entry.id,
		"timestamp": timestamp.isoformat() if timestamp else None,
		"timestamp_display": localized.strftime("%d/%m/%Y %H:%M:%S") if localized else "—",
		"severity": entry.severity,
		"message": entry.message,
		"event_type": entry.event_type,
		"component": entry.component,
		"source_app": entry.source_app,
		"details": entry.details or {},
		"context": entry.context or {},
		"tags": entry.tags or [],
	}


def _collect_session_state(session: VulnScanSession) -> dict:
	tasks_qs = session.tasks.select_related("tool", "script").order_by("order", "id")
	tasks = [_serialize_vuln_task(task) for task in tasks_qs]
	findings_qs = session.findings.select_related("source_task").order_by("-cvss_score", "severity", "title")
	findings = [_serialize_finding_for_live(finding) for finding in findings_qs]
	snapshot = session.report_snapshot if isinstance(session.report_snapshot, dict) else {}
	session_payload = _serialize_session_overview(session)
	session_payload["total_tasks_count"] = len(tasks)
	session_payload["completed_tasks_count"] = sum(
		1 for task in tasks if task.get("status") == VulnTask.Status.COMPLETED
	)
	session_payload["overall_progress_percent"] = _calculate_overall_progress(session.status, tasks)
	return {
		"session": session_payload,
		"tasks": tasks,
		"findings": findings,
		"overview_metrics": _build_overview_metrics(session, snapshot, tasks, findings),
		"report_insights": snapshot.get("insights", []) if isinstance(snapshot, dict) else [],
		"report_summary": snapshot.get("summary", {}) if isinstance(snapshot, dict) else {},
		"report_stats": snapshot.get("stats", {}) if isinstance(snapshot, dict) else {},
	}


def _fetch_session_logs(session: VulnScanSession, *, limit: int = 100) -> tuple[list[dict], str | None]:
	qs = (
		LogEntry.objects.filter(correlation__vuln_session_id=str(session.pk))
		.order_by("timestamp", "id")
	)
	entries = list(qs[: max(1, min(limit, 250))])
	serialized = [_serialize_log_entry(entry) for entry in entries]
	latest = serialized[-1]["timestamp"] if serialized else None
	return serialized, latest


def _build_session_bootstrap(session: VulnScanSession) -> dict:
	state = _collect_session_state(session)
	logs, cursor = _fetch_session_logs(session, limit=100)
	state.update(
		{
			"logs": logs,
			"latest_log_cursor": cursor,
		}
	)
	return state


def _describe_execution_state(session_payload: dict, tasks: list[dict]) -> str:
	status = (session_payload or {}).get("status", "")
	running = next((task for task in tasks if task.get("status") == VulnTask.Status.RUNNING), None)
	failing = next((task for task in tasks if task.get("status") == VulnTask.Status.FAILED), None)
	pending = next(
		(
			task
			for task in tasks
			if task.get("status") in {VulnTask.Status.PENDING, VulnTask.Status.QUEUED}
		),
		None,
	)
	completed = [task for task in tasks if task.get("status") == VulnTask.Status.COMPLETED]
	if running:
		context = running.get("script_name") or running.get("tool_name")
		return f"Em execução: {running.get('name')}" + (f" • {context}" if context else "")
	if status == VulnScanSession.Status.FAILED and failing:
		return f"Falha em {failing.get('name')}"
	if pending:
		return f"Próxima etapa: {pending.get('name')}"
	if status == VulnScanSession.Status.COMPLETED and completed:
		return f"Última etapa concluída: {completed[-1].get('name')}"
	if status == VulnScanSession.Status.CANCELED:
		return "Sessão cancelada."
	if not tasks and status in TERMINAL_SESSION_STATUSES:
		return "Sessão finalizada."
	return "Aguardando atualização…"


def _build_dashboard_links(project: Project | None) -> dict:
	params = {}
	if project:
		params["project"] = str(project.pk)
	query = f"?{urlencode(params)}" if params else ""
	report_url = reverse("arpia_report:report_home") + query
	if project:
		report_url = reverse("arpia_report:project_consolidated", args=[project.pk])
	return {
		"scan_dashboard": reverse("arpia_scan:dashboard") + query,
		"report_home": report_url,
		"vuln_dashboard": reverse("arpia_vuln:dashboard") + query,
	}


def _build_dashboard_api_url(project: Project | None) -> str:
	base_url = reverse("arpia_vuln:api_dashboard_snapshot")
	if project:
		return f"{base_url}?{urlencode({'project': str(project.pk)})}"
	return base_url


def _compose_dashboard_snapshot(
	project: Project | None,
	*,
	project_ids: list[str],
	sessions: list[VulnScanSession],
	findings: list[VulnerabilityFinding],
) -> dict:
	severity_counts = {key: 0 for key in VulnerabilityFinding.Severity.values}
	base_findings_qs = _finding_queryset(project, project_ids)
	for row in base_findings_qs.values("severity").annotate(total=Count("id")):
		severity = row.get("severity") or VulnerabilityFinding.Severity.UNKNOWN
		severity_counts[severity] = row.get("total", 0)
	open_total = base_findings_qs.filter(status=VulnerabilityFinding.Status.OPEN).count()
	if project:
		total_sessions = project.vuln_sessions.count()
	else:
		total_sessions = (
			VulnScanSession.objects.filter(project_id__in=project_ids).count()
			if project_ids
			else 0
		)
	session_payload = [_serialize_session_for_dashboard(session) for session in sessions]
	finding_payload = [_serialize_finding_for_dashboard(finding) for finding in findings]
	project_payload = None
	if project:
		project_payload = {
			"id": str(project.pk),
			"name": project.name,
			"slug": project.slug,
		}
		if getattr(project, "client_name", None):
			project_payload["client_name"] = project.client_name
	links = _build_dashboard_links(project)
	metrics = {
		"recent_sessions": len(session_payload),
		"recent_findings": len(finding_payload),
		"total_sessions": total_sessions,
		"open_findings": open_total,
		"severity_counts": severity_counts,
	}
	meta = {
		"empty_sessions_text": (
			"Nenhuma sessão registrada para este projeto." if project else "Nenhuma sessão registrada nos projetos acessíveis."
		),
		"empty_findings_text": (
			"Nenhum achado registrado para este projeto." if project else "Nenhum achado registrado nos projetos acessíveis."
		),
	}
	return {
		"generated_at": timezone.now().isoformat(),
		"project": project_payload,
		"sessions": session_payload,
		"findings": finding_payload,
		"metrics": metrics,
		"links": links,
		"meta": meta,
	}


class VulnDashboardView(LoginRequiredMixin, TemplateView):
	template_name = "vuln/dashboard.html"

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		projects = list(_user_projects(self.request.user))
		project_ids = _project_ids(projects)
		selected_project = self._resolve_project(projects)
		selected_project_id = str(selected_project.pk) if selected_project else ""
		sessions = _load_dashboard_sessions(selected_project, project_ids)
		macros = build_project_macros(self.request.user, selected_project) if selected_project else {}
		macro_entries = _macro_entries(macros)
		recent_findings = _load_dashboard_findings(selected_project, project_ids)
		snapshot = _compose_dashboard_snapshot(
			selected_project,
			project_ids=project_ids,
			sessions=sessions,
			findings=recent_findings,
		)
		links = snapshot.get("links", {})
		metrics = snapshot.get("metrics", {})
		severity_counts = metrics.get("severity_counts", {})
		severity_overview = [
			{
				"key": key,
				"label": label,
				"count": severity_counts.get(key, 0),
			}
			for key, label in VulnerabilityFinding.Severity.choices
		]

		context.update(
			{
				"projects": projects,
				"selected_project": selected_project,
				"selected_project_id": selected_project_id,
				"has_project": selected_project is not None,
				"recent_sessions": sessions,
				"macro_entries": macro_entries,
				"recent_findings": recent_findings,
				"open_findings_total": metrics.get("open_findings", 0),
				"total_sessions_count": metrics.get("total_sessions", 0),
				"severity_overview": severity_overview,
				"dashboard_api_url": _build_dashboard_api_url(selected_project),
				"plan_api_url": reverse("arpia_vuln:api_session_plan"),
				"dashboard_bootstrap": snapshot,
				"link_scan_dashboard": links.get("scan_dashboard"),
				"link_report": links.get("report_home"),
				"empty_sessions_text": snapshot.get("meta", {}).get("empty_sessions_text"),
				"empty_findings_text": snapshot.get("meta", {}).get("empty_findings_text"),
			}
		)
		return context

	def _resolve_project(self, projects):
		project_id = self.request.GET.get("project")
		if project_id:
			for project in projects:
				if str(project.pk) == str(project_id):
					return project
			return None
		return projects[0] if projects else None


class VulnSessionDetailView(LoginRequiredMixin, TemplateView):
	template_name = "vuln/session_detail.html"

	def dispatch(self, request, *args, **kwargs):
		self.session = get_object_or_404(
			VulnScanSession.objects.select_related("project", "owner", "source_scan_session"),
			pk=kwargs.get("pk"),
		)
		if not _user_has_access(request.user, self.session.project):
			raise Http404("Sessão não encontrada")
		return super().dispatch(request, *args, **kwargs)

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		state = _build_session_bootstrap(self.session)
		session_payload = state.get("session", {})
		tasks_payload = state.get("tasks", [])
		findings_payload = state.get("findings", [])
		overview_metrics = state.get("overview_metrics", [])
		report_insights = state.get("report_insights", [])
		logs_payload = state.get("logs", [])
		execution_descriptor = _describe_execution_state(session_payload, tasks_payload)
		has_greenbone_task = any(task.get("kind") == VulnTask.Kind.GREENBONE_SCAN for task in tasks_payload)
		failed_greenbone_task = any(
			task.get("kind") == VulnTask.Kind.GREENBONE_SCAN and task.get("status") == VulnTask.Status.FAILED
			for task in tasks_payload
		)
		failure_related_to_greenbone = (
			self.session.status == VulnScanSession.Status.FAILED
			and "greenbone" in (self.session.last_error or "").lower()
		)
		can_retry_greenbone = (
			has_greenbone_task
			and self.session.status != VulnScanSession.Status.RUNNING
			and (failed_greenbone_task or failure_related_to_greenbone)
		)
		status_api_url = reverse("arpia_vuln:api_session_status", args=[self.session.pk])
		logs_api_url = reverse("arpia_vuln:api_session_logs", args=[self.session.pk])
		can_cancel_session = self.session.status == VulnScanSession.Status.RUNNING
		context.update(
			{
				"session": self.session,
				"project": self.session.project,
				"source_scan_session": self.session.source_scan_session,
				"session_payload": session_payload,
				"tasks_payload": tasks_payload,
				"findings_payload": findings_payload,
				"overview_metrics": overview_metrics,
				"report_insights": report_insights,
				"logs_payload": logs_payload,
				"session_bootstrap_json": json.dumps(state, ensure_ascii=False),
				"status_api_url": status_api_url,
				"logs_api_url": logs_api_url,
				"latest_log_cursor": state.get("latest_log_cursor") or "",
				"execution_descriptor": execution_descriptor,
				"report_url": reverse("arpia_vuln:session_report_preview", args=[self.session.pk]),
				"can_retry_greenbone": can_retry_greenbone,
				"retry_greenbone_url": reverse("arpia_vuln:api_session_retry", args=[self.session.pk]),
				"can_cancel_session": can_cancel_session,
				"cancel_session_url": reverse("arpia_vuln:api_session_cancel", args=[self.session.pk]) if can_cancel_session else "",
			}
		)
		return context


class VulnSessionReportPreviewView(LoginRequiredMixin, TemplateView):
	template_name = "vuln/session_report_placeholder.html"

	def dispatch(self, request, *args, **kwargs):
		self.session = get_object_or_404(
			VulnScanSession.objects.select_related("project", "owner"),
			pk=kwargs.get("pk"),
		)
		if not _user_has_access(request.user, self.session.project):
			raise Http404("Sessão não encontrada")
		return super().dispatch(request, *args, **kwargs)

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		findings_qs = self.session.findings.select_related("source_task").order_by("-cvss_score", "severity", "title")
		findings = list(findings_qs)
		snapshot = self.session.report_snapshot if isinstance(self.session.report_snapshot, dict) else {}
		display_findings = [self._serialize_finding_for_template(finding) for finding in findings]
		findings_summary = {}
		if isinstance(snapshot, dict):
			candidate = snapshot.get("findings")
			if isinstance(candidate, dict):
				findings_summary = candidate
		if not findings_summary:
			findings_summary = self._build_fallback_summary(findings)

		severity_breakdown = self._build_severity_breakdown(findings_summary, findings)
		total_findings = int(findings_summary.get("total") or len(findings))
		open_findings = int(findings_summary.get("open_total") or self._count_open_findings(findings))
		hosts_impacted = int(findings_summary.get("hosts_impacted") or self._count_hosts(findings))
		top_cves = findings_summary.get("cves") or self._collect_cves_from_findings(findings)
		sources = findings_summary.get("sources") or []
		artifact_entries = findings_summary.get("artifacts") or []
		last_collected_iso = findings_summary.get("last_collected_at")
		last_collected_dt = self._parse_summary_datetime(last_collected_iso)
		report_json = json.dumps(snapshot or {}, indent=2, ensure_ascii=False)
		max_cvss_value = findings_summary.get("max_cvss") if isinstance(findings_summary, dict) else None
		has_max_cvss = max_cvss_value is not None

		project_consolidated_url = None
		if self.session.project_id:
			project_consolidated_url = reverse(
				"arpia_report:project_consolidated",
				args=[self.session.project.pk],
			)
		context.update(
			{
				"session": self.session,
				"project": self.session.project,
				"findings": findings,
				"display_findings": display_findings,
				"has_findings": bool(display_findings),
				"summary": findings_summary,
				"severity_breakdown": severity_breakdown,
				"total_findings": total_findings,
				"open_findings": open_findings,
				"hosts_impacted": hosts_impacted,
				"top_cves": top_cves[:30],
				"sources": sources,
				"artifact_entries": artifact_entries,
				"last_collected": last_collected_dt,
				"last_collected_raw": last_collected_iso,
				"report_json": report_json,
				"max_cvss_value": max_cvss_value,
				"has_max_cvss": has_max_cvss,
				"project_consolidated_url": project_consolidated_url,
			}
		)
		return context

	def _build_fallback_summary(self, findings):
		severity_counts = {key: 0 for key in VulnerabilityFinding.Severity.values}
		cves: set[str] = set()
		sources: set[str] = set()
		hosts: set[str] = set()
		tasks: set[str] = set()
		max_score = None
		open_total = 0
		for finding in findings:
			severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
			if finding.status == VulnerabilityFinding.Status.OPEN:
				open_total += 1
			if finding.cve:
				cves.add(str(finding.cve).upper())
			data = finding.data or {}
			for extra in data.get("cves", []):
				if extra:
					cves.add(str(extra).upper())
			source_kind = data.get("source_kind") or data.get("source")
			if source_kind:
				sources.add(str(source_kind))
			if finding.host:
				hosts.add(str(finding.host))
			if finding.source_task_id:
				tasks.add(str(finding.source_task_id))
			if finding.cvss_score is not None:
				score = float(finding.cvss_score)
				if max_score is None or score > max_score:
					max_score = score
		return {
			"total": len(findings),
			"open_total": open_total,
			"by_severity": severity_counts,
			"cves": sorted(cves),
			"sources": sorted(sources),
			"hosts_impacted": len(hosts),
			"tasks": sorted(tasks),
			"max_cvss": max_score,
			"artifacts": [],
			"last_collected_at": None,
		}

	def _build_severity_breakdown(self, summary, findings):
		base = summary.get("by_severity") if isinstance(summary.get("by_severity"), dict) else {}
		total = int(summary.get("total") or len(findings)) or 0
		breakdown = []
		for key, label in VulnerabilityFinding.Severity.choices:
			count = int(base.get(key, 0))
			percentage = (count / total * 100) if total else 0
			breakdown.append(
				{
					"key": key,
					"label": label,
					"count": count,
					"percentage": round(percentage, 1) if percentage else 0,
				}
			)
		return breakdown

	def _count_open_findings(self, findings):
		return sum(1 for finding in findings if finding.status == VulnerabilityFinding.Status.OPEN)

	def _count_hosts(self, findings):
		return len({str(finding.host) for finding in findings if finding.host})

	def _collect_cves_from_findings(self, findings, limit: int = 60):
		ordered: list[str] = []
		seen: set[str] = set()
		for finding in findings:
			candidates: list[str] = []
			if finding.cve:
				candidates.append(str(finding.cve))
			data = finding.data or {}
			for extra in data.get("cves", []):
				candidates.append(str(extra))
			for raw in candidates:
				cve = raw.strip().upper()
				if not cve or not cve.startswith("CVE-"):
					continue
				if cve in seen:
					continue
				seen.add(cve)
				ordered.append(cve)
				if len(ordered) >= limit:
					return ordered
		return ordered

	def _parse_summary_datetime(self, value):
		if not value or not isinstance(value, str):
			return None
		dt = parse_datetime(value)
		if dt is None:
			return None
		if timezone.is_naive(dt):
			dt = timezone.make_aware(dt, timezone.get_current_timezone())
		return dt

	def _serialize_finding_for_template(self, finding: VulnerabilityFinding) -> dict:
		data = finding.data if isinstance(finding.data, dict) else {}
		references_raw = data.get("references")
		if isinstance(references_raw, (list, tuple, set)):
			references_iterable = references_raw
		elif references_raw:
			references_iterable = [references_raw]
		else:
			references_iterable = []
		references: list[str] = []
		for entry in references_iterable:
			text = str(entry).strip()
			if text and text not in references:
				references.append(text)

		cves_raw = []
		if finding.cve:
			cves_raw.append(finding.cve)
		data_cves = data.get("cves")
		if isinstance(data_cves, (list, tuple, set)):
			cves_raw.extend(data_cves)
		elif data_cves:
			cves_raw.append(data_cves)
		cves: list[str] = []
		for entry in cves_raw:
			code = str(entry).strip().upper()
			if not code:
				continue
			if code not in cves:
				cves.append(code)
		primary_cve = cves[0] if cves else ""
		extra_cves_count = max(len(cves) - (1 if primary_cve else 0), 0)

		cvss_samples_raw = data.get("cvss_samples")
		if isinstance(cvss_samples_raw, (list, tuple, set)):
			sample_iterable = cvss_samples_raw
		elif cvss_samples_raw in (None, ""):
			sample_iterable = []
		else:
			sample_iterable = [cvss_samples_raw]
		cvss_samples: list[float] = []
		for sample in sample_iterable:
			try:
				value = float(sample)
			except (TypeError, ValueError):
				continue
			cvss_samples.append(value)
		cvss_samples = cvss_samples[:5]
		cvss_score = float(finding.cvss_score) if finding.cvss_score is not None else None
		cvss_display = cvss_score if cvss_score is not None else (cvss_samples[0] if cvss_samples else None)
		cvss_samples_display = [f"{value:.1f}" for value in cvss_samples]

		port_display = ""
		if finding.port:
			port_display = str(finding.port)
			if finding.protocol:
				port_display += f"/{finding.protocol}"

		source_label = data.get("source_kind") or data.get("source") or ""
		artifact_path = data.get("file_path") or ""
		scanner = data.get("scanner") or ""
		raw_output = data.get("raw_output") if isinstance(data.get("raw_output"), str) else ""
		summary_hint = data.get("summary_hint") or ""
		summary_basis = finding.summary or summary_hint
		summary_info = _prepare_dashboard_summary(summary_basis)
		top_cves = data.get("top_cves") if isinstance(data.get("top_cves"), list) else []
		if not top_cves and primary_cve:
			top_cves = [primary_cve]

		task_payload = None
		if finding.source_task:
			task_payload = {
				"id": str(finding.source_task.pk),
				"name": finding.source_task.name,
				"kind": finding.source_task.kind,
				"status": finding.source_task.status,
				"status_display": finding.source_task.get_status_display(),
			}

		return {
			"id": str(finding.pk),
			"title": finding.title,
			"summary": finding.summary,
			"summary_hint": summary_hint,
			"summary_preview": summary_info["preview"],
			"summary_full": summary_info["full"],
			"summary_collapsible": summary_info["collapsible"],
			"severity": finding.severity,
			"severity_display": finding.get_severity_display(),
			"status": finding.status,
			"status_display": finding.get_status_display(),
			"is_open": finding.status == VulnerabilityFinding.Status.OPEN,
			"host": finding.host,
			"service": finding.service,
			"port": finding.port,
			"protocol": finding.protocol,
			"port_display": port_display,
			"cvss_score": cvss_score,
			"cvss_samples": cvss_samples,
			"cvss_display": cvss_display,
			"cvss_samples_display": cvss_samples_display,
			"primary_cve": primary_cve,
			"extra_cves_count": extra_cves_count,
			"all_cves": cves,
			"top_cves": top_cves,
			"references": references,
			"references_total": len(references),
			"artifact_path": artifact_path,
			"source_label": source_label,
			"scanner": scanner,
			"raw_output": raw_output,
			"data": data,
			"task": task_payload,
		}


@login_required
@require_http_methods(["GET"])
def api_dashboard_snapshot(request):
	projects = list(_user_projects(request.user))
	project_ids = _project_ids(projects)
	project = None
	project_param = request.GET.get("project")
	if project_param:
		for candidate in projects:
			if str(candidate.pk) == str(project_param):
				project = candidate
				break
		if project is None:
			return JsonResponse({"error": "Projeto não encontrado."}, status=404)
	else:
		project = projects[0] if projects else None

	sessions = _load_dashboard_sessions(project, project_ids)
	findings = _load_dashboard_findings(project, project_ids)
	snapshot = _compose_dashboard_snapshot(
		project,
		project_ids=project_ids,
		sessions=sessions,
		findings=findings,
	)
	return JsonResponse(snapshot, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["POST"])
def api_session_plan(request):
	try:
		payload = json.loads(request.body or "{}")
	except json.JSONDecodeError:
		return JsonResponse({"error": "JSON inválido."}, status=400)

	project_id = payload.get("project_id")
	if not project_id:
		return JsonResponse({"error": "project_id é obrigatório."}, status=400)

	project = get_object_or_404(Project, pk=project_id)
	if not _user_has_access(request.user, project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	source_scan_key = payload.get("source_scan_session") or payload.get("source_scan_session_id")
	source_scan_session = None
	if source_scan_key:
		try:
			source_scan_session = ScanSession.objects.get(pk=source_scan_key, project=project)
		except ScanSession.DoesNotExist:
			return JsonResponse({"error": "Sessão de scan não encontrada para este projeto."}, status=404)

	title = payload.get("title") or f"Sessão Vuln {project.name}"
	pipeline_payload = payload.get("pipeline") if isinstance(payload.get("pipeline"), list) else None
	if pipeline_payload is not None:
		pipeline = pipeline_payload
	else:
		include_targeted = payload.get("include_targeted", True)
		include_targeted_nse = payload.get("include_targeted_nse")
		if include_targeted_nse is False:
			include_targeted = False
		include_greenbone = payload.get("include_greenbone", True)
		pipeline: list[object] = []
		if include_targeted:
			pipeline.append({"action": "targeted"})
		if include_greenbone:
			pipeline.append("greenbone")

	reserved_keys = {
		"project_id",
		"title",
		"pipeline",
		"include_targeted",
		"include_targeted_nse",
		"include_greenbone",
		"source_scan_session",
		"source_scan_session_id",
	}
	config = {key: value for key, value in payload.items() if key not in reserved_keys}

	try:
		session = plan_vulnerability_session(
			owner=request.user,
			project=project,
			title=title,
			source_scan_session=source_scan_session,
			pipeline=pipeline,
			config=config,
		)
	except ValidationError as exc:
		return JsonResponse({"error": exc.message}, status=400)

	response = _serialize_session_for_api(session)
	return JsonResponse(response, status=201, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["POST"])
def api_session_start(request, pk):
	session = get_object_or_404(
		VulnScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)

	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	if session.is_terminal:
		return JsonResponse({"error": "Sessão já foi finalizada."}, status=409)

	if session.status == VulnScanSession.Status.RUNNING:
		return JsonResponse({"error": "Sessão já está em execução."}, status=409)

	try:
		run_vulnerability_pipeline_async(session, triggered_by=request.user)
	except ValidationError as exc:
		return JsonResponse({"error": exc.message}, status=400)
	except Exception as exc:  # pragma: no cover - captura para UI
		session.refresh_from_db()
		return JsonResponse({"error": str(exc)}, status=500)

	session.refresh_from_db()
	return JsonResponse(_serialize_session_for_api(session), status=200, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["POST"])
def api_session_cancel(request, pk):
	session = get_object_or_404(
		VulnScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)

	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	if session.status != VulnScanSession.Status.RUNNING:
		if session.is_terminal:
			return JsonResponse({"error": "Sessão já foi finalizada."}, status=409)
		return JsonResponse({"error": "Sessão não está em execução."}, status=409)

	try:
		payload = json.loads(request.body or "{}")
	except json.JSONDecodeError:
		payload = {}
	reason = str(payload.get("reason") or "").strip()

	try:
		cancel_vulnerability_session(session, triggered_by=request.user, reason=reason)
	except ValidationError as exc:
		return JsonResponse({"error": exc.message}, status=400)
	except Exception as exc:  # pragma: no cover - captura genérica para UI
		return JsonResponse({"error": str(exc)}, status=500)

	session.refresh_from_db()
	return JsonResponse(_serialize_session_for_api(session), status=200, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["POST"])
def api_session_retry(request, pk):
	session = get_object_or_404(
		VulnScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)

	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	if session.status == VulnScanSession.Status.RUNNING:
		return JsonResponse({"error": "Sessão já está em execução."}, status=409)

	try:
		payload = json.loads(request.body or "{}")
	except json.JSONDecodeError:
		return JsonResponse({"error": "JSON inválido."}, status=400)

	action = str(payload.get("action") or payload.get("step") or "greenbone").strip().lower()
	if action not in {"greenbone", "gvm"}:
		return JsonResponse({"error": "Ação de retry inválida."}, status=400)

	greenbone_qs = session.tasks.filter(kind=VulnTask.Kind.GREENBONE_SCAN)
	if not greenbone_qs.exists():
		return JsonResponse({"error": "Sessão não possui etapa Greenbone para retry."}, status=400)

	failed_exists = greenbone_qs.filter(status=VulnTask.Status.FAILED).exists()
	failure_related_to_greenbone = "greenbone" in (session.last_error or "").lower()
	if not failed_exists and not failure_related_to_greenbone:
		return JsonResponse({"error": "Nenhuma execução Greenbone falha encontrada para retry."}, status=400)

	previous_status = session.status
	previous_finished_at = session.finished_at
	previous_last_error = session.last_error
	previous_started_at = session.started_at
	session.status = VulnScanSession.Status.RUNNING
	session.last_error = ""
	session.finished_at = None
	session.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
	if not session.started_at:
		session.started_at = timezone.now()
		session.save(update_fields=["started_at", "updated_at"])

	try:
		task = run_greenbone_scan(session, triggered_by=request.user, auto_finalize=True)
	except ValidationError as exc:
		session.refresh_from_db()
		session.status = previous_status
		session.finished_at = previous_finished_at
		session.last_error = previous_last_error
		session.started_at = previous_started_at
		session.save(update_fields=["status", "finished_at", "last_error", "started_at", "updated_at"])
		return JsonResponse({"error": exc.message}, status=400)
	except VulnGreenboneExecutionError as exc:
		session.refresh_from_db()
		if session.status == VulnScanSession.Status.RUNNING:
			session.status = VulnScanSession.Status.FAILED
			session.last_error = str(exc)
			session.finished_at = timezone.now()
			session.started_at = previous_started_at
			session.save(update_fields=["status", "last_error", "finished_at", "started_at", "updated_at"])
		return JsonResponse({"error": str(exc)}, status=502)
	except Exception as exc:  # pragma: no cover - caminho inesperado
		session.refresh_from_db()
		if session.status == VulnScanSession.Status.RUNNING:
			session.status = VulnScanSession.Status.FAILED
			session.last_error = str(exc)
			session.finished_at = timezone.now()
			session.started_at = previous_started_at
			session.save(update_fields=["status", "last_error", "finished_at", "started_at", "updated_at"])
		return JsonResponse({"error": str(exc)}, status=500)

	session.refresh_from_db()
	if task:
		task.refresh_from_db()

	response = {
		"session": _serialize_session_for_api(session),
		"task": _serialize_task_for_api(task) if task else None,
	}
	return JsonResponse(response, status=200, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["GET"])
def api_session_status(request, pk):
	session = get_object_or_404(
		VulnScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)
	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
	payload = _collect_session_state(session)
	return JsonResponse(payload, status=200, json_dumps_params={"ensure_ascii": False})


@login_required
@require_http_methods(["GET"])
def api_session_logs(request, pk):
	session = get_object_or_404(
		VulnScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)
	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	qs = LogEntry.objects.filter(correlation__vuln_session_id=str(session.pk))

	def _parse_cursor(value: str | None):
		if not value:
			return None
		parsed = parse_datetime(value)
		if not parsed:
			return None
		if timezone.is_naive(parsed):
			parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
		return parsed

	since_param = request.GET.get("since")
	if since_param:
		since_dt = _parse_cursor(since_param)
		if since_dt:
			qs = qs.filter(timestamp__gte=since_dt)

	cursor_param = request.GET.get("cursor")
	if cursor_param:
		cursor_dt = _parse_cursor(cursor_param)
		if cursor_dt:
			qs = qs.filter(timestamp__gt=cursor_dt)

	try:
		limit = int(request.GET.get("limit", "100"))
	except (TypeError, ValueError):
		limit = 100
	limit = max(1, min(limit, 250))

	entries = list(qs.order_by("timestamp", "id")[:limit])
	results = [_serialize_log_entry(entry) for entry in entries]
	latest = results[-1]["timestamp"] if results else cursor_param or since_param

	return JsonResponse(
		{
			"results": results,
			"count": len(results),
			"latest": latest,
		},
		status=200,
		json_dumps_params={"ensure_ascii": False},
	)
