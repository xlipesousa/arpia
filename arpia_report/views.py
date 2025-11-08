import json
from collections import Counter
from typing import Any, Iterable

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView
from django.db.models import Q

from arpia_core.models import Project
from arpia_core.views import build_project_macros
from arpia_scan.models import ScanSession, ScanTask

from .services import ReportAggregator, SectionData


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
OPEN_STATUS_KEYS = {"open", "new", "ack", "in_progress"}
RESOLVED_STATUS_KEYS = {"resolved", "closed", "remediated", "done"}


def _truncate_text(text: Any, max_chars: int = 420) -> str:
	if not text:
		return ""
	value = str(text).strip()
	if len(value) <= max_chars:
		return value
	return value[: max(0, max_chars - 1)].rstrip() + "…"


def _safe_float(value: Any) -> float | None:
	try:
		return float(value)
	except (TypeError, ValueError):
		return None


def _format_metric_value(value: Any) -> str:
	if value is None:
		return "—"
	if isinstance(value, float):
		return (f"{value:.1f}").rstrip("0").rstrip(".") or "0"
	return str(value)


def _summarize_scan_payload(scan_summary: dict, scan_services: dict, scan_hosts: list[str]) -> tuple[list[dict], list[dict], int]:
	artifacts = []
	if isinstance(scan_summary, dict):
		artifacts = scan_summary.get("artifacts", {}) or {}
	connectivity_entries = artifacts.get("connectivity") if isinstance(artifacts, dict) else []
	if not connectivity_entries and isinstance(scan_summary, dict):
		connectivity_entries = scan_summary.get("connectivity", [])
	host_entries: list[dict] = []
	total_open_ports = 0
	for entry in connectivity_entries or []:
		if not isinstance(entry, dict):
			continue
		host = (entry.get("host") or "").strip()
		reachable = bool(entry.get("reachable", False))
		ports = entry.get("ports") or []
		open_ports = [port.get("port") for port in ports if isinstance(port, dict) and port.get("status") == "open"]
		closed_ports = [port.get("port") for port in ports if isinstance(port, dict) and port.get("status") != "open"]
		total_open_ports += len(open_ports)
		host_entries.append(
			{
				"host": host or (
					scan_hosts[0] if not host and scan_hosts else ""
				),
				"reachable": reachable,
				"open_ports": open_ports,
				"closed_ports": closed_ports,
				"notes": entry.get("notes") or entry.get("error") or "",
			}
		)
	host_entries.sort(key=lambda item: (not item.get("reachable", False), -(len(item.get("open_ports", []))), item.get("host") or ""))
	service_entries: list[dict] = []
	if isinstance(scan_services, dict):
		for service in (scan_services.get("items") or []):
			if not isinstance(service, dict):
				continue
			label = service.get("service") or service.get("name") or "Serviço"
			occurrences = service.get("occurrences") or service.get("hosts") or []
			service_entries.append(
				{
					"service": label,
					"occurrences": len(occurrences) if isinstance(occurrences, Iterable) else 0,
				}
			)
	service_entries.sort(key=lambda item: (-item.get("occurrences", 0), item.get("service") or ""))
	return host_entries, service_entries[:10], total_open_ports


def _prepare_scan_findings(findings: list[dict]) -> list[dict]:
	display: list[dict] = []
	for finding in findings or []:
		if not isinstance(finding, dict):
			continue
		severity = str(finding.get("severity") or "info").lower()
		summary = finding.get("summary") or finding.get("description")
		if isinstance(summary, dict):
			summary = summary.get("text")
		data = finding.get("data") if isinstance(finding.get("data"), dict) else {}
		host = finding.get("host") or data.get("host") or ""
		if not host:
			hosts = data.get("hosts") if isinstance(data, dict) else []
			if isinstance(hosts, list) and hosts:
				host = hosts[0]
		display.append(
			{
				"title": finding.get("title") or "Achado",
				"severity": severity,
				"summary": _truncate_text(summary, 320),
				"host": host,
				"kind": finding.get("kind_display") or finding.get("kind"),
			}
		)
	return display


def _summarize_vuln_findings(findings: list[dict], vuln_cves: list[str]) -> dict[str, Any]:
	severity_counter: Counter[str] = Counter()
	status_counter: Counter[str] = Counter()
	host_counter: Counter[str] = Counter()
	service_counter: Counter[str] = Counter()
	entries: list[dict] = []
	max_cvss: float | None = None
	for finding in findings or []:
		if not isinstance(finding, dict):
			continue
		severity = str(finding.get("severity") or "unknown").lower()
		status = str(finding.get("status") or "open").lower()
		severity_counter[severity] += 1
		status_counter[status] += 1
		host = (finding.get("host") or "").strip()
		if host:
			host_counter[host] += 1
		service = (finding.get("service") or "").strip()
		if service:
			service_counter[service] += 1
		cvss = _safe_float(finding.get("cvss_score"))
		if cvss is not None and (max_cvss is None or cvss > max_cvss):
			max_cvss = cvss
		cves = [str(c).upper() for c in finding.get("cves") or [] if c]
		if not cves and finding.get("cve"):
			cves = [str(finding.get("cve")).upper()]
		entries.append(
			{
				"title": finding.get("title") or "Achado",
				"severity": severity,
				"severity_display": severity.upper(),
				"status": status,
				"status_display": status.title() if status else "—",
				"host": host,
				"service": service,
				"port": finding.get("port"),
				"protocol": finding.get("protocol"),
				"summary": _truncate_text(finding.get("summary") or finding.get("description"), 420),
				"primary_cve": (finding.get("cve") or (cves[0] if cves else "")),
				"cves": cves[:6],
				"extra_cve_count": max(len(cves) - 6, 0),
				"cvss": cvss,
				"references": (finding.get("references") or [])[:4],
				"artifact": finding.get("artifact"),
			}
		)
	total = sum(severity_counter.values())
	severity_breakdown = []
	for key in SEVERITY_ORDER:
		count = severity_counter.get(key, 0)
		percentage = (count / total * 100) if total else 0
		severity_breakdown.append(
			{
				"key": key,
				"label": key.upper(),
				"count": count,
				"percentage": round(percentage, 1) if percentage else 0,
			}
		)
	top_hosts = [
		{"label": host, "count": count}
		for host, count in host_counter.most_common(5)
	]
	top_services = [
		{"label": service, "count": count}
		for service, count in service_counter.most_common(5)
	]
	unique_cves_total = len({cve.upper() for cve in vuln_cves}) if vuln_cves else 0
	return {
		"entries": entries,
		"severity": severity_counter,
		"severity_breakdown": severity_breakdown,
		"status": status_counter,
		"top_hosts": top_hosts,
		"top_services": top_services,
		"max_cvss": max_cvss,
		"unique_cves_total": unique_cves_total,
	}


def _build_executive_overview(*, totals: dict, severity: Counter[str], scan_hosts: list[str], max_cvss: float | None, indicators_total: int) -> list[dict]:
	total_findings = sum(int(value or 0) for value in (totals or {}).values())
	critical_total = int(severity.get("critical", 0))
	hosts_count = len(scan_hosts)
	metrics = [
		{
			"label": "Achados totais",
			"value": _format_metric_value(total_findings),
			"description": "Somatório de scan, vulnerabilidades e threat hunt.",
			"tone": "neutral",
		},
		{
			"label": "Vulnerabilidades críticas",
			"value": _format_metric_value(critical_total),
			"description": "Classificadas com severidade crítica.",
			"tone": "danger" if critical_total else "neutral",
		},
		{
			"label": "Hosts analisados",
			"value": _format_metric_value(hosts_count),
			"description": "Cobertos pelas execuções de scan consolidadas.",
			"tone": "info",
		},
	]
	if max_cvss is not None:
		metrics.append(
			{
				"label": "Maior CVSS observado",
				"value": _format_metric_value(max_cvss),
				"description": "Pontuação máxima registrada entre os achados.",
				"tone": "warning" if max_cvss and max_cvss >= 9 else "info",
			}
		)
	if indicators_total:
		metrics.append(
			{
				"label": "Indicadores de ameaça",
				"value": _format_metric_value(indicators_total),
				"description": "Artefatos provenientes do módulo de threat hunt.",
				"tone": "neutral",
			}
		)
	return metrics


def _compose_highlights(scan_highlights: list[dict], vuln_summary: dict, totals: dict) -> list[dict]:
	items: list[dict] = []
	for highlight in scan_highlights[:4]:
		if isinstance(highlight, dict):
			items.append(
				{
					"message": highlight.get("message") or str(highlight),
					"tone": highlight.get("level") or "info",
				}
			)
	total_vuln = sum(int(vuln_summary.get("severity", Counter()).get(key, 0)) for key in SEVERITY_ORDER)
	if total_vuln:
		critical = int(vuln_summary.get("severity", Counter()).get("critical", 0))
		items.append(
			{
				"message": f"{critical} vulnerabilidade(s) crítica(s) entre {total_vuln} achados consolidados.",
				"tone": "danger" if critical else "info",
			}
		)
	total_scan = int(totals.get("scan", 0))
	if total_scan:
		items.append(
			{
				"message": f"{total_scan} evidência(s) registrada(s) pelo módulo de scan.",
				"tone": "success",
			}
		)
	return items


def _user_has_access(user, project: Project) -> bool:
	if project.owner_id == user.id:
		return True
	return project.memberships.filter(user=user).exists()


class ReportLandingView(LoginRequiredMixin, TemplateView):
	template_name = "reports/report_placeholder.html"

	def get_template_names(self):  # type: ignore[override]
		if getattr(self, "_use_consolidated_template", False):
			return ["reports/project_consolidated.html"]
		return [self.template_name]

	def get_context_data(self, **kwargs):  # type: ignore[override]
		context = super().get_context_data(**kwargs)
		session = self._resolve_session()
		project = self._resolve_project(session=session)
		project_param = self.request.GET.get("project")
		use_consolidated = bool(project and project_param)
		self._use_consolidated_template = use_consolidated

		if use_consolidated and project:
			consolidated_context = _build_project_consolidated_context(
				request=self.request,
				project=project,
				session=session,
			)
			context.update(consolidated_context)
			return context

		if not project and not session:
			project_listing = _build_project_reports_listing(self.request.user)
			context.update(
				{
					"project_reports_listing": project_listing,
					"project_reports_total": len(project_listing),
					"has_report": bool(project_listing),
				}
			)
			return context

		aggregator = ReportAggregator(project=project, session=session) if project else None
		sections = aggregator.build_sections() if aggregator else {}
		scan_section = sections.get("scan") if sections else None
		scan_entry = scan_section.items[0] if scan_section and scan_section.items else None
		scan_snapshot = scan_entry.payload if scan_entry else (session.report_snapshot if session else {})
		if not isinstance(scan_snapshot, dict):
			scan_snapshot = scan_snapshot or {}
		status_chart = _build_status_chart(scan_snapshot.get("stats", {})) if scan_snapshot else []
		project_report = aggregator.build_project_report() if aggregator else {}
		project_report_payload = project_report.get("payload", {}) if project_report else {}
		project_report_payload_json = (
			json.dumps(project_report_payload, indent=2, ensure_ascii=False)
			if project_report_payload
			else ""
		)
		scan_tasks = scan_snapshot.get("tasks", []) if isinstance(scan_snapshot, dict) else []
		scan_timeline = scan_snapshot.get("timeline", []) if isinstance(scan_snapshot, dict) else []
		scan_findings = scan_snapshot.get("findings", []) if isinstance(scan_snapshot, dict) else []
		scan_summary = scan_snapshot.get("summary", {}) if isinstance(scan_snapshot, dict) else {}
		scan_observations = scan_summary.get("observations") if isinstance(scan_summary, dict) else {}
		scan_targets = scan_snapshot.get("targets", {}) if isinstance(scan_snapshot, dict) else {}
		scan_services = scan_snapshot.get("services", {}) if isinstance(scan_snapshot, dict) else {}
		scan_snapshot_json = json.dumps(scan_snapshot, indent=2, ensure_ascii=False) if scan_snapshot else ""

		consolidated_url = reverse("arpia_report:project_consolidated", args=[project.pk]) if project else None

		context.update(
			{
				"session": session,
				"project": project,
				"sections": sections,
				"scan_section": scan_section,
				"scan_entry": scan_entry,
				"scan_snapshot": scan_snapshot,
				"scan_tasks": scan_tasks,
				"scan_timeline": scan_timeline,
				"scan_findings": scan_findings,
				"scan_summary": scan_summary,
				"scan_observations": scan_observations or {},
				"scan_targets": scan_targets,
				"scan_services": scan_services,
				"scan_snapshot_json": scan_snapshot_json,
				"report_json": scan_snapshot,
				"report_highlights": scan_snapshot.get("insights", []) if isinstance(scan_snapshot, dict) else [],
				"report_stats": scan_snapshot.get("stats", {}) if isinstance(scan_snapshot, dict) else {},
				"report_targets": scan_snapshot.get("targets", {}) if isinstance(scan_snapshot, dict) else {},
				"report_services": scan_snapshot.get("services", {}) if isinstance(scan_snapshot, dict) else {},
				"report_findings": scan_snapshot.get("findings", []) if isinstance(scan_snapshot, dict) else [],
				"status_chart": status_chart,
				"project_report": project_report,
				"project_report_payload_json": project_report_payload_json,
				"has_report": bool(scan_snapshot) or any(section.items for section in sections.values()) if sections else bool(scan_snapshot),
				"consolidated_report_url": consolidated_url,
			}
		)
		return context

	def _resolve_session(self) -> ScanSession | None:
		session_id = self.request.GET.get("session")
		if not session_id:
			return None

		session = get_object_or_404(
			ScanSession.objects.select_related("project", "owner"),
			pk=session_id,
		)

		if not _user_has_access(self.request.user, session.project):
			raise Http404("Sessão não encontrada")

		return session

	def _resolve_project(self, session: ScanSession | None = None) -> Project | None:
		if session:
			return session.project
		project_id = self.request.GET.get("project")
		if not project_id:
			return None
		project = get_object_or_404(Project, pk=project_id)
		if not _user_has_access(self.request.user, project):
			raise Http404("Projeto não encontrado")
		return project


@login_required
@require_http_methods(["GET"])
def api_session_report(request, pk):
	session = get_object_or_404(
		ScanSession.objects.select_related("project", "owner"),
		pk=pk,
	)
	if not _user_has_access(request.user, session.project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
	report = session.report_snapshot or {}
	aggregator = ReportAggregator(project=session.project, session=session)
	sections = _serialize_sections(aggregator.build_sections())
	project_report = aggregator.build_project_report()
	response = {
		"session": {
			"id": str(session.pk),
			"reference": session.reference,
			"title": session.title,
			"status": session.status,
		},
		"project": {
			"id": str(session.project.pk),
			"name": session.project.name,
			"slug": session.project.slug,
		},
		"report": report,
		"sections": sections,
		"project_report": project_report,
	}
	return JsonResponse(response, json_dumps_params={"ensure_ascii": False, "indent": 2})


@login_required
@require_http_methods(["GET"])
def api_project_report(request, pk):
	project = get_object_or_404(Project.objects.select_related("owner"), pk=pk)
	if not _user_has_access(request.user, project):
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	aggregator = ReportAggregator(project=project)
	sections = _serialize_sections(aggregator.build_sections())
	project_report = aggregator.build_project_report()

	return JsonResponse(
		{
			"project": {
				"id": str(project.pk),
				"name": project.name,
				"slug": project.slug,
			},
			"sections": sections,
			"project_report": project_report,
		}
	)


def _serialize_sections(sections: dict[str, SectionData]) -> dict[str, Any]:
	serialized: dict[str, Any] = {}
	for key, section in sections.items():
		serialized[key] = {
			"key": section.key,
			"label": section.label,
			"description": section.description,
			"empty_text": section.empty_text,
			"items": [
				{
					"title": item.title,
					"summary": item.summary,
					"payload": item.payload,
					"metadata": item.metadata,
					"link": item.link,
				}
				for item in section.items
			],
		}
	return serialized


def _build_status_chart(stats: dict | None) -> list[dict[str, Any]]:
	stats = stats or {}
	status_counts = stats.get("status_counts") or {}
	if not status_counts:
		return []
	total = sum(int(value) for value in status_counts.values()) or 1
	chart: list[dict[str, Any]] = []
	for key, count in status_counts.items():
		try:
			label = ScanTask.Status(key).label
		except ValueError:
			label = key.replace("_", " ").title()
		percentage = round((int(count) / total) * 100, 2) if total else 0
		chart.append(
			{
				"key": key,
				"label": label,
				"count": int(count),
				"percentage": percentage,
			}
		)
	return sorted(chart, key=lambda item: item["count"], reverse=True)


def _as_list(value: Any) -> list:
	if not value:
		return []
	if isinstance(value, list):
		return value
	if isinstance(value, tuple):
		return list(value)
	return [value]


def _split_macro_values(value: Any) -> list[str]:
	if not value:
		return []
	if isinstance(value, (list, tuple, set)):
		return [str(item).strip() for item in value if str(item).strip()]
	if isinstance(value, str):
		tokens = value.replace(";", "\n").replace(",", "\n").splitlines()
		return [token.strip() for token in tokens if token.strip()]
	return [str(value).strip()]


def _normalize_timeline(timeline: Any) -> list[dict[str, Any]]:
	items: list[dict[str, Any]] = []
	for entry in _as_list(timeline):
		if isinstance(entry, dict):
			items.append(entry)
	return items


def _first_section_item(section: SectionData | None):
	if not section or not section.items:
		return None
	return section.items[0]


def _collect_hosts(targets: dict[str, Any]) -> list[str]:
	hosts: list[str] = []
	if not isinstance(targets, dict):
		return hosts

	candidate_hosts = targets.get("hosts") or targets.get("host_list")
	hosts.extend(_split_macro_values(candidate_hosts))

	for network in _as_list(targets.get("networks")):
		if isinstance(network, str):
			hosts.append(network.strip())
	return [host for host in hosts if host]


def _collect_vuln_findings(items: Iterable) -> list[dict[str, Any]]:
	findings: list[dict[str, Any]] = []
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		for finding in _as_list(payload.get("findings")):
			if isinstance(finding, dict):
				findings.append(finding)
	return findings


def _collect_vuln_severity(items: Iterable) -> dict[str, int]:
	severity_counts: dict[str, int] = {}
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		summary = payload.get("summary") or {}
		for severity, value in (summary.get("severity") or {}).items():
			severity_counts[severity] = severity_counts.get(severity, 0) + int(value)
	return severity_counts


def _collect_cves(items: Iterable) -> list[str]:
	codes: set[str] = set()
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		summary = payload.get("summary") or {}
		for cve in _as_list(summary.get("cves")):
			if isinstance(cve, str) and cve.strip():
				codes.add(cve.strip())
		for finding in _as_list(payload.get("findings")):
			if not isinstance(finding, dict):
				continue
			candidate = finding.get("cve")
			if isinstance(candidate, str) and candidate.strip():
				codes.add(candidate.strip())
			for extra in _as_list(finding.get("cves")):
				if isinstance(extra, str) and extra.strip():
					codes.add(extra.strip())
	return sorted(codes)


def _collect_hunt_indicators(items: Iterable) -> list[dict[str, Any]]:
	indicators: list[dict[str, Any]] = []
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		for indicator in _as_list(payload.get("indicators")):
			if isinstance(indicator, dict):
				indicators.append(indicator)
			elif indicator:
				indicators.append({"indicator": indicator})
	return indicators


def _collect_hunt_notes(items: Iterable) -> list[str]:
	notes: list[str] = []
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		for note in _as_list(payload.get("notes")):
			if isinstance(note, str) and note.strip():
				notes.append(note.strip())
		intel_summary = getattr(item, "summary", "")
		if intel_summary:
			notes.append(intel_summary)
	return notes


def _collect_hunt_artifacts(items: Iterable) -> list[dict[str, Any]]:
	artifacts: list[dict[str, Any]] = []
	for item in items or []:
		payload = getattr(item, "payload", {}) or {}
		for artifact in _as_list(payload.get("artifacts")):
			if isinstance(artifact, dict):
				artifacts.append(artifact)
	return artifacts


def _build_project_reports_listing(user) -> list[dict[str, Any]]:
	if not getattr(user, "is_authenticated", False):
		return []

	if getattr(user, "is_superuser", False):
		projects_qs = Project.objects.all()
	else:
		projects_qs = Project.objects.filter(Q(owner=user) | Q(memberships__user=user))

	projects = (
		projects_qs.select_related("owner")
		.prefetch_related("memberships__user")
		.distinct()
		.order_by("name")
	)

	listing: list[dict[str, Any]] = []
	for project in projects:
		aggregator = ReportAggregator(project=project)
		sections = aggregator.build_sections()
		project_report = aggregator.build_project_report()
		findings_totals = aggregator.collect_findings_summary()

		scan_section = sections.get("scan") if sections else None
		scan_item = _first_section_item(scan_section)
		scan_payload: dict[str, Any] = dict(getattr(scan_item, "payload", {}) or {}) if scan_item else {}
		scan_metadata = dict(getattr(scan_item, "metadata", {}) or {}) if scan_item else {}
		scan_status = scan_metadata.get("status")
		scan_status_label = None
		if scan_status:
			try:
				scan_status_label = ScanTask.Status(scan_status).label
			except ValueError:
				scan_status_label = str(scan_status).replace("_", " ").title()

		scan_stats = scan_payload.get("stats") or {}
		scan_summary = scan_payload.get("summary") or {}
		scan_findings_total = len(_as_list(scan_payload.get("findings")))
		scan_finished_at = (
			scan_metadata.get("finished_at")
			or scan_summary.get("finished_at")
			or project_report.get("generated_at") if isinstance(project_report, dict) else None
		)

		vuln_section = sections.get("vuln") if sections else None
		vuln_items = list(vuln_section.items) if vuln_section else []
		vuln_findings = _collect_vuln_findings(vuln_items)
		vuln_severity = _collect_vuln_severity(vuln_items)

		hunt_section = sections.get("hunt") if sections else None
		hunt_items = list(hunt_section.items) if hunt_section else []
		hunt_indicators = _collect_hunt_indicators(hunt_items)
		hunt_notes = _collect_hunt_notes(hunt_items)

		has_report = bool(scan_payload) or any(section.items for section in sections.values()) if sections else bool(scan_payload)

		listing.append(
			{
				"project": project,
				"project_report": project_report,
				"findings_totals": findings_totals,
				"consolidated_url": reverse("arpia_report:project_consolidated", args=[project.pk]),
				"scan_status": scan_status,
				"scan_status_label": scan_status_label,
				"scan_stats": scan_stats,
				"scan_summary": scan_summary,
				"scan_findings_total": scan_findings_total,
				"scan_last_run": scan_finished_at,
				"vuln_findings_total": len(vuln_findings),
				"vuln_severity": vuln_severity,
				"hunt_indicators_total": len(hunt_indicators),
				"hunt_notes_total": len(hunt_notes),
				"has_report": has_report,
				"generated_at": project_report.get("generated_at") if isinstance(project_report, dict) else None,
			}
		)

	return listing


def _build_project_consolidated_context(*, request, project: Project, session: ScanSession | None) -> dict[str, Any]:
	aggregator = ReportAggregator(project=project, session=session)
	sections = aggregator.build_sections()
	project_report = aggregator.build_project_report()
	project_report_payload = project_report.get("payload", {}) if project_report else {}
	project_report_payload_json = (
		json.dumps(project_report_payload, indent=2, ensure_ascii=False)
		if project_report_payload
		else ""
	)

	scan_section = sections.get("scan")
	scan_item = _first_section_item(scan_section)
	scan_payload: dict[str, Any] = dict(getattr(scan_item, "payload", {}) or {}) if scan_item else {}
	if not scan_payload and session and isinstance(session.report_snapshot, dict):
		scan_payload = session.report_snapshot or {}
	scan_metadata = dict(getattr(scan_item, "metadata", {}) or {}) if scan_item else {}
	scan_summary = scan_payload.get("summary") or {}
	scan_targets = scan_payload.get("targets") or {}
	scan_services = scan_payload.get("services") or {}
	scan_stats = scan_payload.get("stats") or {}
	scan_timing = scan_payload.get("timing") or {}
	scan_tasks = scan_payload.get("tasks", []) if isinstance(scan_payload, dict) else []
	scan_timeline = _normalize_timeline(scan_payload.get("timeline"))
	scan_findings = [item for item in _as_list(scan_payload.get("findings")) if isinstance(item, dict)]
	scan_hosts = _collect_hosts(scan_targets)
	scan_highlights = _as_list(scan_payload.get("insights"))
	scan_attachments = [item for item in _as_list(scan_payload.get("artifacts")) if isinstance(item, dict)]
	scan_snapshot_json = json.dumps(scan_payload, indent=2, ensure_ascii=False) if scan_payload else ""
	status_chart = _build_status_chart(scan_stats)
	scan_observations = scan_summary.get("observations") if isinstance(scan_summary, dict) else {}
	processed_scan_hosts, processed_scan_services, total_open_ports = _summarize_scan_payload(scan_summary, scan_services, scan_hosts)
	scan_display_findings = _prepare_scan_findings(scan_findings)

	vuln_section = sections.get("vuln")
	vuln_items = list(vuln_section.items) if vuln_section else []
	vuln_findings = _collect_vuln_findings(vuln_items)
	vuln_severity = _collect_vuln_severity(vuln_items)
	vuln_cves = _collect_cves(vuln_items)
	vuln_overview = _summarize_vuln_findings(vuln_findings, vuln_cves)
	vuln_status_counter: Counter[str] = vuln_overview.get("status", Counter())
	vuln_open_total = sum(vuln_status_counter.get(key, 0) for key in OPEN_STATUS_KEYS)
	vuln_resolved_total = sum(vuln_status_counter.get(key, 0) for key in RESOLVED_STATUS_KEYS)
	vuln_tracking = {
		"open_total": vuln_open_total,
		"resolved_total": vuln_resolved_total,
		"status_counter": vuln_status_counter,
	}

	hunt_section = sections.get("hunt")
	hunt_items = list(hunt_section.items) if hunt_section else []
	hunt_indicators = _collect_hunt_indicators(hunt_items)
	hunt_notes = _collect_hunt_notes(hunt_items)
	hunt_artifacts = _collect_hunt_artifacts(hunt_items)
	hunt_key_metrics = [
		{"label": "Indicadores coletados", "value": _format_metric_value(len(hunt_indicators))},
		{"label": "Notas de inteligência", "value": _format_metric_value(len(hunt_notes))},
		{"label": "Artefatos anexos", "value": _format_metric_value(len(hunt_artifacts))},
	]

	macros = build_project_macros(request.user, project)
	macro_hosts = _split_macro_values(macros.get("TARGET_HOSTS"))
	macro_networks = _split_macro_values(macros.get("TARGET_NETWORKS"))
	macro_ports = _split_macro_values(macros.get("TARGET_PORTS"))
	protected_hosts = _split_macro_values(macros.get("PROTECTED_HOSTS"))
	credential_table = macros.get("CREDENTIALS_TABLE") or []

	assets = list(project.assets.all())
	memberships = list(project.memberships.select_related("user"))
	generated_at = timezone.now()
	findings_totals = aggregator.collect_findings_summary()
	consolidated_url = reverse("arpia_report:project_consolidated", args=[project.pk])
	has_report = bool(scan_payload) or any(section.items for section in sections.values())
	executive_overview = _build_executive_overview(
		totals=findings_totals,
		severity=vuln_overview.get("severity", Counter()),
		scan_hosts=scan_hosts,
		max_cvss=vuln_overview.get("max_cvss"),
		indicators_total=len(hunt_indicators),
	)
	executive_highlights = _compose_highlights(scan_highlights, vuln_overview, findings_totals)
	scan_key_metrics = [
		{"label": "Tarefas executadas", "value": _format_metric_value(scan_stats.get("total_tasks"))},
		{"label": "Hosts alcançados", "value": _format_metric_value(len(scan_hosts))},
		{"label": "Portas abertas", "value": _format_metric_value(total_open_ports)},
		{"label": "Achados registrados", "value": _format_metric_value(scan_stats.get("total_findings") or len(scan_findings))},
	]
	vuln_key_metrics = [
		{"label": "Achados consolidados", "value": _format_metric_value(len(vuln_findings))},
		{"label": "Abertos", "value": _format_metric_value(vuln_open_total)},
		{"label": "Fechados", "value": _format_metric_value(vuln_resolved_total)},
		{"label": "CVEs correlacionadas", "value": _format_metric_value(vuln_overview.get("unique_cves_total"))},
	]

	context: dict[str, Any] = {
		"project": project,
		"session": session,
		"sections": sections,
		"scan_section": scan_section,
		"scan_entry": scan_item,
		"scan_snapshot": scan_payload,
		"scan_payload": scan_payload,
		"scan_metadata": scan_metadata,
		"scan_tasks": scan_tasks,
		"scan_timeline": scan_timeline,
		"scan_findings": scan_findings,
		"scan_summary": scan_summary,
		"scan_stats": scan_stats,
		"scan_timing": scan_timing,
		"scan_observations": scan_observations or {},
		"scan_targets": scan_targets,
		"scan_services": scan_services,
		"scan_hosts": scan_hosts,
		"scan_highlights": scan_highlights,
		"scan_attachments": scan_attachments,
		"scan_snapshot_json": scan_snapshot_json,
		"scan_host_entries": processed_scan_hosts,
		"scan_service_entries": processed_scan_services,
		"scan_display_findings": scan_display_findings,
		"report_json": scan_payload,
		"report_highlights": scan_highlights,
		"report_stats": scan_stats,
		"report_targets": scan_targets,
		"report_services": scan_services,
		"report_findings": scan_findings,
		"status_chart": status_chart,
		"project_report": project_report,
		"project_report_payload_json": project_report_payload_json,
		"project_report_payload": project_report_payload,
		"has_report": has_report,
		"generated_at": generated_at,
		"vuln_items": vuln_items,
		"vuln_findings": vuln_findings,
		"vuln_severity": vuln_severity,
		"vuln_cves": vuln_cves,
		"vuln_overview": vuln_overview,
		"vuln_display_findings": vuln_overview.get("entries", []),
		"vuln_severity_breakdown": vuln_overview.get("severity_breakdown", []),
		"vuln_top_hosts": vuln_overview.get("top_hosts", []),
		"vuln_top_services": vuln_overview.get("top_services", []),
		"vuln_status_overview": vuln_tracking,
		"hunt_items": hunt_items,
		"hunt_indicators": hunt_indicators,
		"hunt_notes": hunt_notes,
		"hunt_artifacts": hunt_artifacts,
		"hunt_key_metrics": hunt_key_metrics,
		"macros": macros,
		"macro_hosts": macro_hosts,
		"macro_networks": macro_networks,
		"macro_ports": macro_ports,
		"protected_hosts": protected_hosts,
		"credential_table": credential_table,
		"assets": assets,
		"memberships": memberships,
		"findings_totals": findings_totals,
		"consolidated_report_url": consolidated_url,
		"executive_overview": executive_overview,
		"executive_highlights": executive_highlights,
		"scan_key_metrics": scan_key_metrics,
		"vuln_key_metrics": vuln_key_metrics,
	}
	return context


class ProjectConsolidatedReportView(LoginRequiredMixin, TemplateView):
	template_name = "reports/project_consolidated.html"

	def dispatch(self, request, *args, **kwargs):  # type: ignore[override]
		self.project = get_object_or_404(
			Project.objects.select_related("owner").prefetch_related("assets", "memberships__user"),
			pk=kwargs.get("pk"),
		)
		if not _user_has_access(request.user, self.project):
			raise Http404("Projeto não encontrado")
		return super().dispatch(request, *args, **kwargs)

	def get_context_data(self, **kwargs):  # type: ignore[override]
		context = super().get_context_data(**kwargs)
		context.update(
			_build_project_consolidated_context(
				request=self.request,
				project=self.project,
				session=None,
			)
		)
		return context
