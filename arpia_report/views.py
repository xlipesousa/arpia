import json
import os
import xml.etree.ElementTree as ET
from collections import Counter
from io import BytesIO
from typing import Any, Iterable, Optional

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.contrib.staticfiles import finders
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView
from django.db.models import Q

from arpia_core.models import Project
from arpia_core.views import build_project_macros
from arpia_scan.models import ScanSession, ScanTask
from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .services import ReportAggregator, SectionData


SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
OPEN_STATUS_KEYS = {"open", "new", "ack", "in_progress"}
RESOLVED_STATUS_KEYS = {"resolved", "closed", "remediated", "done"}


def _log_report_event(
	*,
	request,
	component: str,
	event_type: str,
	message: str,
	project: Optional[Project] = None,
	session: Optional[ScanSession] = None,
	severity: str = LogEntry.Severity.INFO,
	details: Optional[dict[str, Any]] = None,
	tags: Optional[Iterable[str]] = None,
) -> None:
	context: dict[str, Any] = {}
	if project is not None:
		context["project"] = {
			"id": str(project.pk),
			"name": project.name,
			"slug": project.slug,
		}
	correlation: dict[str, Any] = {}
	if project is not None:
		correlation["project_id"] = str(project.pk)
	if session is not None:
		context["session"] = {
			"id": str(session.pk),
			"reference": session.reference,
			"status": session.status,
		}
		correlation["scan_session_id"] = str(session.pk)
	details_payload = dict(details or {})
	tags_payload = list(tags or [])
	if "report" not in tags_payload:
		tags_payload.append("report")

	log_event(
		source_app="arpia_report",
		component=component,
		event_type=event_type,
		message=message,
		severity=severity,
		details=details_payload,
		context=context,
		correlation=correlation,
		tags=tags_payload,
		request=request,
	)


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


def _format_datetime_local(value) -> str:
	if not value:
		return "—"
	try:
		localized = timezone.localtime(value)
	except Exception:
		return str(value)
	return localized.strftime("%d/%m/%Y %H:%M")


def _coerce_string(value: Any, empty_placeholder: str = "—") -> str:
	if value is None:
		return empty_placeholder
	if isinstance(value, (list, tuple, set)):
		items = [str(item).strip() for item in value if str(item).strip()]
		return ", ".join(items) if items else empty_placeholder
	text = str(value).strip()
	return text or empty_placeholder


def _extract_nmap_os_map(artifacts: Any) -> dict[str, str]:
	if not isinstance(artifacts, dict):
		return {}
	xml_blob = artifacts.get("nmap")
	if isinstance(xml_blob, dict):
		xml_blob = xml_blob.get("content") or xml_blob.get("data") or xml_blob.get("value")
	if isinstance(xml_blob, bytes):
		xml_blob = xml_blob.decode("utf-8", errors="ignore")
	if not isinstance(xml_blob, str):
		xml_blob = str(xml_blob) if xml_blob is not None else ""
	xml_blob = xml_blob.strip()
	if not xml_blob:
		return {}
	try:
		root = ET.fromstring(xml_blob)
	except ET.ParseError:
		return {}
	host_map: dict[str, str] = {}
	for host in root.findall("host"):
		identifiers: list[str] = []
		for addr_node in host.findall("address"):
			addr = (addr_node.get("addr") or "").strip()
			if addr:
				identifiers.append(addr)
		for hostname_node in host.findall("hostnames/hostname"):
			name = (hostname_node.get("name") or "").strip()
			if name:
				identifiers.append(name)
		if not identifiers:
			continue
		best_label: str | None = None
		best_accuracy = -1
		for osmatch in host.findall("os/osmatch"):
			name = (osmatch.get("name") or "").strip()
			try:
				accuracy = int(osmatch.get("accuracy") or 0)
			except (TypeError, ValueError):
				accuracy = 0
			if name and accuracy >= best_accuracy:
				best_label = name
				best_accuracy = accuracy
		if not best_label:
			for osclass in host.findall("os/osclass"):
				family = (osclass.get("osfamily") or osclass.get("type") or "").strip()
				generation = (osclass.get("osgen") or "").strip()
				if family:
					label = f"{family} {generation}".strip()
					if label:
						best_label = label
						break
		if not best_label:
			continue
		for identifier in identifiers:
			if not identifier:
				continue
			if identifier not in host_map:
				host_map[identifier] = best_label
			lower_id = identifier.lower()
			if lower_id not in host_map:
				host_map[lower_id] = best_label
	return host_map


def _wrap_text(text: str, font: str, size: int, max_width: float) -> list[str]:
	if text is None:
		return [""]
	try:
		from reportlab.pdfbase import pdfmetrics
	except ImportError:
		return [str(text)]
	words = str(text).split()
	if not words:
		return [""]
	lines: list[str] = []
	current = ""
	for word in words:
		candidate = f"{current} {word}".strip()
		width = pdfmetrics.stringWidth(candidate, font, size)
		if width <= max_width or not current:
			current = candidate
		else:
			lines.append(current)
			current = word
	if current:
		lines.append(current)
	return lines or [""]


class _PdfCanvasWriter:
	def __init__(
		self,
		canvas,
		*,
		width: float,
		height: float,
		margin: float,
		header_title: str,
		header_right: str,
		footer_left: str,
		header_logo_path: str | None = None,
		header_logo_width: float | None = None,
		header_logo_height: float | None = None,
	):
		self.canvas = canvas
		self.width = width
		self.height = height
		self.margin = margin
		self.header_title = header_title
		self.header_right = header_right
		self.footer_left = footer_left
		self.header_logo_path = header_logo_path
		self.header_logo_width = header_logo_width or 0
		self.header_logo_height = header_logo_height or 0
		self.body_font = "Helvetica"
		self.body_size = 10
		self.heading_font = "Helvetica-Bold"
		self.heading_sizes = {1: 16, 2: 13, 3: 11}
		self.line_height = 14
		self.bullet_indent = self.margin + 14
		self.page_number = 1
		self._new_page(initial=True)

	def _new_page(self, *, initial: bool = False) -> None:
		if not initial:
			self._draw_footer()
			self.canvas.showPage()
			self.page_number += 1
		self.canvas.setFont(self.heading_font, 12)
		header_x = self.margin
		if self.header_logo_path and self.header_logo_width and self.header_logo_height:
			try:
				self.canvas.drawImage(
					self.header_logo_path,
					x=self.margin,
					y=self.height - self.margin + 6 - self.header_logo_height,
					width=self.header_logo_width,
					height=self.header_logo_height,
					preserveAspectRatio=True,
					mask="auto",
				)
				header_x += self.header_logo_width + 6
			except Exception:
				self.header_logo_path = None
		if self.header_title:
			self.canvas.drawString(header_x, self.height - self.margin + 6, self.header_title)
		if self.header_right:
			self.canvas.setFont(self.body_font, 9)
			right_width = self.canvas.stringWidth(self.header_right, self.body_font, 9)
			self.canvas.drawString(self.width - self.margin - right_width, self.height - self.margin + 6, self.header_right)
		self.y = self.height - self.margin - 30

	def _draw_footer(self) -> None:
		self.canvas.setFont(self.body_font, 9)
		if self.footer_left:
			self.canvas.drawString(self.margin, self.margin - 10, self.footer_left)
		page_label = f"Página {self.page_number}"
		page_width = self.canvas.stringWidth(page_label, self.body_font, 9)
		self.canvas.drawString(self.width - self.margin - page_width, self.margin - 10, page_label)

	def _ensure_space(self, lines: float = 1.0, extra: float = 0.0) -> None:
		required = lines * self.line_height + extra
		if self.y - required < self.margin + 20:
			self._new_page()

	def _advance(self, lines: float = 1.0) -> None:
		self.y -= self.line_height * lines
		if self.y < self.margin + 20:
			self._new_page()

	def draw_centered_image(self, path: str, *, width: float, height: float, spacing_after: float = 18.0) -> None:
		if not path or not width or not height:
			return
		required = float(height) + float(spacing_after)
		self._ensure_space(extra=required)
		x = (self.width - width) / 2
		y = self.y - height
		try:
			self.canvas.drawImage(
				path,
				x=x,
				y=y,
				width=width,
				height=height,
				preserveAspectRatio=True,
				mask="auto",
			)
		except Exception:
			return
		self.y = y - spacing_after
		if self.y < self.margin + 20:
			self._new_page()

	def draw_heading(self, text: str, *, level: int = 1) -> None:
		if not text:
			return
		size = self.heading_sizes.get(level, self.heading_sizes[3])
		self._ensure_space(1.5)
		self.canvas.setFont(self.heading_font, size)
		self.canvas.drawString(self.margin, self.y, text)
		self._advance(1.2 if level == 1 else 1.0)

	def _write_wrapped(self, text: str, *, x: float, font: str, size: int) -> int:
		lines = _wrap_text(text, font, size, self.width - x - self.margin)
		self._ensure_space(len(lines))
		self.canvas.setFont(font, size)
		for line in lines:
			self.canvas.drawString(x, self.y, line)
			self._advance()
		return len(lines)

	def draw_paragraph(self, text: str) -> None:
		if not text:
			return
		self._write_wrapped(text, x=self.margin, font=self.body_font, size=self.body_size)
		self._advance(0.3)

	def draw_bullet_list(self, items: Iterable[str]) -> None:
		entries = [entry for entry in items if entry]
		if not entries:
			return
		for entry in entries:
			lines = _wrap_text(entry, self.body_font, self.body_size, self.width - self.bullet_indent - self.margin)
			self._ensure_space(len(lines))
			self.canvas.setFont(self.body_font, self.body_size)
			self.canvas.drawString(self.margin, self.y, "•")
			self.canvas.drawString(self.bullet_indent, self.y, lines[0])
			self._advance()
			for line in lines[1:]:
				self.canvas.drawString(self.bullet_indent, self.y, line)
				self._advance()
			self._advance(0.2)
		self._advance(0.3)

	def draw_key_value_block(self, entries: Iterable[tuple[str, Any]]) -> None:
		rows = [(label, _coerce_string(value)) for label, value in entries if value not in (None, "")]
		if not rows:
			return
		for label, value in rows:
			label_text = f"{label}: "
			label_width = self.canvas.stringWidth(label_text, self.heading_font, self.body_size)
			max_width = max(self.width - self.margin - label_width - self.margin, 120)
			value_lines = _wrap_text(value, self.body_font, self.body_size, max_width)
			required_lines = max(1, len(value_lines))
			self._ensure_space(required_lines)
			self.canvas.setFont(self.heading_font, self.body_size)
			self.canvas.drawString(self.margin, self.y, label_text)
			self.canvas.setFont(self.body_font, self.body_size)
			x_value = self.margin + label_width
			if value_lines:
				self.canvas.drawString(x_value, self.y, value_lines[0])
			for line in value_lines[1:]:
				self._advance()
				self.canvas.drawString(x_value, self.y, line)
			self._advance()
			self._advance(0.1)

	def draw_signature_line(self, label: str) -> None:
		self._ensure_space(2, extra=10)
		self.canvas.line(self.margin, self.y, self.width - self.margin, self.y)
		self._advance(0.5)
		self.canvas.setFont(self.body_font, self.body_size)
		self.canvas.drawString(self.margin, self.y, label)
		self._advance(1.5)

	def finish(self) -> None:
		self._draw_footer()
		self.canvas.save()


def _summarize_scan_payload(scan_summary: dict, scan_services: dict, scan_hosts: list[str]) -> tuple[list[dict], list[dict], int]:
	artifacts: Any = {}
	if isinstance(scan_summary, dict):
		artifacts = scan_summary.get("artifacts", {}) or {}
	if not isinstance(artifacts, dict):
		artifacts = {}
	connectivity_entries = artifacts.get("connectivity") if isinstance(artifacts, dict) else []
	nmap_os_map = _extract_nmap_os_map(artifacts)
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
		os_guess = ""
		if host:
			os_guess = nmap_os_map.get(host) or nmap_os_map.get(host.lower(), "")
		if not os_guess and ports:
			first_port = ports[0]
			if isinstance(first_port, dict):
				addr = (first_port.get("host") or first_port.get("ip") or "").strip()
				if addr:
					os_guess = nmap_os_map.get(addr) or nmap_os_map.get(addr.lower(), "")
		resolved_host = host or (
			scan_hosts[0] if not host and scan_hosts else ""
		)
		if not os_guess and resolved_host:
			os_guess = nmap_os_map.get(resolved_host) or nmap_os_map.get(resolved_host.lower(), "")
		host_entries.append(
			{
				"host": resolved_host,
				"reachable": reachable,
				"open_ports": open_ports,
				"closed_ports": closed_ports,
				"notes": entry.get("notes") or entry.get("error") or "",
				"operating_system": os_guess or "",
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
			_log_report_event(
				request=self.request,
				component="ui.landing",
				event_type="report.project.consolidated.view",
				message="Usuário visualizou o relatório consolidado do projeto.",
				project=project,
				session=session,
				details={
					"has_session_filter": bool(session),
					"has_report": bool(consolidated_context.get("has_report")),
					"scan_findings": len(consolidated_context.get("scan_findings", []) or []),
					"vuln_findings": len(consolidated_context.get("vuln_findings", []) or []),
					"hunt_indicators": len(consolidated_context.get("hunt_indicators", []) or []),
				},
			)
			context.update(consolidated_context)
			return context

		if not project and not session:
			project_listing = _build_project_reports_listing(self.request.user)
			_log_report_event(
				request=self.request,
				component="ui.landing",
				event_type="report.landing.list",
				message="Usuário acessou a listagem de relatórios disponíveis.",
				details={"projects_available": len(project_listing)},
			)
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
		_log_report_event(
			request=self.request,
			component="ui.landing",
			event_type="report.session.view" if session else "report.project.view",
			message="Usuário acessou o painel de relatório consolidado em modo detalhado.",
			project=project,
			session=session,
			details={
				"sections_total": len(sections or {}),
				"scan_findings": len(scan_findings or []),
				"status_chart_points": len(status_chart or []),
				"report_payload": bool(project_report_payload_json),
			},
		)

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
			_log_report_event(
				request=self.request,
				component="ui.landing",
				event_type="report.session.access.denied",
				message="Usuário não possui acesso ao relatório de sessão solicitado.",
				project=session.project,
				session=session,
				severity=LogEntry.Severity.WARNING,
				details={"requested_session_id": str(session.pk)},
			)
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
			_log_report_event(
				request=self.request,
				component="ui.landing",
				event_type="report.project.access.denied",
				message="Usuário não possui acesso ao relatório do projeto solicitado.",
				project=project,
				severity=LogEntry.Severity.WARNING,
				details={"requested_project_id": str(project.pk)},
			)
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
		_log_report_event(
			request=request,
			component="api.session",
			event_type="report.session.api.denied",
			message="Usuário sem permissão tentou acessar relatório de sessão via API.",
			project=session.project,
			session=session,
			severity=LogEntry.Severity.WARNING,
			details={"requested_session_id": str(session.pk)},
		)
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
	_log_report_event(
		request=request,
		component="api.session",
		event_type="report.session.api.success",
		message="Relatório de sessão entregue via API.",
		project=session.project,
		session=session,
		details={
			"sections_total": len(sections or {}),
			"report_keys": list(sorted(report.keys())) if isinstance(report, dict) else [],
		},
	)
	return JsonResponse(response, json_dumps_params={"ensure_ascii": False, "indent": 2})


@login_required
@require_http_methods(["GET"])
def api_project_report(request, pk):
	project = get_object_or_404(Project.objects.select_related("owner"), pk=pk)
	if not _user_has_access(request.user, project):
		_log_report_event(
			request=request,
			component="api.project",
			event_type="report.project.api.denied",
			message="Usuário sem permissão tentou acessar relatório de projeto via API.",
			project=project,
			severity=LogEntry.Severity.WARNING,
			details={"requested_project_id": str(project.pk)},
		)
		return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

	aggregator = ReportAggregator(project=project)
	sections = _serialize_sections(aggregator.build_sections())
	project_report = aggregator.build_project_report()

	_log_report_event(
		request=request,
		component="api.project",
		event_type="report.project.api.success",
		message="Relatório de projeto entregue via API.",
		project=project,
		details={
			"sections_total": len(sections or {}),
			"has_project_report": bool(project_report),
		},
	)
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
	operating_system_map: dict[str, dict[str, Any]] = {}
	for host_entry in processed_scan_hosts:
		os_label = (host_entry.get("operating_system") or "").strip()
		host_identifier = (host_entry.get("host") or "").strip() or "—"
		if not os_label:
			continue
		record = operating_system_map.setdefault(
			os_label,
			{"label": os_label, "count": 0, "hosts": []},
		)
		record["count"] += 1
		if host_identifier not in record["hosts"]:
			record["hosts"].append(host_identifier)
	scan_operating_systems = sorted(
		operating_system_map.values(),
		key=lambda item: (-item.get("count", 0), item.get("label", "")),
	)
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
		"scan_item": scan_item,
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
		"scan_operating_systems": scan_operating_systems,
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


def _build_project_consolidated_pdf(*, project: Project, context: dict[str, Any], user) -> bytes:
	try:
		from reportlab.lib.pagesizes import A4
		from reportlab.lib.units import cm
		from reportlab.lib.utils import ImageReader
		from reportlab.pdfgen import canvas
	except ImportError as exc:
		raise RuntimeError(
			"Dependência opcional 'reportlab' ausente. Instale-a para habilitar exportação em PDF."
		) from exc

	buffer = BytesIO()
	pdf = canvas.Canvas(buffer, pagesize=A4)
	width, height = A4
	margin = 2 * cm
	generated_at = context.get("generated_at") or timezone.now()
	generated_at_str = _format_datetime_local(generated_at)
	client_name = _coerce_string(getattr(project, "client_name", ""))
	logo_path: str | None = None
	logo_width: float | None = None
	logo_height: float | None = None
	logo_candidates = ["img/logo.png", "img/logo-40x40.png"]
	for candidate in logo_candidates:
		found = finders.find(candidate)
		if found:
			logo_path = found
			break
	if not logo_path:
		static_dirs = list(getattr(settings, "STATICFILES_DIRS", []))
		static_root = getattr(settings, "STATIC_ROOT", None)
		if static_root:
			static_dirs.append(static_root)
		for base in static_dirs:
			if not base:
				continue
			for candidate in logo_candidates:
				candidate_path = os.path.join(base, candidate)
				if os.path.exists(candidate_path):
					logo_path = candidate_path
					break
			if logo_path:
				break
	if logo_path:
		try:
			image = ImageReader(logo_path)
			iw, ih = image.getSize()
			if iw and ih:
				logo_height = 2.2 * cm
				logo_width = (iw / ih) * logo_height
		except Exception:
			logo_path = None
	header_title = "ARPIA · Relatório Consolidado"
	header_right = f"Gerado em {generated_at_str}"
	footer_left = f"Projeto: {project.name} · Cliente: {client_name}"
	writer = _PdfCanvasWriter(
		pdf,
		width=width,
		height=height,
		margin=margin,
		header_title=header_title,
		header_right=header_right,
		footer_left=footer_left,
		header_logo_path=None,
		header_logo_width=None,
		header_logo_height=None,
	)

	if logo_path and logo_width and logo_height:
		writer.draw_centered_image(
			logo_path,
			width=logo_width,
			height=logo_height,
			spacing_after=24.0,
		)

	owner_name = project.owner_display if hasattr(project, "owner_display") else _coerce_string(project.owner)
	responsible_user = getattr(user, "get_full_name", lambda: "")() or user.get_username()
	project_description = getattr(project, "description", "")

	writer.draw_heading("Relatório Executivo Consolidado", level=1)
	writer.draw_paragraph(f"Projeto: {project.name}")
	if client_name and client_name != "—":
		writer.draw_paragraph(f"Cliente: {client_name}")
	writer.draw_paragraph(f"Responsável do projeto: {owner_name}")
	writer.draw_paragraph(f"Data de geração: {generated_at_str}")
	if project_description:
		writer.draw_paragraph(f"Descrição: {project_description}")

	executive_overview = context.get("executive_overview") or []
	if executive_overview:
		writer.draw_heading("Indicadores consolidados", level=2)
		metrics_lines: list[str] = []
		for metric in executive_overview:
			label = metric.get("label") or "Indicador"
			value = metric.get("value")
			description = metric.get("description")
			line = f"{label}: {value}"
			if description:
				line += f" — {description}"
			metrics_lines.append(line)
		writer.draw_bullet_list(metrics_lines)

	executive_highlights = context.get("executive_highlights") or []
	if executive_highlights:
		writer.draw_heading("Destaques executivos", level=2)
		highlight_lines: list[str] = []
		for item in executive_highlights[:8]:
			if isinstance(item, dict):
				message = item.get("message") or item.get("text")
			else:
				message = str(item)
			if message:
				highlight_lines.append(message)
		writer.draw_bullet_list(highlight_lines)

	writer.draw_heading("Dados do projeto", level=2)
	project_entries = [
		("Cliente", client_name),
		("Status", project.get_status_display() if hasattr(project, "get_status_display") else getattr(project, "status", "—")),
		("Início previsto", _format_datetime_local(getattr(project, "start_at", None))),
		("Término previsto", _format_datetime_local(getattr(project, "end_at", None))),
		("Gerado em", generated_at_str),
	]
	writer.draw_key_value_block(project_entries)

	memberships = context.get("memberships") or []
	team_members = [f"{owner_name} (Owner)"]
	for membership in memberships:
		user_obj = getattr(membership, "user", None)
		if not user_obj or user_obj == project.owner:
			continue
		member_name = getattr(user_obj, "get_full_name", lambda: "")() or user_obj.get_username()
		role_label = getattr(membership, "get_role_display", lambda: getattr(membership, "role", ""))()
		team_members.append(f"{member_name} ({role_label})")
	if team_members:
		writer.draw_paragraph("Equipe envolvida:")
		writer.draw_bullet_list(team_members)

	findings_totals = context.get("findings_totals") or {}
	if findings_totals:
		writer.draw_heading("Totais de artefatos consolidados", level=3)
		totals_lines = [f"{label.title()}: {value}" for label, value in findings_totals.items()]
		writer.draw_bullet_list(totals_lines)

	project_report = context.get("project_report") or {}
	if isinstance(project_report, dict) and project_report.get("summary"):
		writer.draw_paragraph(f"Resumo executivo: {project_report['summary']}")

	scan_key_metrics = context.get("scan_key_metrics") or []
	vuln_key_metrics = context.get("vuln_key_metrics") or []
	hunt_key_metrics = context.get("hunt_key_metrics") or []
	if scan_key_metrics or vuln_key_metrics or hunt_key_metrics:
		writer.draw_heading("Indicadores por módulo", level=2)
		if scan_key_metrics:
			writer.draw_paragraph("Scan:")
			writer.draw_bullet_list([f"{metric.get('label')}: {metric.get('value')}" for metric in scan_key_metrics])
		if vuln_key_metrics:
			writer.draw_paragraph("Vulnerabilidades:")
			writer.draw_bullet_list([f"{metric.get('label')}: {metric.get('value')}" for metric in vuln_key_metrics])
		if hunt_key_metrics:
			writer.draw_paragraph("Threat Hunt:")
			writer.draw_bullet_list([f"{metric.get('label')}: {metric.get('value')}" for metric in hunt_key_metrics])

	writer.draw_heading("Escopo e restrições", level=2)
	macro_hosts = context.get("macro_hosts") or []
	macro_networks = context.get("macro_networks") or []
	macro_ports = context.get("macro_ports") or []
	protected_hosts = context.get("protected_hosts") or []
	credential_table = context.get("credential_table") or []
	if macro_hosts:
		writer.draw_paragraph("Alvos declarados:")
		writer.draw_bullet_list([str(host) for host in macro_hosts[:12]])
	if macro_networks:
		writer.draw_paragraph("Redes monitoradas:")
		writer.draw_bullet_list([str(network) for network in macro_networks[:10]])
	if macro_ports:
		writer.draw_paragraph("Portas observadas:")
		writer.draw_bullet_list([str(port) for port in macro_ports[:20]])
	if protected_hosts:
		writer.draw_paragraph("Restrições de escopo:")
		writer.draw_bullet_list([str(item) for item in protected_hosts[:10]])
	if credential_table:
		writer.draw_paragraph("Credenciais operacionais:")
		credential_lines: list[str] = []
		for cred in credential_table[:8]:
			if isinstance(cred, dict):
				username = cred.get("username") or "—"
				password = cred.get("password") or "—"
				context_text = cred.get("context") or cred.get("description")
			else:
				username = getattr(cred, "username", "—")
				password = getattr(cred, "password", "—")
				context_text = getattr(cred, "context", None)
			entry = f"Usuário {username} / Senha {password}"
			if context_text:
				entry += f" — {context_text}"
			credential_lines.append(entry)
		writer.draw_bullet_list(credential_lines)

	assets = context.get("assets") or []
	if assets:
		writer.draw_heading("Ativos consolidados", level=2)
		asset_lines: list[str] = []
		for asset in assets[:10]:
			identifier = getattr(asset, "identifier", getattr(asset, "id", "Ativo"))
			name = getattr(asset, "name", "")
			category = getattr(asset, "category", "")
			hostnames = _coerce_string(getattr(asset, "hostnames", []))
			ips = _coerce_string(getattr(asset, "ips", []))
			last_seen = _format_datetime_local(getattr(asset, "last_seen", None) or getattr(asset, "created", None))
			line = f"{identifier}"
			if name:
				line += f" · {name}"
			if category:
				line += f" · Categoria: {category}"
			if hostnames and hostnames != "—":
				line += f" · Hostnames: {hostnames}"
			if ips and ips != "—":
				line += f" · IPs: {ips}"
			line += f" · Última observação: {last_seen}"
			asset_lines.append(line)
		writer.draw_bullet_list(asset_lines)

	writer.draw_heading("Atividades de scan", level=2)
	scan_metadata = context.get("scan_metadata") or {}
	scan_stats = context.get("scan_stats") or {}
	scan_highlights = context.get("scan_highlights") or []
	scan_host_entries = context.get("scan_host_entries") or []
	scan_service_entries = context.get("scan_service_entries") or []
	scan_display_findings = context.get("scan_display_findings") or []
	scan_entry = context.get("scan_entry")
	if scan_entry and not scan_metadata.get("title"):
		scan_metadata = {**scan_metadata, "title": getattr(scan_entry, "title", None)}
	if scan_metadata:
		metadata_entries = [
			("Sessão", scan_metadata.get("title") or scan_metadata.get("reference") or "—"),
			("Status", scan_metadata.get("status") or "—"),
			("Início", _format_datetime_local(scan_metadata.get("started_at"))),
			("Término", _format_datetime_local(scan_metadata.get("finished_at"))),
		]
		writer.draw_key_value_block(metadata_entries)
	if scan_stats:
		stats_lines: list[str] = []
		for key, label in (
			("total_tasks", "Tarefas totais"),
			("completed_tasks", "Etapas concluídas"),
			("failed_tasks", "Falhas"),
			("total_findings", "Achados registrados"),
		):
			if key in scan_stats:
				stats_lines.append(f"{label}: {scan_stats.get(key)}")
		if stats_lines:
			writer.draw_bullet_list(stats_lines)
	scan_operating_systems = context.get("scan_operating_systems") or []
	if scan_operating_systems:
		writer.draw_paragraph("Sistemas operacionais detectados:")
		os_lines: list[str] = []
		for entry in scan_operating_systems[:8]:
			label = entry.get("label") or "—"
			count = entry.get("count", 0)
			hosts = entry.get("hosts") or []
			hosts_preview = ", ".join(str(host) for host in hosts[:5]) if hosts else ""
			line = f"{label} · {count} host(s)"
			if hosts_preview:
				line += f" · Hosts: {hosts_preview}"
			if len(hosts) > 5:
				line += f" (+{len(hosts) - 5} outros)"
			os_lines.append(line)
		writer.draw_bullet_list(os_lines)
	if scan_highlights:
		writer.draw_paragraph("Observações do scan:")
		highlights_lines: list[str] = []
		for highlight in scan_highlights[:6]:
			if isinstance(highlight, dict):
				message = highlight.get("message") or highlight.get("text") or str(highlight)
			else:
				message = str(highlight)
			if message:
				highlights_lines.append(message)
		writer.draw_bullet_list(highlights_lines)
	if scan_host_entries:
		writer.draw_paragraph("Hosts analisados:")
		host_lines: list[str] = []
		for host in scan_host_entries[:8]:
			host_id = host.get("host") or "—"
			reachable = "Sim" if host.get("reachable") else "Não"
			open_ports = host.get("open_ports") or []
			notes = host.get("notes") or ""
			operating_system = host.get("operating_system") or "—"
			open_repr = ", ".join(str(port) for port in open_ports) if open_ports else "Nenhuma"
			line = f"{host_id} · Alcançável: {reachable} · Portas abertas: {open_repr}"
			if operating_system and operating_system != "—":
				line += f" · SO: {operating_system}"
			if notes:
				line += f" · Observações: {notes}"
			host_lines.append(line)
		writer.draw_bullet_list(host_lines)
	if scan_service_entries:
		writer.draw_paragraph("Serviços destacados:")
		service_lines = [
			f"{entry.get('service', 'Serviço')} — {entry.get('occurrences', 0)} host(s)"
			for entry in scan_service_entries[:6]
		]
		writer.draw_bullet_list(service_lines)
	if scan_display_findings:
		writer.draw_paragraph("Achados relevantes:")
		finding_lines: list[str] = []
		for finding in scan_display_findings[:6]:
			title = finding.get("title") or "Achado"
			severity = (finding.get("severity") or "").upper() or "—"
			host = finding.get("host") or "—"
			summary = finding.get("summary") or ""
			line = f"{title} · Severidade: {severity} · Host: {host}"
			if summary:
				line += f" — {summary}"
			finding_lines.append(line)
		writer.draw_bullet_list(finding_lines)

	writer.draw_heading("Vulnerabilidades consolidadas", level=2)
	vuln_severity_breakdown = context.get("vuln_severity_breakdown") or []
	vuln_status_overview = context.get("vuln_status_overview") or {}
	vuln_display_findings = context.get("vuln_display_findings") or []
	vuln_top_hosts = context.get("vuln_top_hosts") or []
	vuln_top_services = context.get("vuln_top_services") or []
	if vuln_severity_breakdown:
		writer.draw_paragraph("Distribuição por severidade:")
		severity_lines = [
			f"{item.get('label') or item.get('key')}: {item.get('count', 0)} ({item.get('percentage', 0)}%)"
			for item in vuln_severity_breakdown
		]
		writer.draw_bullet_list(severity_lines)
	if vuln_status_overview:
		status_lines: list[str] = []
		if "open_total" in vuln_status_overview:
			status_lines.append(f"Vulnerabilidades abertas: {vuln_status_overview.get('open_total')}")
		if "resolved_total" in vuln_status_overview:
			status_lines.append(f"Vulnerabilidades resolvidas: {vuln_status_overview.get('resolved_total')}")
		if status_lines:
			writer.draw_bullet_list(status_lines)
	if vuln_top_hosts:
		writer.draw_paragraph("Hosts mais impactados:")
		writer.draw_bullet_list([f"{item.get('label')}: {item.get('count')} ocorrência(s)" for item in vuln_top_hosts])
	if vuln_top_services:
		writer.draw_paragraph("Serviços mais impactados:")
		writer.draw_bullet_list([f"{item.get('label')}: {item.get('count')} ocorrência(s)" for item in vuln_top_services])
	if vuln_display_findings:
		writer.draw_paragraph("Principais vulnerabilidades:")
		vuln_lines: list[str] = []
		for finding in vuln_display_findings[:8]:
			title = finding.get("title") or "Vulnerabilidade"
			severity = finding.get("severity_display") or finding.get("severity") or "—"
			host = finding.get("host") or "—"
			service = finding.get("service") or "—"
			cvss = finding.get("cvss")
			summary = finding.get("summary") or ""
			line = f"{title} · Severidade: {severity} · Host: {host} · Serviço: {service}"
			if cvss is not None:
				line += f" · CVSS: {cvss}"
			if summary:
				line += f" — {summary}"
			vuln_lines.append(line)
		writer.draw_bullet_list(vuln_lines)

	writer.draw_heading("Threat hunt", level=2)
	hunt_indicators = context.get("hunt_indicators") or []
	hunt_notes = context.get("hunt_notes") or []
	hunt_artifacts = context.get("hunt_artifacts") or []
	if hunt_indicators:
		writer.draw_paragraph("Indicadores de ameaça coletados:")
		indicator_lines: list[str] = []
		for indicator in hunt_indicators[:8]:
			if isinstance(indicator, dict):
				value = indicator.get("indicator") or indicator.get("value") or indicator.get("hash")
				description = indicator.get("description") or indicator.get("context")
				line = value or str(indicator)
				if description:
					line += f" — {description}"
				indicator_lines.append(line)
			else:
				indicator_lines.append(str(indicator))
		writer.draw_bullet_list(indicator_lines)
	if hunt_notes:
		writer.draw_paragraph("Notas de inteligência:")
		writer.draw_bullet_list([str(note) for note in hunt_notes[:8]])
	if hunt_artifacts:
		writer.draw_paragraph("Artefatos correlacionados:")
		artifact_lines: list[str] = []
		for artifact in hunt_artifacts[:6]:
			if isinstance(artifact, dict):
				title = artifact.get("name") or artifact.get("label") or "Artefato"
				type_label = artifact.get("type") or artifact.get("category")
				source = artifact.get("source")
				line = title
				if type_label:
					line += f" · Tipo: {type_label}"
				if source:
					line += f" · Origem: {source}"
				artifact_lines.append(line)
			else:
				artifact_lines.append(str(artifact))
		writer.draw_bullet_list(artifact_lines)

	writer.draw_heading("Termo de encerramento e entrega", level=2)
	closing_text = (
		f"Declaramos que o relatório executivo referente ao projeto {project.name} foi consolidado e disponibilizado ao cliente {client_name if client_name != '—' else 'designado'} em {generated_at_str}. "
		"O documento reúne os achados, indicadores e recomendações provenientes das atividades de scan, gestão de vulnerabilidades e threat hunt conduzidas pelo time ARPIA."
	)
	writer.draw_paragraph(closing_text)
	writer.draw_paragraph(
		"O responsável abaixo assina a entrega e atesta a veracidade das informações consolidadas."
	)
	writer.draw_signature_line(f"Assinatura do responsável ARPIA — {responsible_user}")
	writer.draw_paragraph(f"Data: {generated_at_str}")

	writer.finish()
	buffer.seek(0)
	return buffer.getvalue()


class ProjectConsolidatedReportView(LoginRequiredMixin, TemplateView):
	template_name = "reports/project_consolidated.html"

	def dispatch(self, request, *args, **kwargs):  # type: ignore[override]
		self.project = get_object_or_404(
			Project.objects.select_related("owner").prefetch_related("assets", "memberships__user"),
			pk=kwargs.get("pk"),
		)
		if not _user_has_access(request.user, self.project):
			_log_report_event(
				request=request,
				component="ui.consolidated",
				event_type="report.project.access.denied",
				message="Usuário tentou acessar relatório consolidado de projeto sem permissão.",
				project=self.project,
				severity=LogEntry.Severity.WARNING,
				details={"requested_project_id": str(self.project.pk)},
			)
			raise Http404("Projeto não encontrado")
		return super().dispatch(request, *args, **kwargs)

	def get(self, request, *args, **kwargs):  # type: ignore[override]
		if request.GET.get("format") == "pdf":
			_log_report_event(
				request=request,
				component="ui.consolidated",
				event_type="report.project.consolidated.pdf.requested",
				message="Usuário solicitou exportação em PDF do relatório consolidado.",
				project=self.project,
				details={"query_params": dict(request.GET.items())},
			)
			context = _build_project_consolidated_context(
				request=request,
				project=self.project,
				session=None,
			)
			try:
				pdf_bytes = _build_project_consolidated_pdf(
					project=self.project,
					context=context,
					user=request.user,
				)
			except RuntimeError as exc:
				_log_report_event(
					request=request,
					component="ui.consolidated",
					event_type="report.project.consolidated.pdf.failed",
					message="Falha ao gerar PDF do relatório consolidado.",
					project=self.project,
					severity=LogEntry.Severity.ERROR,
					details={"error": str(exc)},
				)
				return HttpResponse(str(exc), content_type="text/plain", status=503)
			filename = f"arpia-relatorio-{getattr(self.project, 'slug', None) or self.project.pk}.pdf"
			response = HttpResponse(pdf_bytes, content_type="application/pdf")
			response["Content-Disposition"] = f'attachment; filename="{filename}"'
			_log_report_event(
				request=request,
				component="ui.consolidated",
				event_type="report.project.consolidated.pdf.generated",
				message="Relatório consolidado exportado em PDF com sucesso.",
				project=self.project,
				details={
					"filename": filename,
					"pdf_bytes": len(pdf_bytes),
					"has_report": bool(context.get("has_report")),
				},
			)
			return response
		return super().get(request, *args, **kwargs)

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
