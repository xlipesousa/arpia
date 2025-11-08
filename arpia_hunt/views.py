from io import BytesIO
from time import perf_counter
from typing import Any
import re

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Prefetch, Count, Q, Max
from django.http import Http404, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views.generic import TemplateView

from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated

from arpia_core.models import Project
from arpia_log.models import LogEntry

from .log_events import emit_hunt_log
from .models import (
	CveAttackTechnique,
	HuntEnrichment,
	HuntFinding,
	HuntRecommendation,
	HuntSyncLog,
)
from .serializers import HuntFindingSerializer


SUMMARY_SPLIT_RE = re.compile(r"[\r\n]+|\s*\*+\s*|\s*[•;]\s*")
URL_SPLIT_RE = re.compile(r"\s+(https?://)")


def _coerce_iterable(value: Any) -> list[Any]:
	if not value:
		return []
	if isinstance(value, (list, tuple, set)):
		return [item for item in value if item]
	return [value]


def _split_urls_segment(text: str) -> list[str]:
	segments: list[str] = []
	remaining = text
	while remaining:
		match = re.search(r"https?://\S+", remaining)
		if not match:
			clean = remaining.strip()
			if clean:
				segments.append(clean)
			break
		start, end = match.span()
		prefix = remaining[:start].strip(" ,;·")
		if prefix:
			segments.append(prefix)
		segments.append(match.group())
		remaining = remaining[end:]
	return segments


def _normalize_summary_lines(value: Any) -> list[str]:
	lines: list[str] = []
	for candidate in _coerce_iterable(value):
		text = str(candidate)
		if not text.strip():
			continue
		text = text.replace("\r", "\n")
		text = URL_SPLIT_RE.sub(r"\n\1", text)
		splits = SUMMARY_SPLIT_RE.split(text)
		for chunk in splits:
			chunk = chunk.strip(" -•\t")
			if not chunk:
				continue
			for piece in _split_urls_segment(chunk):
				clean_piece = re.sub(r"\s{2,}", " ", piece.strip())
				if not clean_piece:
					continue
				if len(clean_piece) > 220:
					clean_piece = clean_piece[:217].rstrip() + "…"
				lines.append(clean_piece)
	return lines


def _profile_summary_lines(profile: dict[str, Any] | None, finding: HuntFinding) -> list[str]:
	items: list[str] = []
	seen: set[str] = set()

	def _extend(candidate_source: Any) -> None:
		for entry in _normalize_summary_lines(candidate_source):
			normalized = entry.strip()
			if normalized and normalized not in seen:
				seen.add(normalized)
				items.append(normalized)

	if isinstance(profile, dict):
		_extend(profile.get("summary"))
		_extend(profile.get("highlights"))
		_extend(profile.get("notes"))
		if not items and profile.get("description"):
			_extend(profile.get("description"))

	if not items and getattr(finding, "summary", None):
		_extend(finding.summary)

	return items[:12]


def _user_has_access(user, project: Project) -> bool:
	if not getattr(user, "is_authenticated", False):
		return False
	if project.owner_id == getattr(user, "id", None):
		return True
	return project.memberships.filter(user=user).exists()


def _resolve_accessible_projects(user):
	if not getattr(user, "is_authenticated", False):
		return Project.objects.none()
	if getattr(user, "is_superuser", False):
		return Project.objects.all().order_by()
	return Project.objects.filter(Q(owner=user) | Q(memberships__user=user)).distinct().order_by()


def _resolve_export_limit(value: str | None) -> int:
	try:
		limit = int(value) if value is not None else 200
	except (TypeError, ValueError):
		limit = 200
	return max(1, min(limit, 1000))


def _build_hunt_report_payload(*, user, project: Project | None = None, limit: int = 200) -> dict[str, Any]:
	projects_qs = _resolve_accessible_projects(user)
	if project is not None:
		if not _user_has_access(user, project):
			raise Http404("Projeto não encontrado")
		projects_qs = projects_qs.filter(pk=project.pk)

	project_ids_subquery = projects_qs.values_list("pk", flat=True)
	base_findings_qs = HuntFinding.objects.filter(project_id__in=project_ids_subquery)

	total_findings = base_findings_qs.count()
	active_findings = base_findings_qs.filter(is_active=True).count()
	findings_with_cve = base_findings_qs.exclude(Q(cve="") | Q(cve__isnull=True)).count()
	severity_rows = list(
		base_findings_qs.values("severity").annotate(total=Count("id")).order_by("-total")
	)
	recommendation_rows = list(
		HuntRecommendation.objects.filter(finding__project_id__in=project_ids_subquery)
		.values("recommendation_type")
		.annotate(total=Count("id"))
	)
	project_rows = list(
		base_findings_qs
		.values("project_id", "project__name", "project__slug")
		.annotate(
			total=Count("id"),
			active=Count("id", filter=Q(is_active=True)),
			with_cve=Count("id", filter=~Q(cve="") & Q(cve__isnull=False)),
			max_cvss=Max("cvss_score"),
		)
		.order_by("-total")
	)

	limit = max(1, min(limit, 1000))
	findings_qs = (
		base_findings_qs
		.select_related("project", "vulnerability")
		.prefetch_related(
			Prefetch(
				"enrichments",
				queryset=HuntEnrichment.objects.only("id", "source", "status", "fetched_at", "expires_at"),
			)
		)
		.annotate(
			recommendation_total=Count("recommendations", distinct=True),
			recommendation_blue=Count(
				"recommendations",
				filter=Q(recommendations__recommendation_type=HuntRecommendation.Type.BLUE),
				distinct=True,
			),
			recommendation_red=Count(
				"recommendations",
				filter=Q(recommendations__recommendation_type=HuntRecommendation.Type.RED),
				distinct=True,
			),
		)
		.order_by("-detected_at", "-created_at")[:limit]
	)
	findings_data: list[dict[str, Any]] = []

	for finding in findings_qs:
		enrichment_data = [
			{
				"id": enrichment.pk,
				"source": enrichment.source,
				"status": enrichment.status,
				"fetched_at": enrichment.fetched_at.isoformat() if enrichment.fetched_at else None,
				"expires_at": enrichment.expires_at.isoformat() if enrichment.expires_at else None,
			}
			for enrichment in finding.enrichments.all()[:12]
		]
		findings_data.append(
			{
				"id": str(finding.pk),
				"project": {
					"id": str(finding.project_id),
					"name": finding.project.name if finding.project else None,
					"slug": finding.project.slug if finding.project else None,
				},
				"vulnerability": {
					"id": str(finding.vulnerability_id),
					"title": getattr(finding.vulnerability, "title", None),
				},
				"host": finding.host,
				"service": finding.service,
				"port": finding.port,
				"protocol": finding.protocol,
				"cve": finding.cve,
				"severity": finding.severity,
				"severity_display": finding.get_severity_display(),
				"cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
				"cvss_vector": finding.cvss_vector,
				"summary": finding.summary,
				"tags": list(finding.tags or []),
				"is_active": finding.is_active,
				"detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
				"last_synced_at": finding.last_synced_at.isoformat() if finding.last_synced_at else None,
				"profile_version": finding.profile_version,
				"last_profiled_at": finding.last_profiled_at.isoformat() if finding.last_profiled_at else None,
				"state_version": finding.state_version,
				"last_state_snapshot_at": finding.last_state_snapshot_at.isoformat() if finding.last_state_snapshot_at else None,
				"blue_profile": finding.blue_profile or {},
				"red_profile": finding.red_profile or {},
				"recommendations": {
					"total": int(getattr(finding, "recommendation_total", 0) or 0),
					"blue": int(getattr(finding, "recommendation_blue", 0) or 0),
					"red": int(getattr(finding, "recommendation_red", 0) or 0),
				},
				"enrichments": enrichment_data,
			}
		)

	accessible_projects_count = projects_qs.distinct().count()
	project_metadata = None
	if project is not None:
		project_metadata = {
			"id": str(project.pk),
			"name": project.name,
			"slug": project.slug,
		}

	severity_distribution = {
		row["severity"] or "unknown": int(row["total"])
		for row in severity_rows
	}
	recommendations_summary = {
		row["recommendation_type"]: int(row["total"])
		for row in recommendation_rows
	}
	project_summaries = []
	for row in project_rows:
		project_summaries.append(
			{
				"project_id": str(row["project_id"]),
				"project_name": row["project__name"],
				"project_slug": row["project__slug"],
				"findings_total": int(row["total"]),
				"findings_active": int(row["active"]),
				"findings_with_cve": int(row["with_cve"]),
				"max_cvss": float(row["max_cvss"]) if row["max_cvss"] is not None else None,
			}
		)

	accessible_project_ids = list(project_ids_subquery)
	accessible_project_refs = [str(pk) for pk in accessible_project_ids]
	syncs_qs = HuntSyncLog.objects.select_related("project").order_by("-started_at", "-id")
	if project is not None:
		syncs_qs = syncs_qs.filter(project=project)
	elif accessible_project_refs:
		syncs_qs = syncs_qs.filter(Q(project__in=projects_qs) | Q(project__isnull=True))
	else:
		syncs_qs = syncs_qs.filter(project__isnull=True)
	recent_syncs = []
	for sync in syncs_qs[:10]:
		recent_syncs.append(
			{
				"id": sync.id,
				"project_id": str(sync.project_id) if sync.project_id else None,
				"project_name": sync.project.name if sync.project else None,
				"status": sync.status,
				"started_at": sync.started_at.isoformat() if sync.started_at else None,
				"finished_at": sync.finished_at.isoformat() if sync.finished_at else None,
				"duration_ms": sync.duration_ms,
				"total_processed": sync.total_processed,
				"created_count": sync.created_count,
				"updated_count": sync.updated_count,
				"skipped_count": sync.skipped_count,
				"error_message": sync.error_message or None,
			}
		)

	logs_qs = LogEntry.objects.filter(source_app="arpia_hunt").order_by("-timestamp", "-id")
	if project is not None:
		logs_qs = logs_qs.filter(project_ref=str(project.pk))
	elif accessible_project_refs:
		logs_qs = logs_qs.filter(project_ref__in=accessible_project_refs)
	else:
		logs_qs = logs_qs.none()
	recent_logs = []
	for entry in logs_qs[:10]:
		recent_logs.append(
			{
				"timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
				"event_type": entry.event_type,
				"severity": entry.severity,
				"message": entry.message,
				"component": entry.component,
				"details": entry.details,
				"tags": entry.tags,
				"project_ref": entry.project_ref,
			}
		)

	return {
		"metadata": {
			"generated_at": timezone.now().isoformat(),
			"project": project_metadata,
			"projects_total": accessible_projects_count,
			"limit": limit,
			"returned_findings": len(findings_data),
			"total_findings": total_findings,
			"active_findings": active_findings,
			"findings_with_cve": findings_with_cve,
		},
		"stats": {
			"severity_distribution": severity_distribution,
			"recommendations": recommendations_summary,
			"per_project": project_summaries,
		},
		"recent_syncs": recent_syncs,
		"recent_logs": recent_logs,
		"findings": findings_data,
	}


def _build_hunt_report_pdf(payload: dict[str, Any]) -> bytes:
	try:
		from reportlab.lib.pagesizes import A4
		from reportlab.lib.units import cm
		from reportlab.pdfgen import canvas
	except ImportError as exc:
		raise RuntimeError(
			"Dependência opcional 'reportlab' ausente. Instale-a para habilitar exportação em PDF."
		) from exc

	buffer = BytesIO()
	pdf = canvas.Canvas(buffer, pagesize=A4)
	width, height = A4
	margin = 2 * cm
	y = height - margin

	def draw_line(text: str, *, font: str = "Helvetica", size: int = 10, spacing: int = 14) -> None:
		nonlocal y
		if y <= margin:
			pdf.showPage()
			y = height - margin
		pdf.setFont(font, size)
		pdf.drawString(margin, y, text)
		y -= spacing

	pdf.setTitle("ARPIA Hunt Report")
	meta = payload.get("metadata", {})
	project_meta = meta.get("project") or {}
	generated_at = meta.get("generated_at")

	pdf.setFont("Helvetica-Bold", 16)
	pdf.drawString(margin, y, "ARPIA · Hunt Report")
	y -= 22

	pdf.setFont("Helvetica", 10)
	if generated_at:
		pdf.drawString(margin, y, f"Gerado em: {generated_at}")
		y -= 14
	if project_meta:
		pdf.drawString(margin, y, f"Projeto: {project_meta.get('name')} ({project_meta.get('id')})")
		y -= 14
	else:
		pdf.drawString(margin, y, f"Projetos incluídos: {meta.get('projects_total', 0)}")
		y -= 14
	pdf.drawString(margin, y, f"Findings retornados: {meta.get('returned_findings', 0)} de {meta.get('total_findings', 0)}")
	y -= 18

	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Resumo de Severidades")
	y -= 16
	severity = payload.get("stats", {}).get("severity_distribution", {})
	if severity:
		for key, value in severity.items():
			draw_line(f"- {key}: {value}")
	else:
		draw_line("Nenhum dado de severidade disponível.")

	y -= 4
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Resumo de Recomendações")
	y -= 16
	recommendations = payload.get("stats", {}).get("recommendations", {})
	if recommendations:
		for key, value in recommendations.items():
			draw_line(f"- {key}: {value}")
	else:
		draw_line("Nenhuma recomendação registrada.")

	y -= 4
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Projetos")
	y -= 16
	projects = payload.get("stats", {}).get("per_project", [])
	if projects:
		for project in projects[:10]:
			title = project.get("project_name") or project.get("project_id")
			draw_line(f"• {title}: {project.get('findings_total', 0)} findings, {project.get('findings_active', 0)} ativos")
	else:
		draw_line("Nenhum projeto agregado.")

	y -= 4
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Findings Destacados")
	y -= 16
	for finding in payload.get("findings", [])[:15]:
		title = finding.get("vulnerability", {}).get("title") or "Finding"
		severity_label = finding.get("severity") or "unknown"
		line = f"[{severity_label}] {title} · {finding.get('host') or '-'}"
		draw_line(line)
		cvss = finding.get("cvss_score")
		if cvss is not None:
			draw_line(f"CVSS: {cvss}", font="Helvetica", size=9, spacing=12)
		recs = finding.get("recommendations") or {}
		if recs:
			draw_line(
				f"Recomendações: total {recs.get('total', 0)} (Blue {recs.get('blue', 0)} / Red {recs.get('red', 0)})",
				font="Helvetica",
				size=9,
				spacing=12,
			)
		project_name = finding.get("project", {}).get("name")
		if project_name:
			draw_line(f"Projeto: {project_name}", font="Helvetica", size=9, spacing=12)
		y -= 4

	y -= 4
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Sincronizações Recentes")
	y -= 16
	for sync in payload.get("recent_syncs", [])[:5]:
		line = f"#{sync.get('id')} · {sync.get('status')} · {sync.get('started_at')}"
		draw_line(line)
		draw_line(
			f"Processados: {sync.get('total_processed', 0)} / Criados: {sync.get('created_count', 0)} / Atualizados: {sync.get('updated_count', 0)}",
			font="Helvetica",
			size=9,
			spacing=12,
		)
		y -= 4

	y -= 4
	pdf.setFont("Helvetica-Bold", 12)
	pdf.drawString(margin, y, "Logs Recentes")
	y -= 16
	for entry in payload.get("recent_logs", [])[:8]:
		line = f"{entry.get('timestamp')} · {entry.get('severity')} · {entry.get('event_type')}"
		draw_line(line)
		msg = (entry.get("message") or "")[:120]
		if msg:
			draw_line(msg, font="Helvetica", size=9, spacing=12)
		y -= 4

	pdf.showPage()
	pdf.save()
	buffer.seek(0)
	return buffer.getvalue()
class HuntDashboardView(LoginRequiredMixin, TemplateView):
	template_name = "hunt/dashboard.html"

	def dispatch(self, request, *args, **kwargs):  # type: ignore[override]
		self._render_started_at = perf_counter()
		return super().dispatch(request, *args, **kwargs)

	def render_to_response(self, context, **response_kwargs):  # type: ignore[override]
		if self._should_export_pdf():
			project = self._resolve_export_project()
			limit = _resolve_export_limit(self.request.GET.get("limit"))
			payload = _build_hunt_report_payload(
				user=self.request.user,
				project=project,
				limit=limit,
			)
			try:
				pdf_bytes = _build_hunt_report_pdf(payload)
			except RuntimeError as exc:
				return HttpResponse(str(exc), status=503, content_type="text/plain")
			filename_parts = ["arpia-hunt-report"]
			if project:
				filename_parts.append(getattr(project, "slug", str(project.pk)))
			filename = "-".join(filename_parts) + ".pdf"
			response = HttpResponse(pdf_bytes, content_type="application/pdf")
			response["Content-Disposition"] = f'attachment; filename="{filename}"'
			return response
		if self._should_export_json():
			project = self._resolve_export_project()
			limit = _resolve_export_limit(self.request.GET.get("limit"))
			payload = _build_hunt_report_payload(
				user=self.request.user,
				project=project,
				limit=limit,
			)
			return JsonResponse(payload, json_dumps_params={"ensure_ascii": False, "indent": 2})

		response = super().render_to_response(context, **response_kwargs)
		if getattr(settings, "ARPIA_HUNT_UI_METRICS_ENABLED", False):
			duration_ms = int((perf_counter() - getattr(self, "_render_started_at", perf_counter())) * 1000)
			try:
				emit_hunt_log(
					event_type="hunt.ui.render",
					message="Dashboard Hunt renderizada.",
					component="hunt.ui",
					details={
						"duration_ms": duration_ms,
						"blue_cards": len(context.get("blue_tabs", [])),
						"red_cards": len(context.get("red_tabs", [])),
					},
					tags=["metric:hunt.ui.render_time"],
				)
			except Exception:
				pass
		return response

	def _should_export_json(self) -> bool:
		export_flag = (self.request.GET.get("export") or "").lower()
		format_flag = (self.request.GET.get("format") or "").lower()
		if format_flag in {"json", "api"}:
			return True
		if export_flag in {"1", "true", "json"}:
			return True
		accept_header = (self.request.headers.get("Accept") or "").lower()
		if "application/json" in accept_header and (self.request.GET.get("html") or "").lower() not in {"1", "true"}:
			return True
		return False

	def _should_export_pdf(self) -> bool:
		format_flag = (self.request.GET.get("format") or "").lower()
		export_flag = (self.request.GET.get("export") or "").lower()
		if format_flag == "pdf":
			return True
		if export_flag == "pdf":
			return True
		accept_header = (self.request.headers.get("Accept") or "").lower()
		if "application/pdf" in accept_header:
			return True
		return False

	def _resolve_export_project(self) -> Project | None:
		project_id = self.request.GET.get("project")
		if not project_id:
			return None
		project = get_object_or_404(
			Project.objects.select_related("owner").prefetch_related("memberships__user"),
			pk=project_id,
		)
		if not _user_has_access(self.request.user, project):
			raise Http404("Projeto não encontrado")
		return project

	def get_context_data(self, **kwargs):  # type: ignore[override]
		context = super().get_context_data(**kwargs)
		projects = list(_resolve_accessible_projects(self.request.user))
		selected_project = self._resolve_project(projects)
		selected_project_id = str(selected_project.pk) if selected_project else ""
		if selected_project:
			filter_ids = [selected_project.pk]
		else:
			filter_ids = [project.pk for project in projects]

		findings_qs = HuntFinding.objects.all()
		if filter_ids:
			findings_qs = findings_qs.filter(project_id__in=filter_ids)
		else:
			findings_qs = HuntFinding.objects.none()

		stats = {
			"findings_total": findings_qs.count(),
			"findings_active": findings_qs.filter(is_active=True).count(),
			"findings_with_cve": findings_qs.exclude(Q(cve="") | Q(cve__isnull=True)).count(),
		}

		syncs_qs = HuntSyncLog.objects.select_related("project").order_by("-started_at", "-id")
		if selected_project:
			syncs_qs = syncs_qs.filter(project=selected_project)
		elif filter_ids:
			syncs_qs = syncs_qs.filter(Q(project_id__in=filter_ids) | Q(project__isnull=True))
		else:
			syncs_qs = syncs_qs.filter(project__isnull=True)
		recent_syncs = list(syncs_qs[:5])

		logs_qs = LogEntry.objects.filter(source_app="arpia_hunt").order_by("-timestamp", "-id")
		if selected_project:
			logs_qs = logs_qs.filter(project_ref=str(selected_project.pk))
		elif filter_ids:
			logs_qs = logs_qs.filter(project_ref__in=[str(pk) for pk in filter_ids])
		else:
			logs_qs = logs_qs.none()
		recent_logs = list(logs_qs[:8])

		recent_profiles_qs = (
			findings_qs.filter(profile_version__gt=0)
			.select_related("vulnerability", "project")
			.prefetch_related("recommendations__technique", "recommendations__technique__tactic")
			.order_by("-last_profiled_at")
		)
		recent_profiles = list(recent_profiles_qs[:5])

		cve_candidates = {finding.cve for finding in recent_profiles if finding.cve}
		heuristic_map: dict[str, list[CveAttackTechnique]] = {}
		if cve_candidates:
			heuristic_qs = (
				CveAttackTechnique.objects.filter(
					cve__in=cve_candidates,
					source=CveAttackTechnique.Source.HEURISTIC,
				)
				.select_related("technique", "technique__tactic")
				.order_by("-updated_at")
			)
			for mapping in heuristic_qs:
				heuristic_map.setdefault(mapping.cve, []).append(mapping)

		blue_tabs: list[dict[str, object]] = []
		red_tabs: list[dict[str, object]] = []
		for finding in recent_profiles:
			recommendations = list(finding.recommendations.all())
			blue_recs = [
				rec
				for rec in recommendations
				if rec.recommendation_type == HuntRecommendation.Type.BLUE
			][:3]
			red_recs = [
				rec
				for rec in recommendations
				if rec.recommendation_type == HuntRecommendation.Type.RED
			][:3]

			heuristics = heuristic_map.get(finding.cve, [])
			blue_summary = _profile_summary_lines(finding.blue_profile or {}, finding)
			red_summary = _profile_summary_lines(finding.red_profile or {}, finding)
			blue_tabs.append(
				{
					"finding": finding,
					"profile": finding.blue_profile or {},
					"recommendations": blue_recs,
					"heuristics": heuristics,
					"summary_lines": blue_summary,
				}
			)
			red_tabs.append(
				{
					"finding": finding,
					"profile": finding.red_profile or {},
					"recommendations": red_recs,
					"heuristics": heuristics,
					"summary_lines": red_summary,
				}
			)

		blue_insights = []
		red_insights = []
		for finding in recent_profiles:
			blue_insights.append(
				{
					"finding": finding,
					"profile": finding.blue_profile or {},
					"recommendations": [
						rec
						for rec in finding.recommendations.all()
						if rec.recommendation_type == HuntRecommendation.Type.BLUE
					][:3],
					"summary_lines": _profile_summary_lines(finding.blue_profile or {}, finding),
				}
			)
			red_insights.append(
				{
					"finding": finding,
					"profile": finding.red_profile or {},
					"recommendations": [
						rec
						for rec in finding.recommendations.all()
						if rec.recommendation_type == HuntRecommendation.Type.RED
					][:3],
					"summary_lines": _profile_summary_lines(finding.red_profile or {}, finding),
				}
			)

		context.update(
			{
				"phase": "Fase 5",
				"snapshot_label": "Automação & alertas",
				"projects": projects,
				"selected_project": selected_project,
				"selected_project_id": selected_project_id,
				"has_project": selected_project is not None,
				"data_sources": [
					{
						"label": "Scan",
						"description": "Resultados consolidados do módulo arpia_scan com contexto de superfície exposta.",
					},
					{
						"label": "Vulnerabilidades",
						"description": "Findings priorizados provenientes do módulo arpia_vuln com CVSS, CWE e owners definidos.",
					},
					{
						"label": "Logs Hunt",
						"description": "Eventos operacionais registrados via arpia_log empregados em métricas e auditoria contínua.",
					},
					{
						"label": "Catálogos externos",
						"description": "NVD, Vulners, Exploit-DB/searchsploit e MITRE ATT&CK atualizados para alimentar heurísticas.",
					},
				],
				"phase_objectives": [
					"Ativar alertas automatizados com thresholds configuráveis para findings críticos.",
					"Garantir reprocessamento incremental mantendo perfis Blue/Red atualizados.",
					"Conectar recomendações ATT&CK a playbooks operacionais e notificações acionáveis.",
				],
				"deliverables": [
					"Serviço de alertas com SLA configurável e canais de notificação (email/webhook).",
					"Comando e jobs de avaliação periódica dos findings priorizados.",
					"Dashboards consolidados para acompanhamento de alertas e métricas operacionais.",
				],
				"next_steps": [
					"Instrumentar monitoramento e métricas para a execução dos alertas automatizados.",
					"Agendar o comando hunt_alerts em cron ou Celery alinhado às SLAs definidas.",
					"Preparar workshop de rollout com equipes Blue e Red para revisar responsabilidades.",
				],
				"stats": stats,
				"recent_syncs": recent_syncs,
				"recent_logs": recent_logs,
				"recent_profiles": recent_profiles,
				"blue_insights": blue_insights,
				"red_insights": red_insights,
				"blue_tabs": blue_tabs,
				"red_tabs": red_tabs,
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

	def _resolve_project(self, projects):
		project_id = self.request.GET.get("project")
		if project_id:
			for project in projects:
				if str(project.pk) == str(project_id):
					return project
			return None
		return projects[0] if projects else None


class HuntFindingDetailView(LoginRequiredMixin, TemplateView):
	template_name = "hunt/findings/detail.html"

	def get_context_data(self, **kwargs):  # type: ignore[override]
		context = super().get_context_data(**kwargs)
		finding = get_object_or_404(
			HuntFinding.objects.select_related("project", "vulnerability")
			.prefetch_related(
				Prefetch(
					"recommendations",
					HuntRecommendation.objects.select_related(
						"technique",
						"technique__tactic",
						"finding",
						"finding__project",
					).order_by("-updated_at", "-created_at"),
				),
				Prefetch(
					"enrichments",
					HuntEnrichment.objects.order_by("-updated_at", "-id"),
				),
			),
			pk=self.kwargs["pk"],
		)

		recommendations = list(finding.recommendations.all())
		blue_recommendations = [
			rec
			for rec in recommendations
			if rec.recommendation_type == HuntRecommendation.Type.BLUE
		]
		red_recommendations = [
			rec
			for rec in recommendations
			if rec.recommendation_type == HuntRecommendation.Type.RED
		]

		heuristics = list(
			CveAttackTechnique.objects.filter(cve=finding.cve)
			.select_related("technique", "technique__tactic")
			.order_by("-updated_at")
		)

		enrichments = list(finding.enrichments.all()[:6])
		recent_logs = list(
			LogEntry.objects.filter(details__finding_id=str(finding.pk))
			.order_by("-timestamp")[:10]
		)
		finding_summary_lines = _normalize_summary_lines(finding.summary)
		blue_summary_lines = _profile_summary_lines(finding.blue_profile or {}, finding)
		red_summary_lines = _profile_summary_lines(finding.red_profile or {}, finding)
		project_url = None
		if finding.project_id:
			try:
				project_url = reverse("projects_detail", args=[finding.project_id])
			except Exception:
				project_url = None
		vulnerability_url = None
		if getattr(finding, "vulnerability_id", None) and getattr(finding.vulnerability, "session_id", None):
			try:
				vulnerability_url = reverse("arpia_vuln:session_detail", args=[finding.vulnerability.session_id])
			except Exception:
				vulnerability_url = None
		report_url = None
		if finding.project_id:
			try:
				report_url = reverse("arpia_report:api_project_report", args=[finding.project_id])
			except Exception:
				report_url = None
		profiles_api_url = reverse("hunt-finding-profiles", args=[finding.pk])
		recommendations_api_url = reverse("hunt-recommendation-list")

		context.update(
			{
				"finding": finding,
				"blue_profile": finding.blue_profile or {},
				"red_profile": finding.red_profile or {},
				"finding_summary_lines": finding_summary_lines,
				"blue_summary_lines": blue_summary_lines,
				"red_summary_lines": red_summary_lines,
				"blue_recommendations": blue_recommendations,
				"red_recommendations": red_recommendations,
				"blue_heuristics": heuristics,
				"red_heuristics": heuristics,
				"enrichments": enrichments,
				"recent_logs": recent_logs,
				"project_url": project_url,
				"vulnerability_url": vulnerability_url,
				"report_url": report_url,
				"profiles_api_url": profiles_api_url,
				"recommendations_api_url": recommendations_api_url,
			}
		)
		return context


class HuntFindingListAPIView(ListAPIView):
	serializer_class = HuntFindingSerializer
	permission_classes = [IsAuthenticated]

	def get_queryset(self):
		queryset = HuntFinding.objects.select_related("project", "vulnerability").prefetch_related(
			"enrichments",
			"snapshots",
			"state_snapshots",
		)
		project_id = self.request.query_params.get("project")
		if project_id:
			queryset = queryset.filter(project_id=project_id)
		limit = self._resolve_limit()
		return queryset.order_by("-last_profiled_at", "-detected_at")[:limit]

	def _resolve_limit(self) -> int:
		try:
			limit = int(self.request.query_params.get("limit", "100"))
		except ValueError:
			limit = 100
		return max(1, min(limit, 500))

