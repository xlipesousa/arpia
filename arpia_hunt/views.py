from time import perf_counter

from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import TemplateView

from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated

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


class HuntDashboardView(LoginRequiredMixin, TemplateView):
	template_name = "hunt/dashboard.html"

	def dispatch(self, request, *args, **kwargs):  # type: ignore[override]
		self._render_started_at = perf_counter()
		return super().dispatch(request, *args, **kwargs)

	def render_to_response(self, context, **response_kwargs):  # type: ignore[override]
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

	def get_context_data(self, **kwargs):  # type: ignore[override]
		context = super().get_context_data(**kwargs)
		stats = {
			"findings_total": HuntFinding.objects.count(),
			"findings_active": HuntFinding.objects.filter(is_active=True).count(),
			"findings_with_cve": HuntFinding.objects.exclude(cve="").count(),
		}
		recent_syncs = list(HuntSyncLog.objects.order_by("-started_at")[:5])
		recent_logs = list(
			LogEntry.objects.filter(source_app="arpia_hunt").order_by("-timestamp")[:8]
		)
		recent_profiles_qs = (
			HuntFinding.objects.filter(profile_version__gt=0)
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
			blue_tabs.append(
				{
					"finding": finding,
					"profile": finding.blue_profile or {},
					"recommendations": blue_recs,
					"heuristics": heuristics,
				}
			)
			red_tabs.append(
				{
					"finding": finding,
					"profile": finding.red_profile or {},
					"recommendations": red_recs,
					"heuristics": heuristics,
				}
			)

		blue_insights = [
			{
				"finding": finding,
				"profile": finding.blue_profile or {},
				"recommendations": [
					rec
					for rec in finding.recommendations.all()
					if rec.recommendation_type == HuntRecommendation.Type.BLUE
				][:3],
			}
			for finding in recent_profiles
		]
		red_insights = [
			{
				"finding": finding,
				"profile": finding.red_profile or {},
				"recommendations": [
					rec
					for rec in finding.recommendations.all()
					if rec.recommendation_type == HuntRecommendation.Type.RED
				][:3],
			}
			for finding in recent_profiles
		]

		context.update(
			{
				"phase": "Fase 3",
				"snapshot_label": "kickoff fase 3",
				"data_sources": [
					{
						"label": "Scan",
						"description": "Sessões, hosts, portas, serviços e metadados consolidados em arpia_scan.",
					},
					{
						"label": "Vulnerabilidades",
						"description": "Findings enriquecidos do módulo arpia_vuln, incluindo CVE/CWE e contexto agregado.",
					},
					{
						"label": "Logs Hunt",
						"description": "Eventos operacionais registrados via arpia_log para auditoria e depuração da ingestão.",
					},
					{
						"label": "Catálogos externos",
						"description": "NVD (nvdlib), Vulners, Exploit-DB/searchsploit, MITRE ATT&CK (pyattck/mitreattack).",
					},
				],
				"phase_objectives": [
					"Mapear técnicas ATT&CK via heurísticas por CVE, CWE e keywords e sincronizar catálogo completo.",
					"Gerar recomendações Blue/Red reutilizando enriquecimentos e confiança dos vínculos ATT&CK.",
					"Unificar taxonomias Blue/Red em componentes de UI consumindo dados reais do pipeline.",
				],
				"deliverables": [
					"Comando de importação ATT&CK capaz de consumir todas as matrizes via pyattck.",
					"Fixtures e contratos de teste cobrindo integrações externas e heurísticas ATT&CK.",
					"Componentes de UI para tabs Blue/Red utilizando perfis e recomendações reais.",
				],
				"next_steps": [
					"Expor endpoints públicos (Fase 4) com paginação e filtros por técnica/confiança.",
					"Evoluir protótipo de abas para componentes definitivos com interações assíncronas.",
					"Instrumentar métricas e alertas para consumo das recomendações automatizadas.",
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

