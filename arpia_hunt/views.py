from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView

from rest_framework.generics import ListAPIView
from rest_framework.permissions import IsAuthenticated

from arpia_log.models import LogEntry

from .models import HuntFinding, HuntSyncLog
from .serializers import HuntFindingSerializer


class HuntDashboardView(LoginRequiredMixin, TemplateView):
	template_name = "hunt/dashboard.html"

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
		recent_profiles = list(
			HuntFinding.objects.filter(profile_version__gt=0)
			.order_by("-last_profiled_at")
			.select_related("vulnerability", "project")
			[:5]
		)
		blue_insights = [
			{
				"finding": finding,
				"profile": finding.blue_profile or {},
			}
			for finding in recent_profiles
		]
		red_insights = [
			{
				"finding": finding,
				"profile": finding.red_profile or {},
			}
			for finding in recent_profiles
		]

		context.update(
			{
				"phase": "Fase 2",
				"snapshot_label": "hunt fase 1",
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
						"description": "NVD (nvdlib), Vulners, Exploit-DB/searchsploit, MITRE ATT&CK (pyattck).",
					},
				],
				"phase_objectives": [
					"Enriquecer achados com CVSS, CWE e referências oficiais da NVD usando cache local.",
					"Correlacionar exploits públicos via Vulners e searchsploit, priorizando riscos acionáveis.",
					"Persistir metadados externos normalizados para Blue-Team e Red-Team utilizarem em perfis.",
				],
				"deliverables": [
					"Serviços de enriquecimento (NVD, Vulners, Exploit-DB) com caching e monitoramento de erro.",
					"Modelos Django para armazenar metadados externos com políticas de expiração.",
					"Integração do Hunt com arpia_log para trilha de auditoria das sincronizações.",
				],
				"next_steps": [
					"Implementar heurísticas ATT&CK e recomendações (Fase 3).",
					"Expandir dashboard com abas Blue/Red e APIs públicas (Fase 4).",
					"Planejar notificações e automações com dados enriquecidos (Fase 5).",
				],
				"stats": stats,
				"recent_syncs": recent_syncs,
				"recent_logs": recent_logs,
				"recent_profiles": recent_profiles,
				"blue_insights": blue_insights,
				"red_insights": red_insights,
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

