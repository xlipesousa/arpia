import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from arpia_core.models import Project
from arpia_scan.models import ScanSession, ScanTask


def _user_has_access(user, project: Project) -> bool:
	if project.owner_id == user.id:
		return True
	return project.memberships.filter(user=user).exists()


class ReportLandingView(LoginRequiredMixin, TemplateView):
	template_name = "reports/report_placeholder.html"

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		session = self._resolve_session()
		report = session.report_snapshot if session and session.report_snapshot else {}
		stats = report.get("stats", {}) if isinstance(report, dict) else {}
		timeline = report.get("timeline", []) if isinstance(report, dict) else []
		tasks = report.get("tasks", []) if isinstance(report, dict) else []
		insights = report.get("insights", []) if isinstance(report, dict) else []
		targets = report.get("targets", {}) if isinstance(report, dict) else {}
		services = report.get("services", {}) if isinstance(report, dict) else {}
		findings = report.get("findings", []) if isinstance(report, dict) else []
		timeline_sorted = sorted(
			[t for t in timeline if t.get("started_at") or t.get("finished_at")],
			key=lambda item: (item.get("started_at") or "", item.get("finished_at") or ""),
		)
		status_chart = self._build_status_chart(stats)
		report_json = json.dumps(report, ensure_ascii=False, indent=2) if report else "{}"
		highlight_insights = insights[:3]
		context.update(
			{
				"session": session,
				"project": session.project if session else None,
				"report": report,
				"report_stats": stats,
				"report_timeline": timeline_sorted,
				"report_tasks": tasks,
				"report_insights": insights,
				"report_highlights": highlight_insights,
				"report_targets": targets,
				"report_services": services,
				"report_findings": findings,
				"status_chart": status_chart,
				"report_json": mark_safe(report_json),
				"has_report": bool(report),
			}
		)
		return context

	def _build_status_chart(self, stats: dict) -> list[dict]:
		status_counts = (stats or {}).get("status_counts") or {}
		if not status_counts:
			return []
		total = sum(int(value) for value in status_counts.values()) or 1
		chart = []
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
	}
	return JsonResponse(response, json_dumps_params={"ensure_ascii": False, "indent": 2})
