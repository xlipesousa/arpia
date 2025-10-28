import json
from typing import Any

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from arpia_core.models import Project
from arpia_scan.models import ScanSession, ScanTask

from .services import ReportAggregator, SectionData


def _user_has_access(user, project: Project) -> bool:
	if project.owner_id == user.id:
		return True
	return project.memberships.filter(user=user).exists()


class ReportLandingView(LoginRequiredMixin, TemplateView):
	template_name = "reports/report_placeholder.html"

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		session = self._resolve_session()
		project = self._resolve_project(session=session)
		aggregator = ReportAggregator(project=project, session=session) if project else None

		sections = aggregator.build_sections() if aggregator else {}
		scan_section = sections.get("scan") if sections else None
		scan_entry = scan_section.items[0] if scan_section and scan_section.items else None
		scan_snapshot = scan_entry.payload if scan_entry else {}
		status_chart = self._build_status_chart(scan_snapshot.get("stats", {})) if scan_snapshot else []
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
		scan_observations = scan_snapshot.get("summary", {}).get("observations") if isinstance(scan_snapshot.get("summary"), dict) else {}
		scan_targets = scan_snapshot.get("targets", {}) if isinstance(scan_snapshot, dict) else {}
		scan_services = scan_snapshot.get("services", {}) if isinstance(scan_snapshot, dict) else {}
		scan_snapshot_json = json.dumps(scan_snapshot, indent=2, ensure_ascii=False) if scan_snapshot else ""

		# expose common keys expected by templates and tests
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
				"report_highlights": scan_snapshot.get("insights", []),
				"report_stats": scan_snapshot.get("stats", {}),
				"report_targets": scan_snapshot.get("targets", {}),
				"report_services": scan_snapshot.get("services", {}),
				"report_findings": scan_snapshot.get("findings", []),
				"status_chart": status_chart,
				"project_report": project_report,
				"project_report_payload_json": project_report_payload_json,
				"has_report": bool(scan_snapshot) or any(section.items for section in sections.values()) if sections else False,
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
