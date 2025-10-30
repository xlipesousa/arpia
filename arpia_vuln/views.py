import json

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.db.models import Count, Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from arpia_core.models import Project
from arpia_scan.models import ScanSession
from arpia_core.views import build_project_macros

from .models import VulnerabilityFinding, VulnScanSession
from .services import plan_vulnerability_session, run_vulnerability_pipeline


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


def _load_dashboard_findings(project, project_ids: list[str], *, limit: int = 6):
	qs = _finding_queryset(project, project_ids)
	return list(qs.order_by("-detected_at", "-created_at")[:limit])


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
	return {
		"id": str(finding.pk),
		"title": finding.title,
		"summary": finding.summary,
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


def _build_dashboard_links(project: Project | None) -> dict:
	params = {}
	if project:
		params["project"] = str(project.pk)
	query = f"?{urlencode(params)}" if params else ""
	return {
		"scan_dashboard": reverse("arpia_scan:dashboard") + query,
		"report_home": reverse("arpia_report:report_home") + query,
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
		tasks = self.session.tasks.select_related("tool", "script").order_by("order", "id")
		findings = self.session.findings.select_related("source_task").order_by("-cvss_score", "severity")
		report_snapshot = self.session.report_snapshot or {}
		report_insights = (
			report_snapshot.get("insights")
			if isinstance(report_snapshot, dict)
			else []
		)
		metrics = report_snapshot.get("stats", {}) if isinstance(report_snapshot, dict) else {}

		context.update(
			{
				"session": self.session,
				"project": self.session.project,
				"source_scan_session": self.session.source_scan_session,
				"tasks": tasks,
				"findings": findings,
				"report_insights": report_insights,
				"metrics": metrics,
				"has_snapshot": bool(report_snapshot),
				"report_url": reverse("arpia_vuln:session_report_preview", args=[self.session.pk]),
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
		report_json = json.dumps(self.session.report_snapshot or {}, indent=2, ensure_ascii=False)
		context.update(
			{
				"session": self.session,
				"project": self.session.project,
				"report_json": report_json,
			}
		)
		return context


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
		run_vulnerability_pipeline(session, triggered_by=request.user)
	except ValidationError as exc:
		return JsonResponse({"error": exc.message}, status=400)
	except Exception as exc:  # pragma: no cover - captura para UI
		session.refresh_from_db()
		return JsonResponse({"error": str(exc)}, status=500)

	session.refresh_from_db()
	return JsonResponse(_serialize_session_for_api(session), status=200, json_dumps_params={"ensure_ascii": False})
