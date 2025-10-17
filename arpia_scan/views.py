import csv

from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404, JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import urlencode

import json

from arpia_core.models import Project
from arpia_core.views import build_project_macros  # TODO: mover para util dedicado

from arpia_log.models import LogEntry

from .models import ScanFinding, ScanSession
from .services import ScanOrchestrator, create_planned_session


def _macro_entries(macros: dict | None) -> list[dict]:
    entries = []
    for key, value in (macros or {}).items():
        if isinstance(value, (list, dict)):
            display = json.dumps(value, indent=2, ensure_ascii=False)
            entries.append({"key": key, "value": display, "is_pre": True})
        else:
            display = str(value or "")
            entries.append({"key": key, "value": display, "is_pre": "\n" in display})
    return entries


class ScanDashboardView(LoginRequiredMixin, TemplateView):
    template_name = "scan/dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        projects = list(self._get_accessible_projects())
        selected_project, selected_project_id = self._resolve_selected_project(projects)
        macros = build_project_macros(self.request.user, selected_project) if selected_project else {}
        macro_entries = _macro_entries(macros)

        sessions = (
            ScanSession.objects.filter(project=selected_project)
            .select_related("owner")
            .order_by("-created_at")
        )[:6] if selected_project else []

        context.update(
            {
                "projects": projects,
                "selected_project_id": selected_project_id,
                "selected_project": selected_project,
                "macros": macros,
                "macro_entries": macro_entries,
                "has_project": selected_project is not None,
                "action_cards": self._action_cards(selected_project_id),
                "recent_sessions": sessions,
                "total_findings": self._count_findings(sessions),
            }
        )
        return context

    def _get_accessible_projects(self):
        user = self.request.user
        return (
            Project.objects.filter(Q(owner=user) | Q(memberships__user=user))
            .distinct()
            .order_by("name")
        )

    def _resolve_selected_project(self, projects):
        requested_id = self.request.GET.get("project", "" ) or ""
        if requested_id:
            for project in projects:
                if str(project.pk) == str(requested_id):
                    return project, str(project.pk)
        if projects:
            project = projects[0]
            return project, str(project.pk)
        return None, ""

    def _action_cards(self, selected_project_id: str) -> list[dict]:
        base_cards = [
            {
                "kind": "connectivity",
                "title": "Teste de conectividade",
                "description": "Valide reachability, interface e rotas antes de iniciar scans pesados.",
                "badge": "Simulação",
            },
            {
                "kind": "rustscan",
                "title": "Scan rápido (Rustscan)",
                "description": "Identifique rapidamente hosts responsivos e portas expostas.",
                "badge": "Simulação",
            },
            {
                "kind": "nmap",
                "title": "Níveis de ruído (Nmap)",
                "description": "Escolha perfis de Nmap para alvos prioritários e avaliação completa.",
                "badge": "Simulação",
            },
        ]

        for card in base_cards:
            card["enabled"] = bool(selected_project_id)
        return base_cards

    def _count_findings(self, sessions) -> int:
        if not sessions:
            return 0
        return ScanFinding.objects.filter(session__in=sessions).count()


class ScanSessionDetailView(LoginRequiredMixin, TemplateView):
    template_name = "scan/session_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        session = self._get_session()
        macros = session.macros_snapshot or build_project_macros(self.request.user, session.project)
        macro_entries = _macro_entries(macros)

        tasks = list(
            session.tasks.select_related("tool", "script", "wordlist").order_by("order", "id")
        )
        findings_qs = session.findings.select_related("source_task").order_by("order", "id")
        finding_rows = [
            {
                "instance": finding,
                "display_data": json.dumps(finding.data, indent=2, ensure_ascii=False) if finding.data else "",
            }
            for finding in findings_qs
        ]

        context.update(
            {
                "session": session,
                "project": session.project,
                "tasks": tasks,
                "findings": finding_rows,
                "macros": macros,
                "macro_entries": macro_entries,
                "report": session.report_snapshot or {},
                "report_insights": (session.report_snapshot or {}).get("insights", []),
                "report_stats": (session.report_snapshot or {}).get("stats", {}),
                "report_targets": (session.report_snapshot or {}).get("targets", {}),
                "report_services": (session.report_snapshot or {}).get("services", {}),
                "report_url": self._build_report_url(session),
                "logs_url": reverse("arpia_scan:api_session_logs", args=[session.pk]),
            }
        )
        return context

    def _get_session(self) -> ScanSession:
        try:
            session = ScanSession.objects.select_related("project", "owner").get(pk=self.kwargs["pk"])
        except ScanSession.DoesNotExist as exc:  # pragma: no cover - Django levantará 404
            raise Http404("Sessão não encontrada") from exc

        user = self.request.user
        if not Project.objects.filter(
            Q(pk=session.project_id)
            & (Q(owner=user) | Q(memberships__user=user))
        ).exists():
            raise Http404("Projeto não encontrado")
        return session

    def _build_report_url(self, session: ScanSession) -> str:
        base = reverse("arpia_report:report_home")
        return f"{base}?{urlencode({'session': str(session.pk)})}"


class ScanSessionReportPreviewView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        session = get_object_or_404(
            ScanSession.objects.select_related("project", "owner"),
            pk=kwargs["pk"],
        )
        if not _user_has_access(request.user, session.project):
            raise Http404("Projeto não encontrado")

        query = urlencode({"session": str(session.pk)})
        report_url = f"{reverse('arpia_report:report_home')}?{query}"
        return redirect(report_url)


class ScanSessionTargetsExportView(LoginRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        session = get_object_or_404(ScanSession, pk=kwargs["pk"])
        if not _user_has_access(request.user, session.project):
            raise Http404("Projeto não encontrado")

        export_format = kwargs.get("format")
        if export_format == "json":
            return self._export_json(session)
        return self._export_csv(session)

    def _export_csv(self, session: ScanSession) -> HttpResponse:
        snapshot = session.report_snapshot or {}
        targets = snapshot.get("targets", {})
        hosts = targets.get("hosts", [])

        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = f"attachment; filename=scan-{session.reference}-targets.csv"
        writer = csv.writer(response)
        writer.writerow(["host", "hostname", "port", "protocol", "service", "severity"])

        for host in hosts:
            ports = host.get("ports", [])
            if not ports:
                writer.writerow([
                    host.get("host"),
                    host.get("hostname", ""),
                    "",
                    "",
                    "",
                    host.get("severity", ""),
                ])
                continue
            for port in ports:
                writer.writerow([
                    host.get("host"),
                    host.get("hostname", ""),
                    port.get("port"),
                    port.get("protocol", "tcp"),
                    port.get("service", ""),
                    port.get("severity", ""),
                ])
        return response

    def _export_json(self, session: ScanSession) -> JsonResponse:
        snapshot = session.report_snapshot or {}
        payload = snapshot.get("targets", {})
        return JsonResponse(payload, json_dumps_params={"indent": 2})


@login_required
@require_http_methods(["GET"])
def api_session_logs(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    if not _user_has_access(request.user, session.project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

    qs = LogEntry.objects.filter(correlation__scan_session_id=str(session.pk))

    since = request.GET.get("since")
    cursor = request.GET.get("cursor")

    def _parse_cursor(value):
        if not value:
            return None
        parsed = parse_datetime(value)
        if not parsed:
            return None
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed, timezone.get_current_timezone())
        return parsed

    since_ts = _parse_cursor(since)
    if since_ts:
        qs = qs.filter(timestamp__gte=since_ts)

    cursor_ts = _parse_cursor(cursor)
    if cursor_ts:
        qs = qs.filter(timestamp__gt=cursor_ts)

    try:
        limit = int(request.GET.get("limit", 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 250))

    qs = qs.order_by("timestamp", "id")[:limit]

    results = [_serialize_log_entry(entry) for entry in qs]
    latest = results[-1]["timestamp"] if results else cursor or since

    return JsonResponse(
        {
            "results": results,
            "count": len(results),
            "latest": latest,
        }
    )


def _user_has_access(user, project: Project) -> bool:
    if project.owner_id == user.id:
        return True
    return project.memberships.filter(user=user).exists()


def _serialize_session(session: ScanSession) -> dict:
    report_url = f"{reverse('arpia_report:report_home')}?{urlencode({'session': str(session.pk)})}"
    return {
        "id": str(session.pk),
        "reference": session.reference,
        "project_id": str(session.project_id),
        "title": session.title,
        "status": session.status,
        "status_display": session.get_status_display(),
        "created_at": session.created_at.isoformat(),
        "started_at": session.started_at.isoformat() if session.started_at else None,
        "finished_at": session.finished_at.isoformat() if session.finished_at else None,
        "detail_url": reverse("arpia_scan:session_detail", args=[session.pk]),
        "report_url": report_url,
        "report_snapshot": session.report_snapshot or {},
    }


def _serialize_task(task) -> dict:
    progress_value = getattr(task, "progress", 0) or 0
    progress_percent = getattr(task, "progress_percent", None)
    if progress_percent is None:
        try:
            progress_percent = max(0, min(100, int(round(float(progress_value) * 100))))
        except (TypeError, ValueError):
            progress_percent = 0

    return {
        "id": task.id,
        "order": task.order,
        "kind": task.kind,
        "status": task.status,
        "status_display": task.get_status_display(),
        "kind_display": task.get_kind_display(),
        "name": task.name,
        "progress": progress_value,
        "progress_percent": progress_percent,
        "tool": task.tool.slug if task.tool else None,
        "tool_name": task.tool.name if task.tool else None,
        "script": task.script.slug if task.script else None,
        "script_name": task.script.name if task.script else None,
        "wordlist": task.wordlist.slug if task.wordlist else None,
        "started_at": task.started_at.isoformat() if task.started_at else None,
        "finished_at": task.finished_at.isoformat() if task.finished_at else None,
        "stdout": task.stdout,
        "stderr": task.stderr,
        "duration_seconds": (task.finished_at - task.started_at).total_seconds() if task.finished_at and task.started_at else None,
    }


@login_required
@require_http_methods(["POST"])
def api_session_create(request):
    try:
        payload = json.loads(request.body or "{}")
    except json.JSONDecodeError:
        return JsonResponse({"error": "JSON inválido"}, status=400)

    project_id = payload.get("project_id")
    if not project_id:
        return JsonResponse({"error": "project_id é obrigatório"}, status=400)

    project = get_object_or_404(Project, pk=project_id)

    if not _user_has_access(request.user, project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)

    title = payload.get("title") or f"Scan {project.name}"
    config = {k: v for k, v in payload.items() if k != "project_id"}

    try:
        session = create_planned_session(owner=request.user, project=project, title=title, config=config)
    except ValidationError as exc:
        return JsonResponse({"error": exc.message}, status=403)

    tasks = [_serialize_task(task) for task in session.tasks.order_by("order", "id")]
    response = _serialize_session(session)
    response["tasks"] = tasks
    return JsonResponse(response, status=201)


@login_required
@require_http_methods(["POST"])
def api_session_start(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    if not _user_has_access(request.user, session.project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
    try:
        ScanOrchestrator(session, run_as_user=request.user).run()
    except ValidationError as exc:
        return JsonResponse({"error": exc.message}, status=400)

    session.refresh_from_db()

    response = _serialize_session(session)
    response["tasks"] = [_serialize_task(task) for task in session.tasks.order_by("order", "id")]
    return JsonResponse(response)


@login_required
@require_http_methods(["GET"])
def api_session_status(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    if not _user_has_access(request.user, session.project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
    response = _serialize_session(session)
    response["tasks"] = [_serialize_task(task) for task in session.tasks.order_by("order", "id")]
    response["findings"] = [
        {
            "id": finding.id,
            "kind": finding.kind,
            "kind_display": finding.get_kind_display(),
            "title": finding.title,
            "severity": finding.severity,
            "created_at": finding.created_at.isoformat(),
            "summary": finding.summary,
            "data": finding.data,
        }
        for finding in session.findings.order_by("order", "id")
    ]
    response["report_snapshot"] = session.report_snapshot or {}
    return JsonResponse(response)


def _serialize_log_entry(entry: LogEntry) -> dict:
    timestamp = entry.timestamp
    timestamp_iso = timestamp.isoformat() if timestamp else None
    localized = timezone.localtime(timestamp) if timestamp else None
    return {
        "id": entry.id,
        "timestamp": timestamp_iso,
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
