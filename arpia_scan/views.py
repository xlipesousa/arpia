import csv
import json
import logging
import threading
import time
from statistics import mean

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import ValidationError
from django.db import close_old_connections
from django.db.models import Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import urlencode
from django.views import View
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView


def _format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "—"
    try:
        seconds = int(round(float(seconds)))
    except (TypeError, ValueError):
        return "—"
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    parts = []
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if sec and hours < 1:
        parts.append(f"{sec}s")
    return " ".join(parts) if parts else f"{seconds}s"

from arpia_core.models import Project, Script, Tool
from arpia_core.views import build_project_macros  # TODO: mover para util dedicado

from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .models import ScanFinding, ScanSession, ScanTask
from .services import ScanOrchestrator, create_planned_session


logger = logging.getLogger(__name__)
UserModel = get_user_model()

TERMINAL_SESSION_STATUSES = {
    ScanSession.Status.COMPLETED,
    ScanSession.Status.FAILED,
    ScanSession.Status.CANCELED,
}


def _dispatch_session_execution(session_id, user_id=None) -> None:
    """Dispara execução de sessão em uma thread de fundo."""

    session_snapshot = (
        ScanSession.objects.filter(pk=session_id)
        .values("reference", "project_id", "status")
        .first()
    )

    reference = (
        session_snapshot.get("reference")
        if session_snapshot and session_snapshot.get("reference")
        else str(session_id)
    )
    project_id = session_snapshot.get("project_id") if session_snapshot else None

    logger.info("Despachando sessão %s para execução assíncrona", reference)

    log_event(
        source_app="arpia_scan",
        event_type="scan.session.dispatch",
        message=f"Despacho da sessão {reference} para execução em background",
        component="scan.dispatcher",
        context={
            "session_id": str(session_id),
            "session_reference": reference,
            "project_id": str(project_id) if project_id else None,
        },
        correlation={
            "scan_session_id": str(session_id),
            "project_id": str(project_id) if project_id else None,
        },
        tags=["scan", "session", "dispatcher"],
    )

    def _runner():  # pragma: no cover - executa apenas em runtime
        close_old_connections()
        try:
            session = (
                ScanSession.objects.select_related("project", "owner")
                .prefetch_related("tasks__tool", "tasks__script")
                .get(pk=session_id)
            )
        except ScanSession.DoesNotExist:
            logger.warning("Sessão %s não encontrada para execução assíncrona", session_id)
            close_old_connections()
            return

        user = None
        if user_id:
            try:
                user = UserModel.objects.get(pk=user_id)
            except UserModel.DoesNotExist:
                logger.warning("Usuário %s não encontrado para execução de sessão %s", user_id, session_id)

        thread_name = threading.current_thread().name
        started = time.perf_counter()

        log_event(
            source_app="arpia_scan",
            event_type="scan.session.thread.started",
            message=f"Thread {thread_name} iniciou execução da sessão {session.reference}",
            component="scan.dispatcher",
            context={
                "session_id": str(session.pk),
                "session_reference": session.reference,
                "project_id": str(session.project_id),
                "thread_name": thread_name,
            },
            correlation={
                "scan_session_id": str(session.pk),
                "project_id": str(session.project_id),
            },
            tags=["scan", "session", "dispatcher", "thread"],
        )

        try:
            ScanOrchestrator(session, run_as_user=user).run()
        except ValidationError as exc:
            logger.warning("Execução da sessão %s terminou com erro de validação: %s", session_id, exc)
            log_event(
                source_app="arpia_scan",
                event_type="scan.session.thread.validation_error",
                message=f"Execução da sessão {session.reference} encerrada por erro de validação",
                severity=LogEntry.Severity.WARNING,
                component="scan.dispatcher",
                context={
                    "session_id": str(session.pk),
                    "session_reference": session.reference,
                    "project_id": str(session.project_id),
                    "thread_name": thread_name,
                },
                correlation={
                    "scan_session_id": str(session.pk),
                    "project_id": str(session.project_id),
                },
                details={"error": str(exc)},
                tags=["scan", "session", "dispatcher", "thread", "validation"],
            )
        except Exception as exc:  # pragma: no cover - caminho não determinístico
            logger.exception("Falha ao executar sessão %s em background", session_id)
            log_event(
                source_app="arpia_scan",
                event_type="scan.session.thread.crashed",
                message=f"Execução da sessão {session.reference} falhou inesperadamente",
                severity=LogEntry.Severity.ERROR,
                component="scan.dispatcher",
                context={
                    "session_id": str(session.pk),
                    "session_reference": session.reference,
                    "project_id": str(session.project_id),
                    "thread_name": thread_name,
                },
                correlation={
                    "scan_session_id": str(session.pk),
                    "project_id": str(session.project_id),
                },
                details={"error": str(exc)},
                tags=["scan", "session", "dispatcher", "thread", "exception"],
            )
        else:
            elapsed = time.perf_counter() - started
            log_event(
                source_app="arpia_scan",
                event_type="scan.session.thread.completed",
                message=f"Thread {thread_name} concluiu execução da sessão {session.reference}",
                component="scan.dispatcher",
                context={
                    "session_id": str(session.pk),
                    "session_reference": session.reference,
                    "project_id": str(session.project_id),
                    "thread_name": thread_name,
                },
                correlation={
                    "scan_session_id": str(session.pk),
                    "project_id": str(session.project_id),
                },
                details={"duration_seconds": round(elapsed, 3)},
                tags=["scan", "session", "dispatcher", "thread", "completed"],
            )
        finally:
            close_old_connections()

    thread = threading.Thread(target=_runner, name=f"scan-session-{session_id}", daemon=True)
    thread.start()


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


def _collect_connectivity_artifacts(summary: dict) -> list[dict]:
    artifacts = []
    summary = summary or {}
    artifacts_block = summary.get("artifacts", {}) if isinstance(summary.get("artifacts"), dict) else {}
    potential_lists = [
        artifacts_block.get("connectivity"),
        summary.get("connectivity"),
    ]
    for payload in potential_lists:
        if isinstance(payload, list):
            artifacts.extend(payload)
        elif isinstance(payload, dict):
            artifacts.extend(payload.get("entries", []))
    return artifacts


def _build_connectivity_overview(summary: dict) -> dict:
    artifacts = _collect_connectivity_artifacts(summary)
    host_map: dict[str, dict] = {}

    for entry in artifacts:
        host = entry.get("host") or "—"
        bucket = host_map.setdefault(
            host,
            {
                "host": host,
                "reachable": False,
                "ports": {},
                "errors": set(),
            },
        )
        if entry.get("reachable"):
            bucket["reachable"] = True
        error_message = entry.get("error")
        if error_message:
            bucket["errors"].add(error_message)

        for port_info in entry.get("ports", []) or []:
            port_number = port_info.get("port")
            if port_number is None:
                continue
            try:
                port_number = int(port_number)
            except (TypeError, ValueError):
                continue

            existing = bucket["ports"].get(port_number, {})
            status = port_info.get("status") or existing.get("status") or "unknown"
            priority = 2 if status == "open" else 1 if status == "closed" else 0
            existing_priority = 2 if existing.get("status") == "open" else 1 if existing.get("status") == "closed" else 0

            if priority >= existing_priority:
                bucket["ports"][port_number] = {
                    "port": port_number,
                    "status": status,
                    "latency_ms": port_info.get("latency_ms"),
                    "error": port_info.get("error"),
                }

    hosts_view = []
    for host, bucket in sorted(host_map.items(), key=lambda item: item[0]):
        ports = list(bucket["ports"].values())
        open_ports = sorted((p for p in ports if p.get("status") == "open"), key=lambda p: p["port"])
        closed_ports = sorted((p for p in ports if p.get("status") != "open"), key=lambda p: p["port"])
        latencies = [p.get("latency_ms") for p in open_ports if isinstance(p.get("latency_ms"), (int, float))]
        hosts_view.append(
            {
                "host": host,
                "reachable": bucket["reachable"],
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "latency_avg": round(mean(latencies), 2) if latencies else None,
                "latency_min": round(min(latencies), 2) if latencies else None,
                "latency_max": round(max(latencies), 2) if latencies else None,
                "errors": sorted(bucket["errors"]),
            }
        )

    connectivity_summary = summary.get("connectivity") if isinstance(summary.get("connectivity"), dict) else {}
    reachable_hosts = connectivity_summary.get("reachable_hosts", []) if isinstance(connectivity_summary, dict) else []
    unreachable_hosts = connectivity_summary.get("unreachable_hosts", []) if isinstance(connectivity_summary, dict) else []
    checked_ports = connectivity_summary.get("checked_ports", []) if isinstance(connectivity_summary, dict) else []

    return {
        "hosts": hosts_view,
        "totals": {
            "reachable": len(reachable_hosts) or sum(1 for host in hosts_view if host["reachable"]),
            "unreachable": len(unreachable_hosts) or sum(1 for host in hosts_view if not host["reachable"]),
            "checked_ports": len(checked_ports) or len({p["port"] for host in hosts_view for p in host["open_ports"] + host["closed_ports"]}),
        },
    }


def _build_overview_metrics(session: ScanSession, snapshot: dict, connectivity_overview: dict) -> list[dict]:
    snapshot = snapshot or {}
    stats = snapshot.get("stats", {}) if isinstance(snapshot.get("stats"), dict) else {}
    targets = snapshot.get("targets", {}) if isinstance(snapshot.get("targets"), dict) else {}
    timings = snapshot.get("timing", {}) if isinstance(snapshot.get("timing"), dict) else {}

    metrics = [
        {
            "label": "Etapas processadas",
            "value": stats.get("total_tasks", 0),
            "note": f"{stats.get('completed_tasks', 0)} concluídas / {stats.get('failed_tasks', 0)} falhas",
        },
        {
            "label": "Hosts configurados",
            "value": len(targets.get("configured_hosts", []) or []),
            "note": "Definidos nas macros da sessão",
        },
        {
            "label": "Hosts alcançados",
            "value": connectivity_overview.get("totals", {}).get("reachable", 0),
            "note": "Resposta positiva durante o teste",
        },
        {
            "label": "Hosts sem resposta",
            "value": connectivity_overview.get("totals", {}).get("unreachable", 0),
            "note": "Necessitam investigação",
        },
        {
            "label": "Portas observadas",
            "value": targets.get("open_ports", 0) or connectivity_overview.get("totals", {}).get("checked_ports", 0),
            "note": "Com base no snapshot consolidado",
        },
    ]

    started_at = session.started_at or session.created_at
    finished_at = session.finished_at
    duration_seconds = timings.get("duration_seconds")
    if duration_seconds is None and started_at and finished_at:
        duration_seconds = (finished_at - started_at).total_seconds()
    metrics.append(
        {
            "label": "Duração da sessão",
            "value": _format_duration(duration_seconds),
            "note": f"Início {started_at:%d/%m %H:%M} — Fim {finished_at:%d/%m %H:%M}" if finished_at else "Em andamento",
        }
    )

    return metrics


def _build_finding_payload(finding: ScanFinding) -> dict:
    data = finding.data or {}
    payload = {"raw": data}

    if finding.kind == ScanFinding.Kind.SUMMARY:
        payload["hosts"] = data.get("hosts", []) if isinstance(data.get("hosts"), list) else []
        payload["tasks"] = data.get("tasks", []) if isinstance(data.get("tasks"), list) else []
        payload["connectivity"] = data.get("connectivity", []) if isinstance(data.get("connectivity"), list) else []
    elif finding.kind == ScanFinding.Kind.TARGET:
        ports = data.get("ports", []) if isinstance(data.get("ports"), list) else []
        open_ports = [p for p in ports if p.get("status") == "open"]
        closed_ports = [p for p in ports if p.get("status") != "open"]
        payload.update(
            {
                "host": data.get("host"),
                "reachable": data.get("reachable"),
                "open_ports": open_ports,
                "closed_ports": closed_ports,
                "error": data.get("error"),
            }
        )
    return payload


def _format_timestamp(value) -> str:
    if not value:
        return "—"
    dt = parse_datetime(value) if isinstance(value, str) else value
    if not dt:
        return "—"
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_current_timezone())
    return timezone.localtime(dt).strftime("%d/%m %H:%M")


def _build_timeline_entries(snapshot: dict) -> list[dict]:
    entries = []
    for item in snapshot.get("timeline", []) or []:
        if not isinstance(item, dict):
            continue
        entries.append(
            {
                "label": item.get("label"),
                "kind": item.get("kind"),
                "status": item.get("status"),
                "status_display": item.get("status_display"),
                "started_at": _format_timestamp(item.get("started_at")),
                "finished_at": _format_timestamp(item.get("finished_at")),
                "duration": _format_duration(item.get("duration_seconds")),
            }
        )
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
        requested_id = self.request.GET.get("project", "") or ""
        if requested_id:
            for project in projects:
                if str(project.pk) == str(requested_id):
                    return project, str(project.pk)
        if projects:
            project = projects[0]
            return project, str(project.pk)
        return None, ""

    def _action_cards(self, selected_project_id: str) -> list[dict]:
        has_project = bool(selected_project_id)
        user = self.request.user
        cards: list[dict] = [
            {
                "kind": "connectivity",
                "title": "Teste de conectividade",
                "description": "Valide reachability, interface e rotas antes de iniciar scans pesados.",
                "badge": "Obrigatório",
                "enabled": has_project,
                "script_slug": None,
                "required_tool_slug": None,
                "tasks": [
                    {
                        "kind": ScanTask.Kind.CONNECTIVITY,
                        "name": "Teste de conectividade",
                        "parameters": {},
                    }
                ],
            }
        ]

        scripts = Script.objects.for_user(user).order_by("name")
        tools_map = {tool.slug: tool for tool in Tool.objects.for_user(user)}

        for script in scripts:
            required_tool_slug = script.required_tool_slug or ""
            required_tool = tools_map.get(required_tool_slug) if required_tool_slug else None
            enabled = has_project and (not required_tool_slug or required_tool is not None)

            card = {
                "kind": f"script:{script.slug}",
                "title": script.name,
                "description": script.description or "Execução de script personalizado do repositório.",
                "badge": "Script",
                "enabled": enabled,
                "script_slug": script.slug,
                "required_tool_slug": required_tool_slug or None,
                "required_tool_name": required_tool.name if required_tool else None,
                "requires_tool_registered": bool(required_tool_slug),
                "missing_tool": bool(required_tool_slug and not required_tool),
                "tasks": [
                    {
                        "kind": ScanTask.Kind.CONNECTIVITY,
                        "name": "Teste de conectividade",
                        "parameters": {},
                    },
                    {
                        "kind": ScanTask.Kind.SCRIPT,
                        "name": script.name,
                        "script": script.slug,
                        "tool": required_tool_slug or None,
                        "parameters": {
                            "script_slug": script.slug,
                        },
                    },
                ],
            }

            cards.append(card)

        return cards

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
        serialized_tasks = [_serialize_task(task) for task in tasks]
        total_tasks_count = len(tasks)
        completed_tasks_count = _calculate_completed_tasks(tasks)
        overall_progress_percent = _calculate_overall_progress(session.status, tasks)
        logs_limit = 100
        bootstrap_logs_qs = (
            LogEntry.objects.filter(correlation__scan_session_id=str(session.pk))
            .order_by("timestamp", "id")[:logs_limit]
        )
        serialized_logs = [_serialize_log_entry(entry) for entry in bootstrap_logs_qs]
        findings_qs = session.findings.select_related("source_task").order_by("order", "id")
        finding_rows = [
            {
                "instance": finding,
                "payload": _build_finding_payload(finding),
                "raw_json": json.dumps(finding.data, indent=2, ensure_ascii=False) if finding.data else "",
            }
            for finding in findings_qs
        ]

        snapshot = session.report_snapshot or {}
        summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary"), dict) else {}
        connectivity_overview = _build_connectivity_overview(summary)
        overview_metrics = _build_overview_metrics(session, snapshot, connectivity_overview)
        timeline_entries = _build_timeline_entries(snapshot)

        context.update(
            {
                "session": session,
                "project": session.project,
                "tasks": tasks,
                "overall_progress_percent": overall_progress_percent,
                "completed_tasks_count": completed_tasks_count,
                "total_tasks_count": total_tasks_count,
                "findings": finding_rows,
                "macros": macros,
                "macro_entries": macro_entries,
                "report": snapshot,
                "report_summary": summary,
                "overview_metrics": overview_metrics,
                "connectivity_overview": connectivity_overview,
                "report_insights": snapshot.get("insights", []),
                "report_stats": snapshot.get("stats", {}),
                "report_targets": snapshot.get("targets", {}),
                "report_services": snapshot.get("services", {}),
                "timeline_entries": timeline_entries,
                "report_url": self._build_report_url(session),
                "logs_url": reverse("arpia_scan:api_session_logs", args=[session.pk]),
                "session_bootstrap": {
                    "session": _serialize_session(session),
                    "status": session.status,
                    "status_display": session.get_status_display(),
                    "tasks": serialized_tasks,
                    "logs": serialized_logs,
                    "overall_progress_percent": overall_progress_percent,
                    "completed_tasks_count": completed_tasks_count,
                    "total_tasks_count": total_tasks_count,
                    "latest_log_cursor": serialized_logs[-1]["timestamp"] if serialized_logs else None,
                    "overview_metrics": overview_metrics,
                    "report_insights": snapshot.get("insights", []),
                    "connectivity_overview": connectivity_overview,
                    "timeline_entries": timeline_entries,
                    "report_summary": summary,
                    "report_stats": snapshot.get("stats", {}),
                    "report_targets": snapshot.get("targets", {}),
                    "report_services": snapshot.get("services", {}),
                },
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
    "notes": session.notes or "",
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


def _resolve_task_status(task) -> str:
    if isinstance(task, dict):
        status = task.get("status")
    else:
        status = getattr(task, "status", "")
    return (status or "").lower()


def _resolve_task_progress_percent(task) -> int:
    if isinstance(task, dict):
        percent = task.get("progress_percent")
        progress_value = task.get("progress")
    else:
        percent = getattr(task, "progress_percent", None)
        progress_value = getattr(task, "progress", None)

    if percent is None:
        try:
            percent = float(progress_value or 0)
            percent = int(round(percent * 100))
        except (TypeError, ValueError):
            percent = 0

    try:
        return max(0, min(100, int(percent)))
    except (TypeError, ValueError):  # pragma: no cover - defensivo
        return 0


def _calculate_completed_tasks(tasks) -> int:
    return sum(1 for task in tasks if _resolve_task_status(task) == ScanTask.Status.COMPLETED)


def _calculate_overall_progress(session_status: str, tasks) -> int:
    if not tasks:
        return 100 if session_status in TERMINAL_SESSION_STATUSES else 0

    total = 0
    count = 0

    for task in tasks:
        total += _resolve_task_progress_percent(task)
        count += 1

    if not count:
        return 100 if session_status in TERMINAL_SESSION_STATUSES else 0

    average = int(round(total / count))
    normalized = max(0, min(100, average))

    if session_status in TERMINAL_SESSION_STATUSES:
        return 100

    return normalized


def _build_session_payload(session: ScanSession) -> dict:
    tasks = [_serialize_task(task) for task in session.tasks.order_by("order", "id")]
    payload = _serialize_session(session)
    payload["tasks"] = tasks
    payload["total_tasks_count"] = len(tasks)
    payload["completed_tasks_count"] = _calculate_completed_tasks(tasks)
    payload["overall_progress_percent"] = _calculate_overall_progress(session.status, tasks)
    return payload


def _await_status_transition(session: ScanSession, *, timeout: float = 1.5, interval: float = 0.1) -> None:
    """Espera transição de status após disparo assíncrono."""

    if timeout <= 0:
        return

    deadline = time.monotonic() + timeout
    planned_status = ScanSession.Status.PLANNED

    while time.monotonic() < deadline:
        session.refresh_from_db()
        if session.status != planned_status:
            return
        if session.is_terminal:
            return
        time.sleep(interval)


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

    response = _build_session_payload(session)
    return JsonResponse(response, status=201)


@login_required
@require_http_methods(["POST"])
def api_session_start(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    if not _user_has_access(request.user, session.project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
    if session.status == ScanSession.Status.RUNNING:
        return JsonResponse(_build_session_payload(session), status=409)

    if session.is_terminal:
        return JsonResponse({"error": "Sessão já foi finalizada."}, status=400)

    if settings.TESTING:
        try:
            ScanOrchestrator(session, run_as_user=request.user).run()
        except ValidationError as exc:
            return JsonResponse({"error": exc.message}, status=400)
        session.refresh_from_db()
        return JsonResponse(_build_session_payload(session))

    log_event(
        source_app="arpia_scan",
        event_type="scan.session.start.requested",
        message=f"Início da sessão {session.reference} solicitado",
        component="scan.api",
        context={
            "session_id": str(session.pk),
            "session_reference": session.reference,
            "project_id": str(session.project_id),
        },
        correlation={
            "scan_session_id": str(session.pk),
            "project_id": str(session.project_id),
        },
        tags=["scan", "session", "api", "start"],
        request=request,
    )

    _dispatch_session_execution(session.pk, request.user.pk)
    _await_status_transition(session)
    session.refresh_from_db()

    response = _build_session_payload(session)
    return JsonResponse(response, status=202)


@login_required
@require_http_methods(["GET"])
def api_session_status(request, pk):
    session = get_object_or_404(ScanSession, pk=pk)
    if not _user_has_access(request.user, session.project):
        return JsonResponse({"error": "Usuário não possui acesso a este projeto."}, status=403)
    tasks = [_serialize_task(task) for task in session.tasks.order_by("order", "id")]
    response = _serialize_session(session)
    response["tasks"] = tasks
    response["total_tasks_count"] = len(tasks)
    response["completed_tasks_count"] = _calculate_completed_tasks(tasks)
    response["overall_progress_percent"] = _calculate_overall_progress(session.status, tasks)
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
    snapshot = session.report_snapshot or {}
    summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary"), dict) else {}
    connectivity_overview = _build_connectivity_overview(summary)
    overview_metrics = _build_overview_metrics(session, snapshot, connectivity_overview)
    timeline_entries = _build_timeline_entries(snapshot)

    response["report_snapshot"] = snapshot
    response["report_summary"] = summary
    response["overview_metrics"] = overview_metrics
    response["connectivity_overview"] = connectivity_overview
    response["report_insights"] = snapshot.get("insights", [])
    response["report_stats"] = snapshot.get("stats", {})
    response["report_targets"] = snapshot.get("targets", {})
    response["report_services"] = snapshot.get("services", {})
    response["timeline_entries"] = timeline_entries
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
