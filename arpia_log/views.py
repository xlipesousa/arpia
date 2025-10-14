import datetime
import io
import json

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import OperationalError
from django.db.models import Count, Q
from django.db.models.functions import TruncHour
from django.http import FileResponse, Http404, JsonResponse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.generic import TemplateView
from django.views.decorators.http import require_http_methods, require_POST
from rest_framework import serializers as drf_serializers
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import LogEntry
from .serializers import LogEntrySerializer
from .services import log_event_from_payload, validate_ingest_token


LOG_APPS = [
    {"slug": "arpia_core", "label": "ARPIA Core"},
    {"slug": "arpia_project", "label": "ARPIA Project"},
    {"slug": "arpia_scan", "label": "ARPIA Scan"},
    {"slug": "arpia_vuln", "label": "ARPIA Vuln"},
    {"slug": "arpia_hunt", "label": "ARPIA Hunt"},
    {"slug": "arpia_pentest", "label": "ARPIA Pentest"},
    {"slug": "arpia_report", "label": "ARPIA Report"},
    {"slug": "arpia_ia", "label": "ARPIA IA"},
]


def _serialize_entry(entry: LogEntry) -> dict:
    timestamp = entry.timestamp if entry.timestamp else None
    local_ts = timezone.localtime(timestamp) if timestamp else None
    return {
        "id": entry.id,
        "version": entry.version,
        "timestamp": timestamp.isoformat() if timestamp else None,
        "timestamp_display": local_ts.strftime("%d/%m/%Y %H:%M:%S") if local_ts else "—",
        "source_app": entry.source_app,
        "component": entry.component,
        "event_type": entry.event_type,
        "severity": entry.severity,
        "message": entry.message,
        "details": entry.details or {},
        "context": entry.context or {},
        "correlation": entry.correlation or {},
        "tags": entry.tags or [],
        "project_ref": entry.project_ref,
        "asset_ref": entry.asset_ref,
        "user_ref": entry.user_ref,
        "ingestion_channel": entry.ingestion_channel,
        "ingested_at": entry.ingested_at.isoformat() if entry.ingested_at else None,
    }


def _sample_logs():
    now = timezone.now()
    base = [
        {
            "id": 1,
            "timestamp": (now - datetime.timedelta(hours=2)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(hours=2)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_core",
            "component": "dashboard",
            "event_type": "HTTP_REQUEST",
            "severity": "INFO",
            "message": "Request GET /login 200",
            "details": {"ip": "10.0.0.5"},
            "context": {"actor": {"username": "analyst"}},
            "correlation": {"project": "webapp"},
            "tags": ["http", "auth"],
            "project_ref": "Web App Audit",
            "asset_ref": "web-01",
            "user_ref": "analyst",
            "ingestion_channel": LogEntry.Channel.INTERNAL,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 2,
            "timestamp": (now - datetime.timedelta(hours=1, minutes=10)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(hours=1, minutes=10)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_scan",
            "component": "scanner",
            "event_type": "PORT_SCAN",
            "severity": "WARN",
            "message": "High number of open ports",
            "details": {"scan": "nmap", "ports": [22, 80, 443]},
            "context": {},
            "correlation": {"project": "infra"},
            "tags": ["scan"],
            "project_ref": "Infra Red Team",
            "asset_ref": "10.0.0.5",
            "user_ref": "",
            "ingestion_channel": LogEntry.Channel.BATCH,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 3,
            "timestamp": (now - datetime.timedelta(minutes=30)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(minutes=30)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_vuln",
            "component": "webhook",
            "event_type": "NEW_FINDING",
            "severity": "ERROR",
            "message": "Auth failure for user admin",
            "details": {"user": "admin", "ip": "192.168.1.10"},
            "context": {},
            "correlation": {"project": "api-security"},
            "tags": ["auth"],
            "project_ref": "API Security",
            "asset_ref": "api-gateway",
            "user_ref": "admin",
            "ingestion_channel": LogEntry.Channel.API,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 4,
            "timestamp": (now - datetime.timedelta(minutes=5)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(minutes=5)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_project",
            "component": "scheduler",
            "event_type": "BACKUP_DONE",
            "severity": "INFO",
            "message": "Backup finished",
            "details": {"duration": "5m"},
            "context": {},
            "correlation": {"project": "system"},
            "tags": ["maintenance"],
            "project_ref": "System",
            "asset_ref": "",
            "user_ref": "",
            "ingestion_channel": LogEntry.Channel.INTERNAL,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 5,
            "timestamp": (now - datetime.timedelta(minutes=3)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(minutes=3)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_hunt",
            "component": "intel_agent",
            "event_type": "IOC_MATCH",
            "severity": "NOTICE",
            "message": "Indicator matched on host",
            "details": {"indicator": "md5:abcd"},
            "context": {},
            "correlation": {"project": "hunt"},
            "tags": ["intel"],
            "project_ref": "Threat Hunt",
            "asset_ref": "endpoint-22",
            "user_ref": "",
            "ingestion_channel": LogEntry.Channel.BATCH,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 6,
            "timestamp": (now - datetime.timedelta(minutes=2)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(minutes=2)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_pentest",
            "component": "executor",
            "event_type": "TASK_STATUS",
            "severity": "INFO",
            "message": "Exploit task completed",
            "details": {"task_id": "exploit-123"},
            "context": {},
            "correlation": {"project": "purple"},
            "tags": ["pentest"],
            "project_ref": "Red Team - Q4",
            "asset_ref": "internal-app",
            "user_ref": "pentester",
            "ingestion_channel": LogEntry.Channel.INTERNAL,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 7,
            "timestamp": (now - datetime.timedelta(minutes=1)).isoformat(),
            "timestamp_display": (now - datetime.timedelta(minutes=1)).strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_report",
            "component": "generator",
            "event_type": "REPORT_READY",
            "severity": "INFO",
            "message": "Relatório consolidado disponível",
            "details": {"report_id": "rep-789"},
            "context": {},
            "correlation": {"project": "exec"},
            "tags": ["report"],
            "project_ref": "Executivo",
            "asset_ref": "",
            "user_ref": "",
            "ingestion_channel": LogEntry.Channel.INTERNAL,
            "ingested_at": now.isoformat(),
        },
        {
            "id": 8,
            "timestamp": now.isoformat(),
            "timestamp_display": now.strftime("%d/%m/%Y %H:%M:%S"),
            "source_app": "arpia_ia",
            "component": "assistant",
            "event_type": "MODEL_RESPONSE",
            "severity": "INFO",
            "message": "Modelo respondeu com sucesso",
            "details": {"latency_ms": 230},
            "context": {},
            "correlation": {"project": "assistant"},
            "tags": ["ai"],
            "project_ref": "AI Assist",
            "asset_ref": "",
            "user_ref": "analyst",
            "ingestion_channel": LogEntry.Channel.API,
            "ingested_at": now.isoformat(),
        },
    ]
    return base


class LogsListView(TemplateView):
    template_name = "logs/list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        bootstrap = {app["slug"]: [] for app in LOG_APPS}

        try:
            for app in LOG_APPS:
                entries = (
                    LogEntry.objects.filter(source_app=app["slug"])
                    .order_by("-timestamp")[:50]
                )
                bootstrap[app["slug"]] = [_serialize_entry(entry) for entry in entries]
        except OperationalError:
            sample = _sample_logs()
            for app in LOG_APPS:
                bootstrap[app["slug"]] = [
                    item for item in sample if item["source_app"] == app["slug"]
                ]

        ctx.update(
            {
                "log_apps": LOG_APPS,
                "severity_options": [
                    {"value": value, "label": label}
                    for value, label in LogEntry.Severity.choices
                ],
                "channel_options": [
                    {"value": value, "label": label}
                    for value, label in LogEntry.Channel.choices
                ],
                "bootstrap_logs": bootstrap,
            }
        )
        return ctx
def logs_api(request):
    """Endpoint JSON para buscar/filtrar logs."""

    def _filter_sample(data):
        filtered = data
        source = request.GET.get("source") or request.GET.get("app")
        if source:
            filtered = [item for item in filtered if item["source_app"] == source]

        severity = request.GET.get("severity") or request.GET.get("level")
        if severity:
            levels = {level.strip().upper() for level in severity.split(",") if level.strip()}
            filtered = [item for item in filtered if item["severity"].upper() in levels]

        search = (request.GET.get("search") or request.GET.get("q") or "").strip()
        if search:
            search_lower = search.lower()
            filtered = [
                item
                for item in filtered
                if search_lower in (item["message"] or "").lower()
                or search_lower in (item["event_type"] or "").lower()
                or search_lower in (item["component"] or "").lower()
                or search_lower in (item["project_ref"] or "").lower()
            ]

        component = request.GET.get("component")
        if component:
            filtered = [item for item in filtered if component.lower() in (item["component"] or "").lower()]

        event_type = request.GET.get("event_type")
        if event_type:
            filtered = [item for item in filtered if event_type.lower() in (item["event_type"] or "").lower()]

        project = request.GET.get("project")
        if project:
            filtered = [item for item in filtered if project.lower() in (item["project_ref"] or "").lower()]

        return filtered

    try:
        qs = LogEntry.objects.all()
        backend_ready = True
    except OperationalError:
        backend_ready = False

    if not backend_ready:
        sample = _filter_sample(_sample_logs())
        return JsonResponse(
            {
                "count": len(sample),
                "num_pages": 1,
                "page": 1,
                "results": sample,
            }
        )

    source = request.GET.get("source") or request.GET.get("app")
    if source:
        qs = qs.filter(source_app=source)

    severity = request.GET.get("severity") or request.GET.get("level")
    if severity:
        levels = [level.strip().upper() for level in severity.split(",") if level.strip()]
        if levels:
            qs = qs.filter(severity__in=levels)

    component = request.GET.get("component")
    if component:
        qs = qs.filter(component__icontains=component)

    event_type = request.GET.get("event_type")
    if event_type:
        qs = qs.filter(event_type__icontains=event_type)

    project = request.GET.get("project")
    if project:
        qs = qs.filter(project_ref__icontains=project)

    asset = request.GET.get("asset")
    if asset:
        qs = qs.filter(asset_ref__icontains=asset)

    user_ref = request.GET.get("user") or request.GET.get("user_ref")
    if user_ref:
        qs = qs.filter(user_ref__icontains=user_ref)

    channel = request.GET.get("channel") or request.GET.get("ingestion_channel")
    if channel:
        qs = qs.filter(ingestion_channel=channel)

    tag = request.GET.get("tag")
    if tag:
        qs = qs.filter(tags__contains=[tag])

    search = (request.GET.get("search") or request.GET.get("q") or "").strip()
    if search:
        qs = qs.filter(
            Q(message__icontains=search)
            | Q(component__icontains=search)
            | Q(event_type__icontains=search)
            | Q(project_ref__icontains=search)
            | Q(asset_ref__icontains=search)
            | Q(user_ref__icontains=search)
        )

    since = request.GET.get("since") or request.GET.get("from")
    until = request.GET.get("until") or request.GET.get("to")

    parsed_since = parse_datetime(since) if since else None
    parsed_until = parse_datetime(until) if until else None
    if parsed_since:
        if timezone.is_naive(parsed_since):
            parsed_since = timezone.make_aware(parsed_since, timezone.get_current_timezone())
        qs = qs.filter(timestamp__gte=parsed_since)
    if parsed_until:
        if timezone.is_naive(parsed_until):
            parsed_until = timezone.make_aware(parsed_until, timezone.get_current_timezone())
        qs = qs.filter(timestamp__lte=parsed_until)

    ordering = request.GET.get("ordering", "-timestamp")
    if ordering not in {"timestamp", "-timestamp"}:
        ordering = "-timestamp"
    secondary = "-id" if ordering.startswith("-") else "id"
    qs = qs.order_by(ordering, secondary)

    try:
        page_size = int(request.GET.get("page_size", 50))
    except (TypeError, ValueError):
        page_size = 50
    page_size = max(1, min(page_size, 200))
    page = request.GET.get("page", 1)

    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)

    items = [_serialize_entry(entry) for entry in page_obj.object_list]

    return JsonResponse(
        {
            "count": paginator.count,
            "num_pages": paginator.num_pages,
            "page": page_obj.number,
            "results": items,
        }
    )


@require_http_methods(["GET"])
def log_tail_api(request):
    source = request.GET.get("source") or request.GET.get("app")
    if not source:
        return JsonResponse({"detail": "Parâmetro 'source' é obrigatório."}, status=400)

    since_param = request.GET.get("since")
    limit_param = request.GET.get("limit", 100)
    try:
        limit = max(1, min(int(limit_param), 200))
    except (TypeError, ValueError):
        limit = 100

    parsed_since = parse_datetime(since_param) if since_param else None
    if parsed_since and timezone.is_naive(parsed_since):
        parsed_since = timezone.make_aware(parsed_since, timezone.get_current_timezone())

    try:
        qs = LogEntry.objects.filter(source_app=source)
        if parsed_since:
            qs = qs.filter(timestamp__gt=parsed_since)
        entries = list(qs.order_by("timestamp", "id")[:limit])
        serialized = [_serialize_entry(entry) for entry in entries]
    except OperationalError:
        sample = [item for item in _sample_logs() if item["source_app"] == source]
        if parsed_since:
            sample = [item for item in sample if parse_datetime(item["timestamp"]) > parsed_since]
        serialized = sample[:limit]

    latest = serialized[-1]["timestamp"] if serialized else since_param
    return JsonResponse({"results": serialized, "latest": latest})


@login_required
@require_http_methods(["GET"])
def log_download_api(request, pk: int):
    try:
        entry = LogEntry.objects.filter(pk=pk).first()
    except OperationalError:
        entry = None

    if not entry:
        raise Http404("Log não encontrado")

    payload = _serialize_entry(entry)
    buffer = io.BytesIO(json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
    filename = f"log-{pk}.json"
    response = FileResponse(buffer, as_attachment=True, filename=filename, content_type="application/json")
    response["Content-Length"] = buffer.getbuffer().nbytes
    return response


@login_required
@require_POST
def log_delete_api(request, pk: int):
    try:
        deleted, _ = LogEntry.objects.filter(pk=pk).delete()
    except OperationalError:
        deleted = 0

    if not deleted:
        return JsonResponse({"detail": "Log não encontrado."}, status=404)
    return JsonResponse({"deleted": pk})

class LogStatsView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def get(self, request, *args, **kwargs):
        if not (request.user.is_authenticated or validate_ingest_token(request.headers.get("Authorization"))):
            return Response({"detail": "Não autorizado."}, status=status.HTTP_403_FORBIDDEN)

        try:
            qs = LogEntry.objects.all()
        except OperationalError:
            return Response(
                {
                    "counts": {"by_severity": [], "by_source": [], "top_events": []},
                    "timeline": [],
                    "filters": {
                        "project": request.GET.get("project"),
                        "source": request.GET.get("source"),
                        "severity": request.GET.get("severity"),
                        "hours": request.GET.get("hours", 24),
                    },
                    "warning": "Base de logs ainda não inicializada",
                },
                status=status.HTTP_200_OK,
            )

        project = request.GET.get("project")
        source = request.GET.get("source")
        severity = request.GET.get("severity")

        if project:
            qs = qs.filter(project_ref=project)
        if source:
            qs = qs.filter(source_app=source)
        if severity:
            qs = qs.filter(severity=severity.upper())

        try:
            hours = int(request.GET.get("hours", 24))
        except (TypeError, ValueError):
            hours = 24

        since = timezone.now() - datetime.timedelta(hours=hours)
        qs_since = qs.filter(timestamp__gte=since)

        severity_counts = list(
            qs.values("severity").annotate(total=Count("id")).order_by("severity")
        )
        source_counts = list(
            qs.values("source_app").annotate(total=Count("id")).order_by("source_app")
        )
        event_counts = list(
            qs_since.values("event_type").annotate(total=Count("id")).order_by("-total")[:10]
        )
        timeline = [
            {"bucket": item["bucket"].isoformat(), "total": item["total"]}
            for item in qs_since.annotate(bucket=TruncHour("timestamp"))
            .values("bucket")
            .annotate(total=Count("id"))
            .order_by("bucket")
        ]

        return Response(
            {
                "filters": {
                    "project": project,
                    "source": source,
                    "severity": severity,
                    "hours": hours,
                },
                "counts": {
                    "by_severity": severity_counts,
                    "by_source": source_counts,
                    "top_events": event_counts,
                },
                "timeline": timeline,
            }
        )


def log_detail_api(request, pk):
    """Retorna detalhes de um log específico."""

    try:
        entry = LogEntry.objects.filter(pk=pk).first()
    except OperationalError:
        entry = None

    if entry:
        item = {
            "id": entry.id,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "source": entry.source_app,
            "level": entry.severity,
            "project": entry.project_ref,
            "message": entry.message,
            "meta": entry.details or {},
        }
        return JsonResponse(item)

    sample = _sample_logs()
    item = next((i for i in sample if int(i["id"]) == int(pk)), None)
    if not item:
        raise Http404("Log not found")
    return JsonResponse(item)


class LogIngestView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):
        if not validate_ingest_token(request.headers.get("Authorization")):
            return Response({"detail": "Token inválido."}, status=status.HTTP_403_FORBIDDEN)

        entry = log_event_from_payload(request.data, channel=LogEntry.Channel.API, request=request)
        serializer = LogEntrySerializer(instance=entry)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class LogBulkIngestView(APIView):
    authentication_classes: list = []
    permission_classes: list = []

    def post(self, request, *args, **kwargs):
        if not validate_ingest_token(request.headers.get("Authorization")):
            return Response({"detail": "Token inválido."}, status=status.HTTP_403_FORBIDDEN)

        payload = request.data
        if not isinstance(payload, list):
            return Response({"detail": "Esperado array de eventos."}, status=status.HTTP_400_BAD_REQUEST)

        created = []
        errors = []
        for idx, item in enumerate(payload):
            try:
                entry = log_event_from_payload(item, channel=LogEntry.Channel.API, request=request)
            except drf_serializers.ValidationError as exc:
                errors.append({"index": idx, "detail": exc.detail})
                continue
            except Exception as exc:  # noqa: BLE001
                errors.append({"index": idx, "detail": str(exc)})
                continue

            serializer = LogEntrySerializer(instance=entry)
            created.append(serializer.data)

        status_code = status.HTTP_201_CREATED
        if errors and created:
            status_code = 207
        elif errors and not created:
            status_code = status.HTTP_400_BAD_REQUEST

        return Response({"created": created, "errors": errors}, status=status_code)
