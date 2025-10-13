import datetime

from django.core.paginator import Paginator
from django.db import OperationalError
from django.db.models import Count
from django.db.models.functions import TruncHour
from django.http import Http404, JsonResponse
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework import serializers as drf_serializers
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import LogEntry
from .serializers import LogEntrySerializer
from .services import log_event_from_payload, validate_ingest_token

def _sample_logs():
    now = timezone.now()
    return [
        {"id": 1, "timestamp": (now - datetime.timedelta(hours=2)).isoformat(), "source": "web", "level": "INFO", "project": "Web App Audit", "message": "Request GET /login 200", "meta": {"ip": "10.0.0.5"}},
        {"id": 2, "timestamp": (now - datetime.timedelta(hours=1, minutes=10)).isoformat(), "source": "scanner", "level": "WARN", "project": "Infra Red Team", "message": "High number of open ports", "meta": {"scan": "nmap"}},
        {"id": 3, "timestamp": (now - datetime.timedelta(minutes=30)).isoformat(), "source": "agent", "level": "ERROR", "project": "API Security", "message": "Auth failure for user admin", "meta": {"user": "admin", "ip": "192.168.1.10"}},
        {"id": 4, "timestamp": (now - datetime.timedelta(minutes=5)).isoformat(), "source": "system", "level": "INFO", "project": "System", "message": "Backup finished", "meta": {}},
    ]


class LogsListView(TemplateView):
    template_name = "logs/list.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        page_size = 25
        page = self.request.GET.get("page", 1)

        try:
            qs = LogEntry.objects.all().order_by("-timestamp")
            paginator = Paginator(qs, page_size)
            page_obj = paginator.get_page(page)
            items = [
                {
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "source": entry.source_app,
                    "level": entry.severity,
                    "project": entry.project_ref,
                    "message": entry.message,
                    "meta": entry.details or {},
                }
                for entry in page_obj
            ]
        except OperationalError:
            page_obj = None
            items = _sample_logs()

        ctx.update({
            "logs_page": page_obj,
            "logs": items,
        })
        return ctx
def logs_api(request):
    """Endpoint JSON para buscar/filtrar logs."""

    try:
        qs = LogEntry.objects.all().order_by("-timestamp")
    except OperationalError:
        sample = _sample_logs()
        return JsonResponse(
            {
                "count": len(sample),
                "num_pages": 1,
                "page": 1,
                "results": sample,
            },
            safe=False,
        )

    term = request.GET.get("q", "").strip()
    level = request.GET.get("level", "").strip().upper()
    source = request.GET.get("source", "").strip()
    project = request.GET.get("project", "").strip()

    if term:
        qs = qs.filter(message__icontains=term)
    if level:
        qs = qs.filter(severity=level)
    if source:
        qs = qs.filter(source_app__icontains=source)
    if project:
        qs = qs.filter(project_ref__icontains=project)

    dt_from = request.GET.get("from")
    dt_to = request.GET.get("to")
    try:
        if dt_from:
            qs = qs.filter(timestamp__gte=datetime.datetime.fromisoformat(dt_from))
        if dt_to:
            qs = qs.filter(timestamp__lte=datetime.datetime.fromisoformat(dt_to))
    except Exception:
        pass

    try:
        page_size = int(request.GET.get("page_size", 25))
    except (TypeError, ValueError):
        page_size = 25
    page = request.GET.get("page", 1)

    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(page)

    items = [
        {
            "id": entry.id,
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
            "source": entry.source_app,
            "level": entry.severity,
            "project": entry.project_ref,
            "message": entry.message,
            "meta": entry.details or {},
        }
        for entry in page_obj
    ]

    return JsonResponse(
        {
            "count": paginator.count,
            "num_pages": paginator.num_pages,
            "page": page_obj.number,
            "results": items,
        },
        safe=False,
    )

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
