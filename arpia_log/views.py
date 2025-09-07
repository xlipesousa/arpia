from django.views.generic import TemplateView
from django.shortcuts import render
from django.http import JsonResponse, Http404
from django.core.paginator import Paginator
from django.utils import timezone
import datetime

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
        items = []
        try:
            # se existir modelo LogEntry, use-o
            from .models import LogEntry  # noqa: WPS433 - import dinâmico
            qs = LogEntry.objects.all().order_by("-timestamp")
            for e in qs:
                items.append({
                    "id": getattr(e, "id", None),
                    "timestamp": getattr(e, "timestamp", None),
                    "source": getattr(e, "source", "") or "unknown",
                    "level": getattr(e, "level", "INFO"),
                    "project": getattr(e, "project", "") or "unknown",
                    "message": getattr(e, "message", str(e)),
                    "meta": getattr(e, "meta", {}) or {},
                })
        except Exception:
            # fallback: dados de amostra
            items = _sample_logs()

        # paginação básica (compatível com templates existentes)
        page = self.request.GET.get("page", 1)
        try:
            page_size = int(self.request.GET.get("page_size", 10))
        except (TypeError, ValueError):
            page_size = 10

        paginator = Paginator(items, page_size)
        page_obj = paginator.get_page(page)

        ctx.update({
            "logs_page": page_obj,
            "logs": page_obj.object_list,
        })
        return ctx


def logs_api(request):
    """
    Endpoint JSON para buscar/filtrar logs.
    Query params suportados: q, level, source, project, from, to, page, page_size
    """
    # obter dados (modelo real se existir, senão amostra)
    try:
        from .models import LogEntry  # noqa: WPS433
        qs = LogEntry.objects.all().order_by("-timestamp")
        items = [{
            "id": getattr(e, "id", None),
            "timestamp": getattr(e, "timestamp", None).isoformat() if getattr(e, "timestamp", None) else None,
            "source": getattr(e, "source", ""),
            "level": getattr(e, "level", ""),
            "project": getattr(e, "project", ""),
            "message": getattr(e, "message", ""),
            "meta": getattr(e, "meta", {}) or {},
        } for e in qs]
    except Exception:
        items = _sample_logs()

    # filtros simples
    q = request.GET.get("q", "").strip().lower()
    level = request.GET.get("level", "").strip().upper()
    source = request.GET.get("source", "").strip().lower()
    project = request.GET.get("project", "").strip().lower()

    if q:
        items = [i for i in items if q in (i.get("message") or "").lower() or q in (i.get("project") or "").lower()]

    if level:
        items = [i for i in items if (i.get("level") or "").upper() == level]

    if source:
        items = [i for i in items if source in (i.get("source") or "").lower()]

    if project:
        items = [i for i in items if project in (i.get("project") or "").lower()]

    # range de datas opcional (ISO date)
    dt_from = request.GET.get("from")
    dt_to = request.GET.get("to")
    try:
        if dt_from:
            df = datetime.datetime.fromisoformat(dt_from)
            items = [i for i in items if i.get("timestamp") and datetime.datetime.fromisoformat(i["timestamp"]) >= df]
        if dt_to:
            dt = datetime.datetime.fromisoformat(dt_to)
            items = [i for i in items if i.get("timestamp") and datetime.datetime.fromisoformat(i["timestamp"]) <= dt]
    except Exception:
        # ignorar filtros malformados
        pass

    # paginação JSON
    try:
        page_size = int(request.GET.get("page_size", 10))
    except (TypeError, ValueError):
        page_size = 10
    page = int(request.GET.get("page", 1))

    paginator = Paginator(items, page_size)
    page_obj = paginator.get_page(page)

    return JsonResponse({
        "count": paginator.count,
        "num_pages": paginator.num_pages,
        "page": page_obj.number,
        "results": list(page_obj.object_list),
    }, safe=False)


def log_detail_api(request, pk):
    """
    Retorna JSON com dados do log (placeholder). Se existir model, busca por pk.
    """
    try:
        from .models import LogEntry  # noqa: WPS433
        e = LogEntry.objects.filter(pk=pk).first()
        if not e:
            raise Http404("Log not found")
        item = {
            "id": e.id,
            "timestamp": getattr(e, "timestamp", None).isoformat() if getattr(e, "timestamp", None) else None,
            "source": getattr(e, "source", ""),
            "level": getattr(e, "level", ""),
            "project": getattr(e, "project", ""),
            "message": getattr(e, "message", ""),
            "meta": getattr(e, "meta", {}) or {},
        }
    except Exception:
        # buscar no sample set
        items = _sample_logs()
        item = next((i for i in items if int(i["id"]) == int(pk)), None)
        if not item:
            raise Http404("Log not found (simulado)")
    return JsonResponse(item)
