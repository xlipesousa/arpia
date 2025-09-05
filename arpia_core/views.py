from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.urls import reverse
from django.views import View
from django.http import JsonResponse


class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/home.html"


class ProjectsListView(LoginRequiredMixin, TemplateView):
    template_name = "projects/list.html"


class ScriptsListView(LoginRequiredMixin, TemplateView):
    template_name = "scripts/list.html"


class ToolsListView(LoginRequiredMixin, TemplateView):
    template_name = "tools/list.html"


class ReportsListView(LoginRequiredMixin, TemplateView):
    template_name = "reports/list.html"


class LogsListView(LoginRequiredMixin, TemplateView):
    template_name = "logs/list.html"


class HealthCheck(View):
    """
    Endpoint de healthcheck simples usado por arpia_core/urls.py.
    Retorna 200 OK com payload mínimo.
    """
    def get(self, request, *args, **kwargs):
        return JsonResponse({"status": "ok", "service": "arpia_core"}, status=200)


def projects_list(request):
    """
    Lista paginada de projetos.
    - tenta usar arpia_core.models.Project se existir;
    - se não houver model/erro, usa dados fictícios.
    """
    items = []
    try:
        from .models import Project  # noqa: WPS433 - import dinâmico por compatibilidade
        qs = Project.objects.all().order_by('-id')
        for obj in qs:
            # owner fallback
            owner = getattr(obj, "owner", None) or getattr(obj, "created_by", None)
            owner_name = getattr(owner, "username", str(owner)) if owner else "---"

            # created fallback (várias convenções)
            created = (
                getattr(obj, "created_at", None)
                or getattr(obj, "created", None)
                or getattr(obj, "created_on", None)
                or getattr(obj, "date_created", None)
            )
            created_str = created.strftime("%Y-%m-%d") if getattr(created, "strftime", None) else (str(created) if created else "")

            status = getattr(obj, "status", None) or getattr(obj, "state", None) or "Ativo"

            items.append({
                "id": getattr(obj, "id", ""),
                "name": getattr(obj, "name", getattr(obj, "title", str(obj))),
                "owner": owner_name,
                "created": created_str,
                "status": str(status),
            })
    except Exception:
        # dados fictícios
        items = [
            {"id": 1, "name": "Infra Red Team", "owner": "alice", "created": "2025-08-01", "status": "Ativo"},
            {"id": 2, "name": "Web App Audit", "owner": "bob", "created": "2025-06-12", "status": "Em revisão"},
            {"id": 3, "name": "Pentest Finance", "owner": "carol", "created": "2025-07-20", "status": "Concluído"},
            {"id": 4, "name": "Continuous Hunt", "owner": "dave", "created": "2025-05-02", "status": "Planejado"},
            {"id": 5, "name": "API Security", "owner": "erin", "created": "2025-03-18", "status": "Ativo"},
            {"id": 6, "name": "Mobile Audit", "owner": "frank", "created": "2025-01-09", "status": "Em revisão"},
            {"id": 7, "name": "Retention Test", "owner": "gina", "created": "2024-12-30", "status": "Planejado"},
        ]

    # paginação
    page = request.GET.get("page", 1)
    try:
        page_size = int(request.GET.get("page_size", 10))
    except (TypeError, ValueError):
        page_size = 10

    paginator = Paginator(items, page_size)
    page_obj = paginator.get_page(page)

    return render(request, "projects/list.html", {"projects_page": page_obj, "projects": page_obj.object_list})


def projects_create(request):
    """
    Placeholder simples para 'Novo Projeto'.
    Por enquanto redireciona para a lista. Se quiser, posso criar o formulário.
    """
    return redirect(reverse("projects_list"))
