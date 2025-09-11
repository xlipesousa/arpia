from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.urls import reverse
from django.views import View
from django.http import JsonResponse, FileResponse, HttpResponse
from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import datetime


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


# --- novos placeholders para reports ---
class ReportDetailView(LoginRequiredMixin, TemplateView):
    template_name = "reports/detail.html"


class ReportGenerateView(LoginRequiredMixin, View):
    """
    Placeholder que simula enfileiramento/geração do relatório.
    Retorna JSON com estado.
    """
    def post(self, request, pk, *args, **kwargs):
        # Simular processo assíncrono: retornar queued
        return JsonResponse({"status": "queued", "id": pk})


def reports_download(request, pk):
    """
    Placeholder de download: retorna JSON simulando um link ou content.
    """
    return JsonResponse({"status": "ok", "id": pk, "download_url": f"/media/reports/report-{pk}.pdf"})


@require_http_methods(["GET", "POST"])
def projects_create(request):
    """
    View de criação de projeto com validação server-side mínima.
    - Campos: name (required), description, client, start, end
    - Tenta salvar em app_project.models.Project se existir, senão grava em session (temporário)
    """
    errors = {}
    # tentar carregar clients reais, senão fallback exemplares
    clients = []
    try:
        from app_project.models import Client  # app responsável conforme instrução
        clients_qs = Client.objects.all()
        clients = [{"id": c.id, "name": getattr(c, "name", str(c))} for c in clients_qs]
    except Exception:
        clients = [{"id": "infra", "name": "Infra Red Team"}, {"id": "webapp", "name": "Web App Audit"}]

    form = {
        "name": "",
        "description": "",
        "client": "",
        "start": "",
        "end": "",
    }

    if request.method == "POST":
        form["name"] = request.POST.get("name", "").strip()
        form["description"] = request.POST.get("description", "").strip()
        form["client"] = request.POST.get("client", "").strip()
        form["start"] = request.POST.get("start", "").strip()
        form["end"] = request.POST.get("end", "").strip()

        # validações
        if not form["name"]:
            errors["name"] = "O nome é obrigatório."

        dt_start = dt_end = None
        if form["start"]:
            try:
                dt_start = datetime.datetime.fromisoformat(form["start"])
            except Exception:
                errors["start"] = "Data/hora de início inválida."
        if form["end"]:
            try:
                dt_end = datetime.datetime.fromisoformat(form["end"])
            except Exception:
                errors["end"] = "Data/hora de término inválida."

        if dt_start and dt_end and dt_end < dt_start:
            errors["end"] = "Data de término não pode ser anterior ao início."

        if not errors:
            # tentar persistir em modelo Project (se existir), senão guardar em sessão (temporário)
            try:
                from app_project.models import Project
                p = Project(
                    name=form["name"],
                    description=form["description"],
                    start=dt_start,
                    end=dt_end
                )
                # se existir campo client relacionado, tentar atribuir
                if hasattr(p, "client_id") and form["client"]:
                    try:
                        # tenta converter id para int, senão usa string
                        p.client_id = int(form["client"])
                    except Exception:
                        p.client_id = form["client"]
                p.save()
            except Exception:
                tmp = request.session.get("tmp_projects", [])
                tmp.append({
                    "id": len(tmp) + 1,
                    "name": form["name"],
                    "description": form["description"],
                    "client": form["client"],
                    "start": form["start"],
                    "end": form["end"],
                })
                request.session["tmp_projects"] = tmp
            return redirect("projects_list")

    return render(request, "projects/new.html", {"clients": clients, "errors": errors, "form": form})


def projects_list(request):
    """
    Lista simples de projetos para compatibilidade com o template projects/list.html.
    Usa modelo Project se disponível, senão dados salvos em sessão.
    """
    projects = []
    try:
        from app_project.models import Project
        qs = Project.objects.all().order_by("-id")
        projects = [{"id": p.id, "name": getattr(p, "name", str(p)), "client": getattr(p, "client", None)} for p in qs]
    except Exception:
        projects = request.session.get("tmp_projects", [])
    return render(request, "projects/list.html", {"projects": projects})


def scripts_list(request):
    """
    Lista scripts (default + personalizados). Usa modelo Script quando existir,
    caso contrário fornece dados fictícios. Paginação via querystring page/page_size.
    """
    items = []
    try:
        from .models import Script  # noqa: WPS433
        qs = Script.objects.all().order_by('-id')
        for s in qs:
            items.append({
                "id": getattr(s, "id", ""),
                "name": getattr(s, "name", getattr(s, "title", str(s))),
                "description": getattr(s, "description", "") or "",
                "type": "custom" if getattr(s, "is_user", False) else "default",
            })
    except Exception:
        # dados fictícios
        items = [
            {"id": 1, "name": "nmap-scan-basic", "description": "Nmap scan rápido", "type": "default"},
            {"id": 2, "name": "sqlmap-detect", "description": "Scan básico SQLi", "type": "default"},
            {"id": 3, "name": "hydra-brute-ssh", "description": "Brute-force SSH (demo)", "type": "default"},
            {"id": 101, "name": "minha-varredura-web", "description": "Script personalizado para sites", "type": "custom"},
            {"id": 102, "name": "lista-hosts", "description": "Meu script de inventário", "type": "custom"},
        ]

    # paginação
    page = request.GET.get("page", 1)
    try:
        page_size = int(request.GET.get("page_size", 10))
    except (TypeError, ValueError):
        page_size = 10

    paginator = Paginator(items, page_size)
    page_obj = paginator.get_page(page)

    return render(request, "scripts/list.html", {"scripts_page": page_obj, "scripts": page_obj.object_list})


def scripts_create(request):
    # placeholder: aqui implementaremos form de criação
    messages.info(request, "Criar script: funcionalidade pendente (placeholder).")
    return redirect("scripts_list")


def scripts_edit(request, pk):
    # placeholder: form de edição
    messages.info(request, f"Editar script {pk}: funcionalidade pendente (placeholder).")
    return redirect("scripts_list")


def scripts_delete(request, pk):
    # placeholder: excluir (apenas feedback)
    messages.success(request, f"Script {pk} removido (simulado).")
    return redirect("scripts_list")


def scripts_clone(request, pk):
    # placeholder: clonar default -> cria cópia simulada
    messages.success(request, f"Script {pk} clonado para personalizado (simulado).")
    return redirect("scripts_list")


def scripts_reset(request, pk):
    # placeholder: resetar script default a partir do original
    messages.success(request, f"Script {pk} restaurado para default (simulado).")
    return redirect("scripts_list")


def scripts_run(request, pk):
    # endpoint simples para executar (simulação)
    return JsonResponse({"status": "ok", "action": "run", "id": pk})


def tools_list(request):
    """
    Lista a página de Tools (aponta para templates/tools/list.html).
    Usa dados fictícios no template — view placeholder.
    """
    return render(request, "tools/list.html", {})


def tools_add(request):
    """
    Placeholder para adicionar ferramenta.
    """
    messages.info(request, "Adicionar ferramenta: funcionalidade pendente (placeholder).")
    return redirect(reverse("tools_list"))


def tools_configure(request, pk):
    """
    Placeholder para configurar uma ferramenta (pk).
    """
    messages.info(request, f"Configurar ferramenta {pk}: funcionalidade pendente (placeholder).")
    return redirect(reverse("tools_list"))


def tools_delete(request, pk):
    """
    Placeholder para excluir ferramenta (simulado).
    """
    messages.success(request, f"Ferramenta {pk} removida (simulado).")
    return redirect(reverse("tools_list"))


def wordlists_add(request):
    messages.info(request, "Adicionar wordlist: funcionalidade pendente (placeholder).")
    return redirect(reverse("tools_list"))


def wordlists_edit(request, pk):
    messages.info(request, f"Editar wordlist {pk}: funcionalidade pendente (placeholder).")
    return redirect(reverse("tools_list"))


def wordlists_delete(request, pk):
    messages.success(request, f"Wordlist {pk} removida (simulado).")
    return redirect(reverse("tools_list"))


def wordlists_download(request, pk):
    """
    Placeholder para download de wordlist.
    Retorna JSON simulando link/estado.
    """
    return JsonResponse({"status": "ok", "action": "download", "id": pk})


@require_http_methods(["GET", "POST"])
def projects_edit(request, pk):
    """
    Edita um projeto existente. Atualiza modelo real (se existir) ou fallback para sessão.
    Compatível com o template projects/edit.html.
    """
    errors = {}
    try:
        from app_project.models import Client  # para compatibilidade (não obrigatório)
        clients_qs = Client.objects.all()
        clients = [{"id": c.id, "name": getattr(c, "name", str(c))} for c in clients_qs]
    except Exception:
        clients = [{"id": "infra", "name": "Infra Red Team"}, {"id": "webapp", "name": "Web App Audit"}]

    project_obj = None
    project = {}
    # tentar carregar instância real
    try:
        try:
            from app_project.models import Project as ProjectModel
        except Exception:
            from .models import Project as ProjectModel
        project_obj = ProjectModel.objects.filter(pk=pk).first()
    except Exception:
        project_obj = None

    # fallback para sessão
    if not project_obj:
        tmp = request.session.get("tmp_projects", [])
        project = next((p for p in tmp if p.get("id") == pk), {}) or {}
    else:
        project = {
            "id": project_obj.id,
            "name": getattr(project_obj, "name", "") or "",
            "description": getattr(project_obj, "description", "") or "",
            "client": getattr(getattr(project_obj, "client", None), "id", getattr(project_obj, "client", "")) or "",
            "start": getattr(project_obj, "start", "") or "",
            "end": getattr(project_obj, "end", "") or "",
            "hosts": getattr(project_obj, "hosts", "") or "",
            "networks": getattr(project_obj, "networks", "") or "",
            "ports": getattr(project_obj, "ports", "") or "",
            "credentials_json": getattr(project_obj, "credentials_json", "[]") or "[]",
            "credentials": getattr(project_obj, "credentials", []) or [],
        }

    form = {
        "name": project.get("name", ""),
        "description": project.get("description", ""),
        "client": project.get("client", ""),
        "start": project.get("start", ""),
        "end": project.get("end", ""),
        "hosts": project.get("hosts", ""),
        "networks": project.get("networks", ""),
        "ports": project.get("ports", ""),
        "credentials_json": project.get("credentials_json", "[]"),
        "credentials": project.get("credentials", []),
    }

    if request.method == "POST":
        form["name"] = request.POST.get("name", "").strip()
        form["description"] = request.POST.get("description", "").strip()
        form["client"] = request.POST.get("client", "").strip()
        form["start"] = request.POST.get("start", "").strip()
        form["end"] = request.POST.get("end", "").strip()
        form["hosts"] = request.POST.get("hosts", "").strip()
        form["networks"] = request.POST.get("networks", "").strip()
        form["ports"] = request.POST.get("ports", "").strip()
        form["credentials_json"] = request.POST.get("credentials_json", form["credentials_json"])

        if not form["name"]:
            errors["name"] = "O nome é obrigatório."

        dt_start = dt_end = None
        if form["start"]:
            try:
                dt_start = datetime.datetime.fromisoformat(form["start"])
            except Exception:
                errors["start"] = "Data/hora de início inválida."
        if form["end"]:
            try:
                dt_end = datetime.datetime.fromisoformat(form["end"])
            except Exception:
                errors["end"] = "Data/hora de término inválida."

        if dt_start and dt_end and dt_end < dt_start:
            errors["end"] = "Data de término não pode ser anterior ao início."

        if not errors:
            try:
                # prioriza modelo real
                try:
                    from app_project.models import Project as ProjectModel
                except Exception:
                    from .models import Project as ProjectModel

                if project_obj:
                    p = project_obj
                    p.name = form["name"]
                    p.description = form["description"]
                    p.start = dt_start
                    p.end = dt_end
                else:
                    p = ProjectModel(
                        name=form["name"],
                        description=form["description"],
                        start=dt_start,
                        end=dt_end
                    )

                if hasattr(p, "client_id") and form["client"]:
                    try:
                        p.client_id = int(form["client"])
                    except Exception:
                        p.client_id = form["client"]

                if hasattr(p, "hosts"):
                    setattr(p, "hosts", form.get("hosts", ""))
                if hasattr(p, "networks"):
                    setattr(p, "networks", form.get("networks", ""))
                if hasattr(p, "ports"):
                    setattr(p, "ports", form.get("ports", ""))
                if hasattr(p, "credentials_json"):
                    setattr(p, "credentials_json", form.get("credentials_json", "[]"))

                p.save()
                messages.success(request, "Projeto salvo com sucesso.")
                return redirect("projects_list")
            except Exception:
                # fallback sessão
                tmp = request.session.get("tmp_projects", [])
                found = False
                for i, it in enumerate(tmp):
                    if it.get("id") == pk:
                        tmp[i].update({
                            "name": form["name"],
                            "description": form["description"],
                            "client": form["client"],
                            "start": form["start"],
                            "end": form["end"],
                            "hosts": form.get("hosts", ""),
                            "networks": form.get("networks", ""),
                            "ports": form.get("ports", ""),
                        })
                        found = True
                        break
                if not found:
                    tmp.append({
                        "id": pk,
                        "name": form["name"],
                        "description": form["description"],
                        "client": form["client"],
                        "start": form["start"],
                        "end": form["end"],
                        "hosts": form.get("hosts", ""),
                        "networks": form.get("networks", ""),
                        "ports": form.get("ports", ""),
                    })
                request.session["tmp_projects"] = tmp
                messages.success(request, "Projeto salvo na sessão (fallback).")
                return redirect("projects_list")

    return render(request, "projects/edit.html", {"project": project, "form": form, "clients": clients, "errors": errors})
