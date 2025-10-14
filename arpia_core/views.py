from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
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
from django.db.models import Q
import datetime
import os
from pathlib import Path

from .project_logging import (
    log_project_created,
    log_project_member_added,
    log_project_member_removed,
    log_project_member_updated,
)

SCRIPTS_BASE = Path(__file__).resolve().parent / "scripts"


def ensure_script_dirs():
    """
    Garante a existência da árvore de scripts:
    arpia_core/scripts/
      ├─ default/
      └─ user/
           └─ <username>/
    Cria um script de exemplo em default se o diretório default estiver vazio.
    """
    try:
        (SCRIPTS_BASE / "default").mkdir(parents=True, exist_ok=True)
        (SCRIPTS_BASE / "user").mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    # criar um exemplo em default se estiver vazio
    try:
        default_dir = SCRIPTS_BASE / "default"
        if not any(default_dir.iterdir()):
            sample = default_dir / "example_reset.sh"
            sample.write_text("#!/usr/bin/env bash\n\necho \"Script default de restore — exemplo\"\n", encoding="utf-8")
            sample.chmod(0o755)
    except Exception:
        pass


def safe_filename(name: str) -> str:
    """
    Sanitiza o nome do arquivo: remove caminhos e caracteres perigosos.
    Retorna basename simples; se inválido, retorna empty string.
    """
    if not name:
        return ""
    name = os.path.basename(name)
    # proibir caminhos relativos ../ e nomes com barras
    if '/' in name or '\\' in name or name in ('.', '..'):
        return ""
    # limitar caracteres básicos
    allowed = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    cleaned = ''.join(ch for ch in name if ch in allowed)
    return cleaned.strip()


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


def _parse_datetime_local(value: str):
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(value)
        if dt.tzinfo is None:
            from django.utils import timezone

            return timezone.make_aware(dt, timezone.get_current_timezone())
        return dt
    except ValueError:
        return None


@login_required
@require_http_methods(["GET", "POST"])
def projects_create(request):
    from django.utils import timezone

    errors = {}
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

        if not form["name"]:
            errors["name"] = "O nome é obrigatório."

        dt_start = _parse_datetime_local(form["start"])
        dt_end = _parse_datetime_local(form["end"])

        if form["start"] and not dt_start:
            errors["start"] = "Data/hora de início inválida."
        if form["end"] and not dt_end:
            errors["end"] = "Data/hora de término inválida."
        if dt_start and dt_end and dt_end < dt_start:
            errors["end"] = "Data de término não pode ser anterior ao início."

        if not errors:
            from .models import Project, ProjectMembership

            project = Project(
                owner=request.user,
                name=form["name"],
                description=form["description"],
                client_name=form["client"],
                start_at=dt_start,
                end_at=dt_end,
                timezone=str(timezone.get_current_timezone()),
            )
            project.save()
            ProjectMembership.objects.get_or_create(
                project=project,
                user=request.user,
                defaults={"role": ProjectMembership.Role.OWNER, "invited_by": request.user},
            )
            log_project_created(project, request=request)
            messages.success(request, "Projeto criado com sucesso.")
            return redirect("projects_edit", pk=project.pk)

    return render(request, "projects/new.html", {"errors": errors, "form": form})


@login_required
def projects_list(request):
    from django.db.models import Q
    from django.utils import timezone

    from .models import Project

    page = request.GET.get("page", 1)
    try:
        page_size = int(request.GET.get("page_size", 10))
    except (TypeError, ValueError):
        page_size = 10

    queryset = (
        Project.objects.select_related("owner")
        .filter(Q(owner=request.user) | Q(memberships__user=request.user))
        .distinct()
        .order_by("-created")
    )

    paginator = Paginator(queryset, page_size)
    page_obj = paginator.get_page(page)

    projects_table = []
    for project in page_obj.object_list:
        created = timezone.localtime(project.created)
        projects_table.append(
            {
                "id": project.pk,
                "name": project.name,
                "owner": project.owner_display,
                "created": created.strftime("%Y-%m-%d %H:%M"),
                "status": project.get_status_display(),
                "detail_url": reverse("projects_detail", kwargs={"pk": project.pk}),
                "share_url": reverse("projects_share", kwargs={"pk": project.pk}),
                "edit_url": reverse("projects_edit", kwargs={"pk": project.pk}),
            }
        )

    context = {
        "projects": projects_table,
        "projects_page": page_obj,
    }
    return render(request, "projects/list.html", context)


def _get_accessible_project(user, pk, *, owner_only=False):
    from .models import Project

    base_qs = Project.objects.select_related("owner").prefetch_related("memberships__user")
    if owner_only:
        return get_object_or_404(base_qs.filter(owner=user), pk=pk)
    return get_object_or_404(
        base_qs.filter(Q(owner=user) | Q(memberships__user=user)).distinct(),
        pk=pk,
    )


@login_required
def projects_detail(request, pk):
    project = _get_accessible_project(request.user, pk)
    assets = project.assets.all().order_by("-last_seen")[:100]
    memberships = project.memberships.select_related("user").all()

    context = {
        "project": project,
        "assets": assets,
        "memberships": memberships,
    }
    return render(request, "projects/detail.html", context)


@login_required
@require_http_methods(["GET", "POST"])
def projects_share(request, pk):
    from django.contrib.auth import get_user_model
    from .models import ProjectMembership

    project = _get_accessible_project(request.user, pk, owner_only=True)
    errors = {}
    success = False

    role_choices = list(ProjectMembership.Role.choices)
    form_data = {
        "username": "",
        "role": ProjectMembership.Role.VIEWER,
    }

    if request.method == "POST":
        action = request.POST.get("action", "add")

        if action == "remove":
            membership_id = request.POST.get("membership_id")
            membership = project.memberships.filter(pk=membership_id).select_related("user").first()
            if not membership:
                errors["membership"] = "Participante não encontrado."
            elif membership.user_id == project.owner_id:
                errors["membership"] = "Não é possível remover o proprietário do projeto."
            else:
                log_project_member_removed(project, membership, request=request)
                membership.delete()
                messages.success(request, "Acesso revogado com sucesso.")
                return redirect("projects_share", pk=project.pk)

        elif action == "update":
            membership_id = request.POST.get("membership_id")
            role = request.POST.get("role", ProjectMembership.Role.VIEWER)
            membership = project.memberships.filter(pk=membership_id).select_related("user").first()
            valid_roles = {choice[0] for choice in role_choices}
            if not membership:
                errors["membership"] = "Participante não encontrado."
            elif membership.user_id == project.owner_id:
                errors["membership"] = "O proprietário já possui acesso total."
            elif role not in valid_roles:
                errors["membership"] = "Permissão inválida."
            else:
                previous_role = membership.role
                membership.role = role
                membership.invited_by = request.user
                membership.save(update_fields=["role", "invited_by", "updated_at"])
                if previous_role != membership.role:
                    log_project_member_updated(project, membership, previous_role=previous_role, request=request)
                messages.success(request, "Permissões atualizadas.")
                return redirect("projects_share", pk=project.pk)

        else:
            form_data["username"] = request.POST.get("username", "").strip()
            form_data["role"] = request.POST.get("role", form_data["role"])
            username = form_data["username"]
            role = form_data["role"]
            User = get_user_model()
            target_user = None

            if not username:
                errors["username"] = "Informe o usuário que receberá acesso."
            else:
                try:
                    target_user = User.objects.get(username=username)
                except User.DoesNotExist:
                    errors["username"] = "Usuário não encontrado."

            valid_roles = {choice[0] for choice in role_choices}
            if role not in valid_roles:
                errors["role"] = "Tipo de acesso inválido."

            if not errors:
                membership, created = ProjectMembership.objects.get_or_create(
                    project=project,
                    user=target_user,
                    defaults={"role": role, "invited_by": request.user},
                )
                if not created and membership.role != role:
                    previous_role = membership.role
                    membership.role = role
                    membership.invited_by = request.user
                    membership.save(update_fields=["role", "invited_by", "updated_at"])
                    log_project_member_updated(project, membership, previous_role=previous_role, request=request)
                else:
                    if created:
                        log_project_member_added(project, membership, request=request)
                messages.success(request, "Compartilhamento atualizado.")
                return redirect("projects_share", pk=project.pk)

    share_url = request.build_absolute_uri(reverse("projects_share", kwargs={"pk": project.pk}))

    context = {
        "project": project,
        "share_url": share_url,
        "memberships": project.memberships.select_related("user").order_by("user__username"),
        "role_choices": role_choices,
        "form": form_data,
        "errors": errors,
        "success": success,
    }
    return render(request, "projects/share.html", context)


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


@login_required
def scripts_create(request):
    """
    Wrapper compatível com o nome de URL 'scripts_create' usado em templates.
    Reusa a lógica do editor (scripts_new).
    """
    return scripts_new(request)


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


@login_required
@require_http_methods(["GET", "POST"])
def projects_edit(request, pk):
    import json

    from django.utils import timezone

    from .models import Project

    project = get_object_or_404(Project, pk=pk)

    if project.owner != request.user:
        messages.error(request, "Você não tem permissão para editar este projeto.")
        return redirect("projects_list")

    errors = {}

    def summarize_credentials(creds):
        summary = []
        for cred in creds:
            label = cred.get("type_label") or cred.get("type", "-")
            parts = []
            if cred.get("username"):
                parts.append(f"user: {cred['username']}")
            if cred.get("password"):
                masked = cred["password"][:10] + ("…" if len(cred["password"]) > 10 else "")
                parts.append(f"pass: {masked}")
            if cred.get("passphrase"):
                masked = cred["passphrase"][:10] + ("…" if len(cred["passphrase"]) > 10 else "")
                parts.append(f"passphrase: {masked}")
            if cred.get("pkey"):
                masked = cred["pkey"][:30] + ("…" if len(cred["pkey"]) > 30 else "")
                parts.append(f"pkey: {masked}")
            summary.append({
                "type": cred.get("type"),
                "type_label": label,
                "summary": " · ".join(parts) or "",
            })
        return summary

    def serialize_project(p):
        credentials = p.credentials_json or []
        return {
            "id": str(p.pk),
            "name": p.name,
            "description": p.description,
            "client": p.client_name,
            "start": timezone.localtime(p.start_at).strftime("%Y-%m-%dT%H:%M") if p.start_at else "",
            "end": timezone.localtime(p.end_at).strftime("%Y-%m-%dT%H:%M") if p.end_at else "",
            "hosts": p.hosts,
            "protected_hosts": p.protected_hosts,
            "networks": p.networks,
            "ports": p.ports,
            "credentials_json": json.dumps(credentials),
            "credentials": summarize_credentials(credentials),
        }

    project_data = serialize_project(project)
    form = project_data.copy()

    if request.method == "POST":
        form["name"] = request.POST.get("name", "").strip()
        form["description"] = request.POST.get("description", "").strip()
        form["client"] = request.POST.get("client", "").strip()
        form["start"] = request.POST.get("start", "").strip()
        form["end"] = request.POST.get("end", "").strip()
        form["hosts"] = request.POST.get("hosts", "").strip()
        form["protected_hosts"] = request.POST.get("protected_hosts", "").strip()
        form["networks"] = request.POST.get("networks", "").strip()
        form["ports"] = request.POST.get("ports", "").strip()
        form["credentials_json"] = request.POST.get("credentials_json", form["credentials_json"])

        if not form["name"]:
            errors["name"] = "O nome é obrigatório."

        dt_start = _parse_datetime_local(form["start"])
        dt_end = _parse_datetime_local(form["end"])

        if form["start"] and not dt_start:
            errors["start"] = "Data/hora de início inválida."
        if form["end"] and not dt_end:
            errors["end"] = "Data/hora de término inválida."
        if dt_start and dt_end and dt_end < dt_start:
            errors["end"] = "Data de término não pode ser anterior ao início."

        try:
            credentials_payload = json.loads(form["credentials_json"] or "[]")
        except json.JSONDecodeError:
            credentials_payload = []
            errors["credentials_json"] = "Formato inválido de credenciais."

        if not errors:
            project.name = form["name"]
            project.description = form["description"]
            project.client_name = form["client"]
            project.start_at = dt_start
            project.end_at = dt_end
            project.hosts = form["hosts"]
            project.protected_hosts = form["protected_hosts"]
            project.networks = form["networks"]
            project.ports = form["ports"]
            project.credentials_json = credentials_payload
            project.metadata = {
                **(project.metadata or {}),
                "credentials_display": summarize_credentials(credentials_payload),
            }
            project.save()
            messages.success(request, "Projeto atualizado com sucesso.")
            return redirect("projects_edit", pk=project.pk)

    context = {
        "project": form,
        "form": form,
        "errors": errors,
    }
    return render(request, "projects/edit.html", context)


@login_required
def scripts_new(request):
    """
    Editor simples para criar um novo script usuário.
    Salva em arpia_core/scripts/user/<username>/<filename>.
    """
    ensure_script_dirs()
    username = request.user.username or "anonymous"
    user_dir = SCRIPTS_BASE / "user" / username
    user_dir.mkdir(parents=True, exist_ok=True)

    context = {
        "filename": "",
        "content": "",
        "username": username,
        "user_files": sorted([p.name for p in user_dir.iterdir() if p.is_file()]),
    }

    if request.method == "POST":
        filename = request.POST.get("filename", "").strip()
        content = request.POST.get("content", "")
        filename = safe_filename(filename)
        if not filename:
            messages.error(request, "Nome de arquivo inválido.")
            context.update({"filename": request.POST.get("filename", ""), "content": content})
            return render(request, "scripts/new.html", context)

        target = user_dir / filename
        try:
            target.write_text(content, encoding="utf-8")
            # permissões padrão
            try:
                target.chmod(0o644)
            except Exception:
                pass
            messages.success(request, f"Script salvo: {filename}")
            return redirect("scripts_list")
        except Exception as e:
            messages.error(request, f"Falha ao salvar o script: {e}")
            context.update({"filename": filename, "content": content})
            return render(request, "scripts/new.html", context)

    return render(request, "scripts/new.html", context)
