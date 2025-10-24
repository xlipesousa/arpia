from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormMixin, UpdateView

from .forms import ScriptForm, ToolForm, WordlistForm
from .models import Project, ProjectMembership, Script, Tool, Wordlist
from .project_logging import (
    log_project_created,
    log_project_member_added,
    log_project_member_removed,
    log_project_member_updated,
)
from .script_registry import get_default_by_slug, get_default_catalog
from .utils import safe_filename


BASE_DIR = Path(__file__).resolve().parent
SCRIPTS_BASE = BASE_DIR / "scripts"


@login_required
def scripts_list(request):
    sync_default_scripts()

    page = request.GET.get("page", 1)
    try:
        page_size = int(request.GET.get("page_size", 10))
    except (TypeError, ValueError):
        page_size = 10

    scripts_qs = Script.objects.for_user(request.user).order_by("kind", "name")
    paginator = Paginator(scripts_qs, page_size)
    page_obj = paginator.get_page(page)

    scripts_table = []
    for script in page_obj.object_list:
        scripts_table.append(
            {
                "id": script.pk,
                "name": script.name,
                "description": script.description,
                "type": script.kind,
                "tags": script.tags,
                "filename": script.filename,
                "updated_at": script.updated_at,
                "is_default": script.is_default,
                "owner_id": script.owner_id,
                "can_edit": script.owner_id == request.user.id and script.kind == Script.Kind.USER,
                "can_delete": script.owner_id == request.user.id and script.kind == Script.Kind.USER,
                "can_reset": script.is_default or bool(script.owner_id == request.user.id and script.source_path),
                "can_clone": script.is_default,
            }
        )

    projects = list(_get_user_projects(request.user))
    project_options = [
        {"id": str(project.pk), "name": project.name, "client": project.client_name}
        for project in projects
    ]

    selected_project_id = request.GET.get("project", "")
    selected_project = None
    if selected_project_id:
        try:
            selected_project = _get_accessible_project(request.user, selected_project_id)
        except Http404:
            selected_project = None
            selected_project_id = ""

    if not selected_project and projects:
        selected_project = projects[0]
        selected_project_id = str(selected_project.pk)

    project_macros = build_project_macros(request.user, selected_project)
    macros_json = json.dumps(project_macros, ensure_ascii=False)
    macro_entries = _macro_entries(project_macros)

    context = {
        "scripts_page": page_obj,
        "scripts": scripts_table,
        "project_options": project_options,
        "selected_project_id": selected_project_id,
        "project_macros": project_macros,
        "project_macros_json": macros_json,
        "macro_entries": macro_entries,
        "page_size_choices": [5, 10, 25],
    }
    return render(request, "scripts/list.html", context)


@login_required
def scripts_create(request):
    return scripts_new(request)


@login_required
def scripts_new(request):
    sync_default_scripts()

    form = ScriptForm(request.POST or None, owner=request.user)
    project_id = request.GET.get("project")
    selected_project = None
    if project_id:
        try:
            selected_project = _get_accessible_project(request.user, project_id)
        except Http404:
            selected_project = None

    if request.method == "POST" and form.is_valid():
        script = form.save(commit=False)
        script.owner = request.user
        script.kind = Script.Kind.USER
        script.tags = script.tags or []
        script.save()

        file_path = _write_user_script_file(request.user, script.filename, script.content)
        script.source_path = str(file_path)
        script.save(update_fields=["source_path"])

        messages.success(request, "Script criado com sucesso.")
        return redirect("scripts_list")

    projects = list(_get_user_projects(request.user))
    project_options = [
        {"id": str(project.pk), "name": project.name}
        for project in projects
    ]
    if not selected_project and projects:
        selected_project = projects[0]
    project_macros = build_project_macros(request.user, selected_project)
    macros_json = json.dumps(project_macros, ensure_ascii=False)
    macro_entries = _macro_entries(project_macros)

    user_scripts = Script.objects.filter(owner=request.user).order_by("name")

    context = {
        "form": form,
        "mode": "create",
        "project_options": project_options,
        "selected_project_id": str(selected_project.pk) if selected_project else "",
        "project_macros": project_macros,
        "project_macros_json": macros_json,
        "macro_entries": macro_entries,
        "user_scripts": user_scripts,
    }
    return render(request, "scripts/new.html", context)


@login_required
def scripts_edit(request, pk):
    script = get_object_or_404(Script, pk=pk, owner=request.user, kind=Script.Kind.USER)
    original_filename = script.filename

    form = ScriptForm(request.POST or None, instance=script, owner=request.user)

    project_id = request.GET.get("project")
    selected_project = None
    if project_id:
        try:
            selected_project = _get_accessible_project(request.user, project_id)
        except Http404:
            selected_project = None

    if request.method == "POST" and form.is_valid():
        script = form.save(commit=False)
        script.kind = Script.Kind.USER
        script.save()

        if original_filename != script.filename:
            old_path = _user_scripts_dir(request.user) / original_filename
            try:
                if old_path.exists():
                    old_path.unlink()
            except Exception:
                pass

        file_path = _write_user_script_file(request.user, script.filename, script.content)
        script.source_path = str(file_path)
        script.save(update_fields=["source_path", "updated_at"])

        messages.success(request, "Script atualizado com sucesso.")
        return redirect("scripts_list")

    projects = list(_get_user_projects(request.user))
    project_options = [
        {"id": str(project.pk), "name": project.name}
        for project in projects
    ]
    if not selected_project and projects:
        selected_project = projects[0]
    project_macros = build_project_macros(request.user, selected_project)
    macros_json = json.dumps(project_macros, ensure_ascii=False)
    macro_entries = _macro_entries(project_macros)

    context = {
        "form": form,
        "mode": "edit",
        "script_obj": script,
        "project_options": project_options,
        "selected_project_id": str(selected_project.pk) if selected_project else "",
        "project_macros": project_macros,
        "project_macros_json": macros_json,
        "macro_entries": macro_entries,
    }
    return render(request, "scripts/new.html", context)


@login_required
@require_http_methods(["POST"])
def scripts_delete(request, pk):
    script = get_object_or_404(Script, pk=pk, owner=request.user, kind=Script.Kind.USER)
    path = _user_scripts_dir(request.user) / script.filename
    script.delete()
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass
    messages.success(request, "Script removido com sucesso.")
    return redirect("scripts_list")


@login_required
@require_http_methods(["POST"])
def scripts_clone(request, pk):
    sync_default_scripts()
    base_script = get_object_or_404(Script, pk=pk, owner__isnull=True, kind=Script.Kind.DEFAULT)

    base_filename = base_script.filename
    filename = base_filename
    counter = 1
    while Script.objects.filter(owner=request.user, filename=filename).exists():
        name, ext = os.path.splitext(base_filename)
        filename = f"{name}-{counter}{ext}"
        counter += 1

    clone = Script.objects.create(
        owner=request.user,
        name=base_script.name,
        description=base_script.description,
        filename=filename,
        content=base_script.content,
        kind=Script.Kind.USER,
        tags=list(base_script.tags) + [f"default:{base_script.slug}"],
        source_path=base_script.source_path,
    )

    file_path = _write_user_script_file(request.user, clone.filename, clone.content)
    clone.source_path = str(file_path)
    clone.save(update_fields=["source_path"])

    messages.success(request, "Script clonado para o seu workspace.")
    return redirect("scripts_list")


@login_required
@require_http_methods(["POST"])
def scripts_reset(request, pk):
    sync_default_scripts()
    script = get_object_or_404(Script.objects.for_user(request.user), pk=pk)

    if script.is_default:
        definition = get_default_by_slug(script.slug)
        if not definition:
            messages.error(request, "Script default não encontrado no catálogo.")
            return redirect("scripts_list")
        try:
            content = definition.read_content()
        except FileNotFoundError:
            content = script.content
        script.content = content
        script.description = definition.description
        script.filename = definition.filename
        script.tags = definition.tags
        script.source_path = str(definition.source_path)
        script.save()
        messages.success(request, "Script default restaurado com sucesso.")
        return redirect("scripts_list")

    if script.owner_id != request.user.id:
        messages.error(request, "Você não tem permissão para resetar este script.")
        return redirect("scripts_list")

    default_slug = None
    for tag in script.tags or []:
        if isinstance(tag, str) and tag.startswith("default:"):
            default_slug = tag.split(":", 1)[1]
            break

    if default_slug:
        definition = get_default_by_slug(default_slug)
        if definition:
            try:
                script.content = definition.read_content()
            except FileNotFoundError:
                script.content = script.content
    file_path = _write_user_script_file(request.user, script.filename, script.content)
    script.source_path = str(file_path)
    script.save(update_fields=["content", "source_path", "updated_at"])
    messages.success(request, "Script restaurado com sucesso.")
    return redirect("scripts_list")


@login_required
def scripts_run(request, pk):
    sync_default_scripts()
    script = get_object_or_404(Script.objects.for_user(request.user), pk=pk)

    project_id = request.GET.get("project")
    selected_project = None
    if project_id:
        try:
            selected_project = _get_accessible_project(request.user, project_id)
        except Http404:
            selected_project = None

    macros = build_project_macros(request.user, selected_project)
    rendered_content = render_script_with_macros(script.content, macros)

    return JsonResponse(
        {
            "status": "ok",
            "id": script.pk,
            "name": script.name,
            "project": {
                "id": str(selected_project.pk),
                "name": selected_project.name,
            }
            if selected_project
            else None,
            "content": rendered_content,
            "macros": macros,
        }
    )


def sync_default_scripts() -> None:
    for entry in get_default_catalog():
        try:
            content = entry.read_content()
        except FileNotFoundError:
            content = ""

        defaults = {
            "name": entry.name,
            "description": entry.description,
            "filename": entry.filename,
            "content": content,
            "kind": Script.Kind.DEFAULT,
            "tags": entry.tags,
            "source_path": str(entry.source_path),
        }

        Script.objects.update_or_create(
            owner=None,
            slug=entry.slug,
            defaults=defaults,
        )


def _normalize_multiline(value: str) -> str:
    if not value:
        return ""
    separators = [",", "\r", "\n", "\t", ";"]
    for sep in separators:
        value = value.replace(sep, "\n")
    items = [item.strip() for item in value.splitlines() if item.strip()]
    return "\n".join(items)


PORT_SPEC_PATTERN = re.compile(r"^(\d{1,5})(?:\s*/\s*([a-zA-Z]{1,8}))?$")
VALID_PROTOCOLS = {"tcp", "udp"}


def _normalize_port_specs(value: str) -> tuple[str, list[str]]:
    if not value:
        return "", []

    if not isinstance(value, str):
        value = str(value)

    normalized: list[str] = []
    invalid: list[str] = []

    cleaned = value.replace(",", "\n").replace(";", "\n").replace("\r", "\n")
    for raw in cleaned.splitlines():
        token = raw.strip()
        if not token:
            continue

        match = PORT_SPEC_PATTERN.match(token)
        if not match:
            invalid.append(token)
            continue

        port = int(match.group(1))
        protocol = (match.group(2) or "tcp").lower()

        if not (1 <= port <= 65535) or protocol not in VALID_PROTOCOLS:
            invalid.append(token)
            continue

        normalized.append(f"{port}/{protocol}")

    return "\n".join(normalized), invalid


def _format_ports_for_form(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("\n", ", ")


def _credentials_summary(credentials):
    summary = []
    for cred in credentials or []:
        username = cred.get("username") or ""
        password = cred.get("password") or cred.get("passphrase") or ""
        target = cred.get("target") or cred.get("host") or ""
        summary.append(
            {
                "type": cred.get("type") or cred.get("type_label") or "",
                "username": username,
                "password": password,
                "target": target,
            }
        )
    return summary


def build_project_macros(user, project: Project | None) -> dict:
    base_macros = {
        "PROJECT_NAME": "",
        "TARGET_HOSTS": "",
        "TARGET_NETWORKS": "",
        "TARGET_PORTS": "",
        "PROTECTED_HOSTS": "",
        "CREDENTIALS_JSON": "[]",
        "CREDENTIALS_TABLE": [],
    }

    if project:
        credentials = project.credentials_json or []
        base_macros.update(
            {
                "PROJECT_NAME": project.name,
                "TARGET_HOSTS": _normalize_multiline(project.hosts),
                "TARGET_NETWORKS": _normalize_multiline(project.networks),
                "TARGET_PORTS": (project.ports or "").replace("\n", ", "),
                "PROTECTED_HOSTS": _normalize_multiline(project.protected_hosts),
                "CREDENTIALS_JSON": json.dumps(credentials, indent=2, ensure_ascii=False),
                "CREDENTIALS_TABLE": _credentials_summary(credentials),
            }
        )

    if user and getattr(user, "is_authenticated", False):
        tool_macros = {}
        tools_data = []
        for tool in Tool.objects.for_user(user).order_by("name"):
            tool_macros[tool.macro_key] = tool.path
            tools_data.append(
                {
                    "name": tool.name,
                    "slug": tool.slug,
                    "path": tool.path,
                    "category": tool.category,
                }
            )

        wordlist_macros = {}
        wordlists_data = []
        for wordlist in Wordlist.objects.for_user(user).order_by("name"):
            wordlist_macros[wordlist.macro_key] = wordlist.path
            wordlists_data.append(
                {
                    "name": wordlist.name,
                    "slug": wordlist.slug,
                    "path": wordlist.path,
                    "category": wordlist.category,
                    "tags": wordlist.tags,
                }
            )

        base_macros.update(tool_macros)
        base_macros.update(wordlist_macros)
        base_macros["TOOLS_JSON"] = json.dumps(tools_data, indent=2, ensure_ascii=False)
        base_macros["WORDLISTS_JSON"] = json.dumps(wordlists_data, indent=2, ensure_ascii=False)

    return base_macros


def render_script_with_macros(content: str, macros: dict[str, str]) -> str:
    rendered = content
    for key, value in macros.items():
        if isinstance(value, (list, dict)):
            value_str = json.dumps(value, indent=2, ensure_ascii=False)
        else:
            value_str = str(value)
        pattern = re.compile(r"\{\{\s*" + re.escape(key) + r"\s*\}\}")
        rendered = pattern.sub(value_str, rendered)
    return rendered


def _get_user_projects(user):
    return (
        Project.objects.filter(Q(owner=user) | Q(memberships__user=user))
        .distinct()
        .order_by("name")
    )


def _macro_entries(macros: dict) -> list[dict]:
    entries = []
    for key, value in macros.items():
        if isinstance(value, (list, dict)):
            display = json.dumps(value, indent=2, ensure_ascii=False)
            entries.append({"key": key, "value": display, "is_pre": True})
        else:
            display = str(value)
            entries.append({"key": key, "value": display, "is_pre": "\n" in display})
    return entries


def _user_scripts_dir(user) -> Path:
    username = safe_filename(getattr(user, "username", "")) or f"user-{user.pk}"
    directory = SCRIPTS_BASE / "user" / username
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _write_user_script_file(user, filename: str, content: str) -> Path:
    directory = _user_scripts_dir(user)
    path = directory / filename
    path.write_text(content, encoding="utf-8")
    try:
        path.chmod(0o644)
    except Exception:
        pass
    return path


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
        "ports": "",
    }

    if request.method == "POST":
        form["name"] = request.POST.get("name", "").strip()
        form["description"] = request.POST.get("description", "").strip()
        form["client"] = request.POST.get("client", "").strip()
        form["start"] = request.POST.get("start", "").strip()
        form["end"] = request.POST.get("end", "").strip()
        form["ports"] = request.POST.get("ports", "").strip()

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

        normalized_ports, invalid_ports = _normalize_port_specs(form["ports"])
        if invalid_ports:
            errors["ports"] = "Entradas de porta inválidas: " + ", ".join(invalid_ports)

        if not errors:
            project = Project(
                owner=request.user,
                name=form["name"],
                description=form["description"],
                client_name=form["client"],
                start_at=dt_start,
                end_at=dt_end,
                timezone=str(timezone.get_current_timezone()),
            )
            project.ports = normalized_ports
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
    from django.utils import timezone

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

class ToolWordlistView(LoginRequiredMixin, TemplateView):
    template_name = "tools/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user

        tools = list(Tool.objects.for_user(user).order_by("name"))
        wordlists = list(Wordlist.objects.for_user(user).order_by("name"))

        context.update(
            {
                "tools": tools,
                "wordlists": wordlists,
                "tool_form": ToolForm(owner=user),
                "wordlist_form": WordlistForm(owner=user),
            }
        )
        return context


class OwnerMixin(LoginRequiredMixin):
    model = None
    slug_field = "slug"
    slug_url_kwarg = "slug"

    def get_queryset(self):
        return self.model.objects.for_user(self.request.user)

    def form_valid(self, form):
        form.instance.owner = self.request.user
        return super().form_valid(form)

    def get_success_url(self):
        return reverse("tools_list")


class ToolFormMixin(FormMixin):
    form_class = ToolForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["owner"] = self.request.user
        return kwargs


class WordlistFormMixin(FormMixin):
    form_class = WordlistForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["owner"] = self.request.user
        return kwargs


class ToolCreateView(ToolFormMixin, OwnerMixin, CreateView):
    template_name = "tools/tool_form.html"
    model = Tool

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Ferramenta cadastrada com sucesso.")
        return response


class ToolUpdateView(ToolFormMixin, OwnerMixin, UpdateView):
    template_name = "tools/tool_form.html"
    model = Tool

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Ferramenta atualizada com sucesso.")
        return response


class ToolDeleteView(OwnerMixin, DeleteView):
    template_name = "tools/tool_confirm_delete.html"
    model = Tool

    def delete(self, request, *args, **kwargs):
        messages.success(request, "Ferramenta removida com sucesso.")
        return super().delete(request, *args, **kwargs)


class WordlistCreateView(WordlistFormMixin, OwnerMixin, CreateView):
    template_name = "tools/wordlist_form.html"
    model = Wordlist

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Wordlist cadastrada com sucesso.")
        return response


class WordlistUpdateView(WordlistFormMixin, OwnerMixin, UpdateView):
    template_name = "tools/wordlist_form.html"
    model = Wordlist

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Wordlist atualizada com sucesso.")
        return response


class WordlistDeleteView(OwnerMixin, DeleteView):
    template_name = "tools/wordlist_confirm_delete.html"
    model = Wordlist

    def delete(self, request, *args, **kwargs):
        messages.success(request, "Wordlist removida com sucesso.")
        return super().delete(request, *args, **kwargs)


@login_required
def wordlists_download(request, slug):
    wordlist = get_object_or_404(Wordlist.objects.for_user(request.user), slug=slug)
    return JsonResponse(
        {
            "status": "ok",
            "action": "download",
            "id": wordlist.pk,
            "path": wordlist.path,
        }
    )


@login_required
@require_http_methods(["GET", "POST"])
def projects_edit(request, pk):
    from django.utils import timezone

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
            "ports": _format_ports_for_form(p.ports),
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

        ports_normalized, invalid_ports = _normalize_port_specs(form["ports"])
        if invalid_ports:
            errors["ports"] = "Entradas de porta inválidas: " + ", ".join(invalid_ports)

        if not errors:
            project.name = form["name"]
            project.description = form["description"]
            project.client_name = form["client"]
            project.start_at = dt_start
            project.end_at = dt_end
            project.hosts = form["hosts"]
            project.protected_hosts = form["protected_hosts"]
            project.networks = form["networks"]
            project.ports = ports_normalized
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
