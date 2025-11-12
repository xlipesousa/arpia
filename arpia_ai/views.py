from __future__ import annotations

import logging
from typing import Any, Optional

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import TemplateView

from arpia_core.models import Project
from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .models import ChatSession, Provider, ProviderCredential
from .services import (
    AdvisorResponse,
    ensure_demo_provider,
    ensure_openai_provider,
    generate_advisor_response,
    record_interaction,
    validate_openai_api_key,
)
from .services.context import build_project_context


logger = logging.getLogger(__name__)


def _log_ai_event(
    *,
    request,
    component: str,
    event_type: str,
    message: str,
    severity: str = LogEntry.Severity.INFO,
    project: Optional[Project] = None,
    provider: Optional[Provider] = None,
    details: Optional[dict[str, Any]] = None,
    tags: Optional[list[str]] = None,
) -> None:
    context: dict[str, Any] = {}
    correlation: dict[str, Any] = {}
    if project is not None:
        context["project"] = {
            "id": str(project.pk),
            "name": project.name,
            "slug": project.slug,
        }
        correlation["project_id"] = str(project.pk)
    if provider is not None:
        context["provider"] = {
            "slug": provider.slug,
            "name": provider.name,
        }
        details = dict(details or {})
        details.setdefault("provider_slug", provider.slug)
        details.setdefault("provider_name", provider.name)
        details_payload = details
    else:
        details_payload = dict(details or {})
    _tags = list(tags or [])
    if "ai" not in _tags:
        _tags.append("ai")

    log_event(
        source_app="arpia_ai",
        component=component,
        event_type=event_type,
        message=message,
        severity=severity,
        details=details_payload,
        context=context,
        correlation=correlation,
        tags=_tags,
        request=request,
    )


class AIHomeView(LoginRequiredMixin, TemplateView):
    template_name = "ai/home.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        projects = list(self._get_accessible_projects())
        selected_project = self._resolve_selected_project(projects)
        project_context = (
            build_project_context(project=selected_project, user=self.request.user)
            if selected_project
            else {}
        )

        context.update(
            {
                "projects": projects,
                "selected_project": selected_project,
                "project_context": project_context,
                "assist_url": reverse("arpia_ai:assist"),
                "providers_url": reverse("arpia_ai:providers"),
                "register_openai_url": reverse("arpia_ai:provider_openai_credential"),
                "chat_history": self._get_chat_history(selected_project=selected_project),
            }
        )
        _log_ai_event(
            request=self.request,
            component="ui.home",
            event_type="ai.home.view",
            message="Usuário acessou o painel do assistente de IA.",
            project=selected_project,
            details={
                "projects_total": len(projects),
                "has_context": bool(project_context),
            },
        )
        return context

    def _get_accessible_projects(self):
        user = self.request.user
        return (
            Project.objects.filter(Q(owner=user) | Q(memberships__user=user))
            .distinct()
            .order_by("name")
        )

    def _resolve_selected_project(self, projects: list[Project]) -> Project | None:
        requested_id = self.request.GET.get("project") or ""
        if requested_id:
            for project in projects:
                if str(project.pk) == requested_id:
                    return project
        return projects[0] if projects else None

    def _get_chat_history(self, selected_project: Project | None) -> list[dict[str, Any]]:
        user = self.request.user
        sessions = ChatSession.objects.filter(owner=user).select_related("provider", "project")
        if selected_project:
            sessions = sessions.filter(project=selected_project)

        entries: list[dict[str, Any]] = []
        for session in sessions.order_by("-created_at")[:15]:
            entries.append(
                {
                    "id": str(session.pk),
                    "title": session.title or f"Conversa com {session.provider.name}",
                    "provider": session.provider.name,
                    "provider_slug": session.provider.slug,
                    "created_at": session.created_at,
                }
            )
        return entries


@login_required
@require_POST
def assist_request(request):
    project_id = request.POST.get("project_id")
    question = request.POST.get("question", "")

    project = None
    if project_id:
        project = get_object_or_404(Project, pk=project_id)
        if project.owner != request.user and not project.memberships.filter(user=request.user).exists():
            _log_ai_event(
                request=request,
                component="assist",
                event_type="ai.assist.project.denied",
                message="Usuário tentou acionar o assistente para projeto sem permissão.",
                project=project,
                severity=LogEntry.Severity.WARNING,
                details={"project_id": project_id},
            )
            return JsonResponse({"error": "Acesso negado ao projeto selecionado."}, status=403)

    _log_ai_event(
        request=request,
        component="assist",
        event_type="ai.assist.request.received",
        message="Comando do assistente IA recebido.",
        project=project,
        details={
            "question_length": len(question or ""),
            "has_project": bool(project),
        },
    )

    advisor_result: AdvisorResponse = generate_advisor_response(
        user=request.user,
        project=project,
        question=question,
    )

    _log_ai_event(
        request=request,
        component="assist",
        event_type="ai.assist.response.generated",
        message="Resposta do assistente IA gerada.",
        project=project,
        provider=advisor_result.provider,
        details={
            "answer_length": len(advisor_result.answer or ""),
            "context_keys": sorted((advisor_result.context or {}).keys()),
            "metadata": advisor_result.metadata,
        },
    )

    if project:
        try:
            record_interaction(
                user=request.user,
                project=project,
                question=question,
                answer=advisor_result.answer,
                context=advisor_result.context,
                provider=advisor_result.provider,
                credential=advisor_result.credential,
                metadata=advisor_result.metadata,
            )
        except Exception as exc:  # pragma: no cover - falha nao deve interromper resposta
            logger.exception("Falha ao registrar historico do assistente.")
            _log_ai_event(
                request=request,
                component="assist",
                event_type="ai.assist.history.error",
                message="Falha ao registrar histórico do assistente.",
                project=project,
                provider=advisor_result.provider,
                severity=LogEntry.Severity.ERROR,
                details={"error": str(exc)},
            )
        else:
            _log_ai_event(
                request=request,
                component="assist",
                event_type="ai.assist.history.recorded",
                message="Interação do assistente IA registrada com sucesso.",
                project=project,
                provider=advisor_result.provider,
            )

    response_payload = {
        "answer": advisor_result.answer,
        "context": advisor_result.context,
        "provider": {
            "slug": advisor_result.provider.slug,
            "name": advisor_result.provider.name,
        },
        "metadata": advisor_result.metadata,
    }

    _log_ai_event(
        request=request,
        component="assist",
        event_type="ai.assist.response.sent",
        message="Resposta do assistente IA entregue ao cliente web.",
        project=project,
        provider=advisor_result.provider,
        details={
            "answer_length": len(advisor_result.answer or ""),
            "metadata_keys": sorted((advisor_result.metadata or {}).keys()),
        },
    )

    return JsonResponse(response_payload)


@login_required
@require_GET
def list_providers(request):
    ensure_demo_provider()
    ensure_openai_provider()

    providers = Provider.objects.filter(is_active=True).order_by("name")
    entries: list[dict[str, Any]] = []

    for provider in providers:
        credential = provider.credentials.filter(owner=request.user).order_by("created_at").first()
        credential_metadata = (
            credential.metadata if credential is not None and isinstance(credential.metadata, dict) else {}
        )

        entries.append(
            {
                "slug": provider.slug,
                "name": provider.name,
                "description": provider.description,
                "default_model": provider.default_model,
                "metadata": provider.metadata,
                "has_credentials": credential is not None,
                "credential": None
                if credential is None
                else {
                    "label": credential.label,
                    "masked_api_key": credential.masked_api_key,
                    "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
                    "validation": credential_metadata.get("validation"),
                },
            }
        )

    _log_ai_event(
        request=request,
        component="providers",
        event_type="ai.providers.list",
        message="Usuário consultou provedores de IA disponíveis.",
        details={
            "providers_total": len(entries),
            "providers_with_credentials": sum(1 for item in entries if item.get("has_credentials")),
        },
    )

    return JsonResponse({"providers": entries})


@login_required
@require_POST
def register_openai_credential(request):
    api_key = (request.POST.get("api_key") or "").strip()
    label = (request.POST.get("label") or "default").strip() or "default"

    if not api_key:
        _log_ai_event(
            request=request,
            component="providers",
            event_type="ai.provider.openai.invalid",
            message="Tentativa de registrar credencial OpenAI sem chave informada.",
            severity=LogEntry.Severity.WARNING,
            details={"label": label},
        )
        return JsonResponse({"error": "Informe uma chave de API valida."}, status=400)

    provider = ensure_openai_provider()
    validation = validate_openai_api_key(
        api_key=api_key,
        model_name=provider.default_model or "gpt-4o-mini",
    )

    metadata = {
        "source": "manual",
        "updated_by": request.user.username,
        "validation": validation,
    }

    credential, created = ProviderCredential.objects.update_or_create(
        provider=provider,
        owner=request.user,
        label=label,
        defaults={
            "api_key": api_key,
            "metadata": metadata,
        },
    )

    if not created:
        credential.api_key = api_key
        credential.metadata = metadata
        credential.save(update_fields=["api_key", "metadata", "updated_at"])

    _log_ai_event(
        request=request,
        component="providers",
        event_type="ai.provider.openai.registered",
        message="Credencial OpenAI cadastrada ou atualizada.",
        provider=provider,
        details={
            "label": credential.label,
            "created": created,
            "validation": validation,
        },
    )

    return JsonResponse(
        {
            "provider": provider.slug,
            "credential": {
                "label": credential.label,
                "masked_api_key": credential.masked_api_key,
                "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
                "validation": validation,
            },
        }
    )
