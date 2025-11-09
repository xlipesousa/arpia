from __future__ import annotations

import logging
from typing import Any

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.http import require_GET, require_POST
from django.views.generic import TemplateView

from arpia_core.models import Project

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
            return JsonResponse({"error": "Acesso negado ao projeto selecionado."}, status=403)

    advisor_result: AdvisorResponse = generate_advisor_response(
        user=request.user,
        project=project,
        question=question,
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
        except Exception:  # pragma: no cover - falha nao deve interromper resposta
            logger.exception("Falha ao registrar historico do assistente.")

    return JsonResponse(
        {
            "answer": advisor_result.answer,
            "context": advisor_result.context,
            "provider": {
                "slug": advisor_result.provider.slug,
                "name": advisor_result.provider.name,
            },
            "metadata": advisor_result.metadata,
        }
    )


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

    return JsonResponse({"providers": entries})


@login_required
@require_POST
def register_openai_credential(request):
    api_key = (request.POST.get("api_key") or "").strip()
    label = (request.POST.get("label") or "default").strip() or "default"

    if not api_key:
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
