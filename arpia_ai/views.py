from __future__ import annotations

import logging

from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.decorators.http import require_POST
from django.views.generic import TemplateView

from arpia_core.models import Project

from .services import AdvisorResponse, generate_advisor_response, record_interaction
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
            )
        except Exception:  # pragma: no cover - falha nao deve interromper resposta
            logger.exception("Falha ao registrar historico do assistente.")

    return JsonResponse(
        {
            "answer": advisor_result.answer,
            "context": advisor_result.context,
        }
    )
