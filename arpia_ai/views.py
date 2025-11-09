from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods
from django.views.generic import TemplateView

from arpia_core.models import Project

from .services import ProjectAccessError, build_project_context


class AIListView(LoginRequiredMixin, TemplateView):
    template_name = "ai/list.html"


@login_required
@require_http_methods(["GET"])
def project_context_view(request, project_id):
    project = get_object_or_404(Project, pk=project_id)
    try:
        context_payload = build_project_context(request.user, project)
    except ProjectAccessError as exc:
        raise Http404("Projeto não encontrado") from exc

    return JsonResponse(context_payload, json_dumps_params={"ensure_ascii": False})
