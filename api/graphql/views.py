from __future__ import annotations

from time import perf_counter

from django.conf import settings
from django.http import Http404, JsonResponse
from graphene_django.views import GraphQLView

from arpia_hunt.log_events import emit_hunt_log

from ..schema import schema


class HuntGraphQLView(GraphQLView):
    def dispatch(self, request, *args, **kwargs):  # type: ignore[override]
        if not getattr(settings, "ARPIA_HUNT_API_BETA", False):
            raise Http404("API Hunt (beta) desabilitada.")

        if not request.user.is_authenticated:
            return JsonResponse({"errors": [{"message": "Autenticação requerida."}]}, status=401)

        started_at = perf_counter()
        response = super().dispatch(request, *args, **kwargs)
        duration_ms = int((perf_counter() - started_at) * 1000)
        try:
            emit_hunt_log(
                event_type="hunt.api.graphql",
                message=f"GraphQL {request.path}",
                component="hunt.api",
                details={
                    "duration_ms": duration_ms,
                    "path": request.path,
                    "status_code": getattr(response, "status_code", None),
                },
                tags=["metric:hunt.api.latency", "graphql"],
            )
        except Exception:
            pass
        return response
