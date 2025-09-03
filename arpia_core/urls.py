from django.urls import path
from django.views.generic import RedirectView

# tenta importar HealthCheck da API (se api ainda não existir, usa fallback)
try:
    from api.views import HealthCheck  # noqa: WPS433
except Exception:  # pragma: no cover - fallback simples
    from django.http import JsonResponse
    from rest_framework.views import APIView
    from rest_framework import status

    class HealthCheck(APIView):
        permission_classes = ()
        authentication_classes = ()

        def get(self, request, *args, **kwargs):
            return JsonResponse({"status": "ok"}, status=status.HTTP_200_OK)


urlpatterns = [
    path("", RedirectView.as_view(url="/api/", permanent=False)),
    path("health/", HealthCheck.as_view(), name="arpia-core-health"),
]