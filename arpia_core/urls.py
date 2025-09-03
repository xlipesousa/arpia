from django.urls import path
from django.views.generic import RedirectView
from .views import DashboardView
from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework import status

class HealthCheck(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get(self, request, *args, **kwargs):
        return JsonResponse({"status": "ok"}, status=status.HTTP_200_OK)


urlpatterns = [
    path("", RedirectView.as_view(url="/api/", permanent=False)),
    path("health/", HealthCheck.as_view(), name="arpia-core-health"),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
]