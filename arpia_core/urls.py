from django.urls import path
from .views import (
    DashboardView,
    ProjectsListView,
    ScriptsListView,
    ToolsListView,
    ReportsListView,
    LogsListView,
)
from rest_framework.views import APIView
from django.http import JsonResponse
from rest_framework import status

class HealthCheck(APIView):
    permission_classes = ()
    authentication_classes = ()

    def get(self, request, *args, **kwargs):
        return JsonResponse({"status": "ok"}, status=status.HTTP_200_OK)


urlpatterns = [
    path("", DashboardView.as_view(), name="dashboard"),
    path("health/", HealthCheck.as_view(), name="arpia-core-health"),
    path("projects/", ProjectsListView.as_view(), name="projects_list"),
    path("scripts/", ScriptsListView.as_view(), name="scripts_list"),
    path("tools/", ToolsListView.as_view(), name="tools_list"),
    path("reports/", ReportsListView.as_view(), name="reports_list"),
    path("logs/", LogsListView.as_view(), name="logs_list"),
]