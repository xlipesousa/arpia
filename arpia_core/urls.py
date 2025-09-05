from django.urls import path
from . import views

urlpatterns = [
    path("", views.DashboardView.as_view(), name="dashboard"),
    path("health/", views.HealthCheck.as_view(), name="arpia-core-health"),
    path("projects/", views.projects_list, name="projects_list"),
    path("projects/new/", views.projects_create, name="projects_create"),
    path("scripts/", views.ScriptsListView.as_view(), name="scripts_list"),
    path("tools/", views.ToolsListView.as_view(), name="tools_list"),
    path("reports/", views.ReportsListView.as_view(), name="reports_list"),
    path("logs/", views.LogsListView.as_view(), name="logs_list"),
]