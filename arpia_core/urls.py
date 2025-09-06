from django.urls import path
from . import views

urlpatterns = [
    path("", views.DashboardView.as_view(), name="dashboard"),
    path("health/", views.HealthCheck.as_view(), name="arpia-core-health"),
    path("projects/", views.projects_list, name="projects_list"),
    path("projects/new/", views.projects_create, name="projects_create"),

    # Scripts
    path("scripts/", views.scripts_list, name="scripts_list"),
    path("scripts/new/", views.scripts_create, name="scripts_create"),
    path("scripts/<int:pk>/edit/", views.scripts_edit, name="scripts_edit"),
    path("scripts/<int:pk>/delete/", views.scripts_delete, name="scripts_delete"),
    path("scripts/<int:pk>/clone/", views.scripts_clone, name="scripts_clone"),
    path("scripts/<int:pk>/reset/", views.scripts_reset, name="scripts_reset"),
    path("scripts/<int:pk>/run/", views.scripts_run, name="scripts_run"),

    # Tools
    path("tools/", views.ToolsListView.as_view(), name="tools_list"),

    # Reports
    path("reports/", views.ReportsListView.as_view(), name="reports_list"),

    # Logs
    path("logs/", views.LogsListView.as_view(), name="logs_list"),
]