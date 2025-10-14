from django.urls import path
from . import views
# novo: importar views do app arpia_log
from arpia_log import views as arpia_log_views
# novo: importar views do app arpia_ai
from arpia_ai import views as arpia_ai_views

urlpatterns = [
    # rota raiz / dashboard (necessária para templates que fazem {% url 'dashboard' %})
    path("", views.DashboardView.as_view(), name="dashboard"),

    path("projects/", views.projects_list, name="projects_list"),
    path("projects/new/", views.projects_create, name="projects_create"),
    path("projects/<uuid:pk>/", views.projects_detail, name="projects_detail"),
    path("projects/<uuid:pk>/edit/", views.projects_edit, name="projects_edit"),
    path("projects/<uuid:pk>/share/", views.projects_share, name="projects_share"),

    # Scripts
    path("scripts/", views.scripts_list, name="scripts_list"),
    # alias compatível com templates que usam 'scripts_create'
    path("scripts/create/", views.scripts_create, name="scripts_create"),
    path("scripts/new/", views.scripts_new, name="scripts_new"),
    path("scripts/<int:pk>/edit/", views.scripts_edit, name="scripts_edit"),
    path("scripts/<int:pk>/delete/", views.scripts_delete, name="scripts_delete"),
    path("scripts/<int:pk>/clone/", views.scripts_clone, name="scripts_clone"),
    path("scripts/<int:pk>/reset/", views.scripts_reset, name="scripts_reset"),
    path("scripts/<int:pk>/run/", views.scripts_run, name="scripts_run"),

    # Tools & Wordlists
    path("tools/", views.tools_list, name="tools_list"),
    path("tools/add/", views.tools_add, name="tools_add"),
    path("tools/<int:pk>/configure/", views.tools_configure, name="tools_configure"),
    path("tools/<int:pk>/delete/", views.tools_delete, name="tools_delete"),

    path("wordlists/add/", views.wordlists_add, name="wordlists_add"),
    path("wordlists/<int:pk>/edit/", views.wordlists_edit, name="wordlists_edit"),
    path("wordlists/<int:pk>/delete/", views.wordlists_delete, name="wordlists_delete"),
    path("wordlists/<int:pk>/download/", views.wordlists_download, name="wordlists_download"),

    # Reports & Logs
    path("reports/", views.ReportsListView.as_view(), name="reports_list"),
    path("reports/<int:pk>/", views.ReportDetailView.as_view(), name="reports_detail"),
    path("reports/<int:pk>/generate/", views.ReportGenerateView.as_view(), name="reports_generate"),
    path("reports/<int:pk>/download/", views.reports_download, name="reports_download"),

    # Logs: delega para arpia_log.views
    path("logs/", arpia_log_views.LogsListView.as_view(), name="logs_list"),
    path("logs/api/", arpia_log_views.logs_api, name="logs_api"),
    path("logs/api/ingest/", arpia_log_views.LogIngestView.as_view(), name="logs_ingest"),
    path("logs/api/bulk/", arpia_log_views.LogBulkIngestView.as_view(), name="logs_bulk_ingest"),
    path("logs/api/stats/", arpia_log_views.LogStatsView.as_view(), name="logs_stats"),
    path("logs/<int:pk>/", arpia_log_views.log_detail_api, name="logs_detail_api"),

    # AI: lista inicial (placeholder)
    path("ai/", arpia_ai_views.AIListView.as_view(), name="ai_list"),
    # ...existing app routes...
]