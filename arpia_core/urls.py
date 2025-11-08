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
    path("projects/<uuid:pk>/delete/", views.projects_delete, name="projects_delete"),

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
    path("tools/", views.ToolWordlistView.as_view(), name="tools_list"),
    path("tools/new/", views.ToolCreateView.as_view(), name="tools_add"),
    path("tools/<slug:slug>/edit/", views.ToolUpdateView.as_view(), name="tools_configure"),
    path("tools/<slug:slug>/delete/", views.ToolDeleteView.as_view(), name="tools_delete"),

    path("wordlists/new/", views.WordlistCreateView.as_view(), name="wordlists_add"),
    path("wordlists/<slug:slug>/edit/", views.WordlistUpdateView.as_view(), name="wordlists_edit"),
    path("wordlists/<slug:slug>/delete/", views.WordlistDeleteView.as_view(), name="wordlists_delete"),
    path("wordlists/<slug:slug>/download/", views.wordlists_download, name="wordlists_download"),

    # Logs: delega para arpia_log.views
    path("logs/", arpia_log_views.LogsListView.as_view(), name="logs_list"),
    path("logs/api/", arpia_log_views.logs_api, name="logs_api"),
    path("logs/api/ingest/", arpia_log_views.LogIngestView.as_view(), name="logs_ingest"),
    path("logs/api/bulk/", arpia_log_views.LogBulkIngestView.as_view(), name="logs_bulk_ingest"),
    path("logs/api/stats/", arpia_log_views.LogStatsView.as_view(), name="logs_stats"),
    path("logs/api/tail/", arpia_log_views.log_tail_api, name="logs_tail_api"),
    path("logs/<int:pk>/", arpia_log_views.log_detail_api, name="logs_detail_api"),
    path("logs/<int:pk>/download/", arpia_log_views.log_download_api, name="logs_download"),
    path("logs/<int:pk>/delete/", arpia_log_views.log_delete_api, name="logs_delete"),

    # AI: lista inicial (placeholder)
    path("ai/", arpia_ai_views.AIListView.as_view(), name="ai_list"),
    # ...existing app routes...
]