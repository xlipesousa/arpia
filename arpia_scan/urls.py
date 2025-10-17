from django.urls import path

from . import views

app_name = "arpia_scan"

urlpatterns = [
    path("", views.ScanDashboardView.as_view(), name="dashboard"),
    path("sessions/<uuid:pk>/", views.ScanSessionDetailView.as_view(), name="session_detail"),
    path("sessions/<uuid:pk>/relatorio/", views.ScanSessionReportPreviewView.as_view(), name="session_report_preview"),
    path(
        "sessions/<uuid:pk>/export/alvos.csv",
        views.ScanSessionTargetsExportView.as_view(),
        {"format": "csv"},
        name="session_targets_export_csv",
    ),
    path(
        "sessions/<uuid:pk>/export/alvos.json",
        views.ScanSessionTargetsExportView.as_view(),
        {"format": "json"},
        name="session_targets_export_json",
    ),
    path("api/sessions/", views.api_session_create, name="api_session_create"),
    path("api/sessions/<uuid:pk>/start/", views.api_session_start, name="api_session_start"),
    path("api/sessions/<uuid:pk>/status/", views.api_session_status, name="api_session_status"),
    path("api/sessions/<uuid:pk>/logs/", views.api_session_logs, name="api_session_logs"),
]
