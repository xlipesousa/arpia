from django.urls import path

from . import views

app_name = "arpia_vuln"

urlpatterns = [
    path("", views.VulnDashboardView.as_view(), name="dashboard"),
    path("sessions/<uuid:pk>/", views.VulnSessionDetailView.as_view(), name="session_detail"),
    path(
        "sessions/<uuid:pk>/relatorio/",
        views.VulnSessionReportPreviewView.as_view(),
        name="session_report_preview",
    ),
    path("api/dashboard/", views.api_dashboard_snapshot, name="api_dashboard_snapshot"),
    path("api/sessions/plan/", views.api_session_plan, name="api_session_plan"),
    path("api/sessions/<uuid:pk>/start/", views.api_session_start, name="api_session_start"),
]
