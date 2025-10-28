from django.urls import path

from . import views

app_name = "arpia_report"

urlpatterns = [
    path("", views.ReportLandingView.as_view(), name="report_home"),
    path("api/sessions/<uuid:pk>/", views.api_session_report, name="api_session_report"),
    path("api/projects/<uuid:pk>/", views.api_project_report, name="api_project_report"),
]
