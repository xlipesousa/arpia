from django.urls import path

from .views import AIListView, project_context_view

app_name = "arpia_ai"

urlpatterns = [
    path("dashboard/", AIListView.as_view(), name="dashboard"),
    path("projects/<uuid:project_id>/context/", project_context_view, name="project_context"),
]
