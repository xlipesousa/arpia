from django.urls import path

from . import views

app_name = "arpia_hunt"

urlpatterns = [
    path("", views.HuntDashboardView.as_view(), name="dashboard"),
    path("findings/<uuid:pk>/", views.HuntFindingDetailView.as_view(), name="finding-detail"),
    path("api/findings/", views.HuntFindingListAPIView.as_view(), name="api-findings"),
]
