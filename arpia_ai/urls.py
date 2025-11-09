from django.urls import path

from . import views

app_name = "arpia_ai"

urlpatterns = [
    path("", views.AIHomeView.as_view(), name="home"),
    path("assist/", views.assist_request, name="assist"),
]
