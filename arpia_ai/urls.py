from django.urls import path

from . import views

app_name = "arpia_ai"

urlpatterns = [
    path("", views.AIHomeView.as_view(), name="home"),
    path("assist/", views.assist_request, name="assist"),
    path("providers/", views.list_providers, name="providers"),
    path(
        "providers/openai/credential/",
        views.register_openai_credential,
        name="provider_openai_credential",
    ),
]
