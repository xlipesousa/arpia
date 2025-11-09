"""
URL configuration for arpia_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from arpia_pentest.views import PentestDashboardView
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/", include("django.contrib.auth.urls")),

    # delega o root para as URLs da app (contém projects_list, scripts_list, ...)
    path("", include("arpia_core.urls")),
    path("scan/", include(("arpia_scan.urls", "arpia_scan"), namespace="arpia_scan")),
    path("vuln/", include(("arpia_vuln.urls", "arpia_vuln"), namespace="arpia_vuln")),
    path("hunt/", include(("arpia_hunt.urls", "arpia_hunt"), namespace="arpia_hunt")),
    path("reports/", include(("arpia_report.urls", "arpia_report"), namespace="arpia_report")),
    path("pentest/", include(("arpia_pentest.urls", "arpia_pentest"), namespace="arpia_pentest")),
    path("pentest", PentestDashboardView.as_view(), name="pentest_dashboard"),
    path("ai/", include(("arpia_ai.urls", "arpia_ai"), namespace="arpia_ai")),
    path("api/", include("api.urls")),
]
