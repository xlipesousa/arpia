from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import render

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/home.html"
    # LoginRequiredMixin redireciona para /accounts/login/ se não autenticado

# Create your views here.
