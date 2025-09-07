from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import TemplateView
from django.shortcuts import render

class AIListView(LoginRequiredMixin, TemplateView):
    """
    Lista básica para o módulo arpia_ai (placeholder).
    """
    template_name = "ai/list.html"

# Create your views here.
