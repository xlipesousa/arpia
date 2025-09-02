import uuid
from django.db import models
from django.utils import timezone


class Project(models.Model):
    """Agrupa ativos e configurações de um escopo lógico."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=220, unique=True)
    slug = models.SlugField(max_length=220, unique=True)
    summary = models.TextField(blank=True)
    created = models.DateTimeField(default=timezone.now, editable=False)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created",)
        verbose_name = "Projeto"
        verbose_name_plural = "Projetos"

    def __str__(self):
        return self.title


class Asset(models.Model):
    """Representa um ativo consolidado (host, container, serviço lógico)."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, related_name="assets", on_delete=models.CASCADE)
    identifier = models.CharField(max_length=300, db_index=True)  # identificador reconciliado
    name = models.CharField(max_length=300, blank=True)
    hostnames = models.JSONField(default=list, blank=True)
    ips = models.JSONField(default=list, blank=True)
    category = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created = models.DateTimeField(default=timezone.now, editable=False)
    last_seen = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = (("project", "identifier"),)
        ordering = ("-last_seen", "-created")
        verbose_name = "Ativo"
        verbose_name_plural = "Ativos"

    def __str__(self):
        return self.name or self.identifier


class ObservedEndpoint(models.Model):
    """Observações coletadas (scans, ingest, discovery)."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    asset = models.ForeignKey(Asset, related_name="endpoints", on_delete=models.SET_NULL, null=True, blank=True)
    ip = models.CharField(max_length=46)
    port = models.PositiveIntegerField()
    proto = models.CharField(max_length=24, blank=True)
    service = models.CharField(max_length=200, blank=True)
    path = models.CharField(max_length=500, blank=True)
    raw = models.JSONField(default=dict, blank=True)
    source = models.CharField(max_length=120, blank=True)
    first_seen = models.DateTimeField(default=timezone.now, editable=False)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["ip", "port", "proto", "source"], name="uniq_endpoint_by_source")
        ]
        ordering = ("-last_seen", "-first_seen")
        verbose_name = "Endpoint Observado"
        verbose_name_plural = "Endpoints Observados"

    def __str__(self):
        return f"{self.ip}:{self.port}/{self.proto or 'tcp'}"
