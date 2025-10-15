import os
import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone as dj_timezone
from django.utils.text import slugify


class Project(models.Model):
    """Agrupa ativos e configurações de um escopo lógico."""
    class Status(models.TextChoices):
        DRAFT = "draft", "Rascunho"
        ACTIVE = "active", "Ativo"
        PAUSED = "paused", "Pausado"
        COMPLETED = "completed", "Concluído"
        ARCHIVED = "archived", "Arquivado"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="projects_owned",
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=220)
    slug = models.SlugField(max_length=220)
    description = models.TextField(blank=True)
    client_name = models.CharField(max_length=220, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.DRAFT)
    visibility = models.CharField(max_length=24, default="private")

    start_at = models.DateTimeField(null=True, blank=True)
    end_at = models.DateTimeField(null=True, blank=True)
    timezone = models.CharField(max_length=64, blank=True, default="America/Sao_Paulo")

    hosts = models.TextField(blank=True)
    protected_hosts = models.TextField(blank=True)
    networks = models.TextField(blank=True)
    ports = models.TextField(blank=True)
    credentials_json = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    created = models.DateTimeField(default=dj_timezone.now, editable=False)
    modified = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created",)
        verbose_name = "Projeto"
        verbose_name_plural = "Projetos"
        constraints = [
            models.UniqueConstraint(fields=["owner", "slug"], name="uniq_project_owner_slug"),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or slugify(str(self.id))
            candidate = base_slug
            suffix = 1
            while Project.objects.exclude(pk=self.pk).filter(owner=self.owner, slug=candidate).exists():
                suffix += 1
                candidate = f"{base_slug}-{suffix}"
            self.slug = candidate
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def owner_display(self):
        return getattr(self.owner, "get_full_name", lambda: "")() or self.owner.get_username()


class ProjectMembership(models.Model):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        EDITOR = "editor", "Editor"
        VIEWER = "viewer", "Viewer"

    id = models.BigAutoField(primary_key=True)
    project = models.ForeignKey(Project, related_name="memberships", on_delete=models.CASCADE)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, related_name="project_memberships", on_delete=models.CASCADE)
    role = models.CharField(max_length=24, choices=Role.choices, default=Role.VIEWER)
    invited_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="project_invitations_sent",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("project", "user")
        verbose_name = "Participante de Projeto"
        verbose_name_plural = "Participantes de Projeto"

    def __str__(self) -> str:
        return f"{self.user} -> {self.project} ({self.role})"


class ScriptQuerySet(models.QuerySet):
    def for_user(self, user):
        if user.is_superuser:
            return self.all()
        return self.filter(models.Q(kind="default") | models.Q(owner=user))


class Script(models.Model):
    class Kind(models.TextChoices):
        DEFAULT = "default", "Default"
        USER = "user", "Personalizado"

    id = models.BigAutoField(primary_key=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="scripts",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=180)
    slug = models.SlugField(max_length=220, db_index=True)
    description = models.TextField(blank=True)
    filename = models.CharField(max_length=220)
    content = models.TextField()
    kind = models.CharField(max_length=24, choices=Kind.choices, default=Kind.USER)
    tags = models.JSONField(default=list, blank=True)
    source_path = models.CharField(max_length=500, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ScriptQuerySet.as_manager()

    class Meta:
        unique_together = (
            ("owner", "slug"),
            ("owner", "filename"),
        )
        constraints = [
            models.UniqueConstraint(
                fields=["slug"],
                condition=models.Q(owner__isnull=True),
                name="uniq_default_script_slug",
            ),
            models.UniqueConstraint(
                fields=["filename"],
                condition=models.Q(owner__isnull=True),
                name="uniq_default_script_filename",
            ),
        ]
        ordering = ("name",)
        verbose_name = "Script"
        verbose_name_plural = "Scripts"

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or slugify(self.filename) or slugify(str(self.pk))
            candidate = base_slug or "script"
            suffix = 1
            owner_filter = models.Q(owner=self.owner)
            while Script.objects.exclude(pk=self.pk).filter(owner_filter, slug=candidate).exists():
                suffix += 1
                candidate = f"{base_slug}-{suffix}"
            self.slug = candidate
        super().save(*args, **kwargs)

    @property
    def is_default(self) -> bool:
        return self.kind == Script.Kind.DEFAULT

    def __str__(self) -> str:
        return self.name


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
    created = models.DateTimeField(default=dj_timezone.now, editable=False)
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
    first_seen = models.DateTimeField(default=dj_timezone.now, editable=False)
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


class ToolQuerySet(models.QuerySet):
    def for_user(self, user):
        if not user or not getattr(user, "is_authenticated", False):
            return self.none()
        return self.filter(owner=user)


class Tool(models.Model):
    id = models.BigAutoField(primary_key=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="tools",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=120)
    slug = models.SlugField(max_length=150)
    description = models.TextField(blank=True)
    path = models.CharField(max_length=500)
    category = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ToolQuerySet.as_manager()

    class Meta:
        verbose_name = "Ferramenta"
        verbose_name_plural = "Ferramentas"
        ordering = ("name",)
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "name"],
                condition=Q(owner__isnull=False),
                name="uniq_tool_owner_name",
            ),
            models.UniqueConstraint(
                fields=["owner", "slug"],
                condition=Q(owner__isnull=False),
                name="uniq_tool_owner_slug",
            ),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or "tool"
            candidate = base_slug
            suffix = 1
            owner_filter = Q(owner=self.owner)
            while Tool.objects.exclude(pk=self.pk).filter(owner_filter, slug=candidate).exists():
                suffix += 1
                candidate = f"{base_slug}-{suffix}"
            self.slug = candidate
        super().save(*args, **kwargs)

    @property
    def macro_key(self) -> str:
        return f"TOOL_{self.slug.replace('-', '_').upper()}"

    def __str__(self):
        return f"{self.name} ({self.path})"


class WordlistQuerySet(models.QuerySet):
    def for_user(self, user):
        if not user or not getattr(user, "is_authenticated", False):
            return self.none()
        return self.filter(owner=user)


class Wordlist(models.Model):
    id = models.BigAutoField(primary_key=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        related_name="wordlists",
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=180)
    description = models.TextField(blank=True)
    path = models.CharField(max_length=500)
    category = models.CharField(max_length=80, blank=True)
    tags = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = WordlistQuerySet.as_manager()

    class Meta:
        verbose_name = "Wordlist"
        verbose_name_plural = "Wordlists"
        ordering = ("name",)
        constraints = [
            models.UniqueConstraint(
                fields=["owner", "name"],
                condition=Q(owner__isnull=False),
                name="uniq_wordlist_owner_name",
            ),
            models.UniqueConstraint(
                fields=["owner", "slug"],
                condition=Q(owner__isnull=False),
                name="uniq_wordlist_owner_slug",
            ),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or "wordlist"
            candidate = base_slug
            suffix = 1
            owner_filter = Q(owner=self.owner)
            while Wordlist.objects.exclude(pk=self.pk).filter(owner_filter, slug=candidate).exists():
                suffix += 1
                candidate = f"{base_slug}-{suffix}"
            self.slug = candidate
        super().save(*args, **kwargs)

    @property
    def macro_key(self) -> str:
        return f"WORDLIST_{self.slug.replace('-', '_').upper()}"

    def __str__(self):
        return f"{self.name} ({self.path})"
