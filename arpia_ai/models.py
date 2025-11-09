from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils.text import slugify

from arpia_core.models import Project


class Provider(models.Model):
	id = models.BigAutoField(primary_key=True)
	slug = models.SlugField(max_length=80, unique=True)
	name = models.CharField(max_length=120)
	description = models.TextField(blank=True)
	base_url = models.URLField(blank=True)
	metadata = models.JSONField(default=dict, blank=True)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("name",)

	def save(self, *args, **kwargs):  # noqa: D401 - slug auto-fill
		if not self.slug:
			self.slug = slugify(self.name) or str(uuid.uuid4())
		super().save(*args, **kwargs)

	def __str__(self) -> str:
		return self.name

	@property
	def default_model(self) -> str | None:
		return self.metadata.get("default_model") if isinstance(self.metadata, dict) else None


class ProviderCredential(models.Model):
	id = models.BigAutoField(primary_key=True)
	provider = models.ForeignKey(Provider, related_name="credentials", on_delete=models.CASCADE)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		related_name="ai_credentials",
		on_delete=models.CASCADE,
	)
	label = models.CharField(max_length=120, default="default")
	api_key = models.CharField(max_length=512)
	metadata = models.JSONField(default=dict, blank=True)
	last_used_at = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = (
			("provider", "owner", "label"),
		)
		ordering = ("provider", "label")

	def __str__(self) -> str:
		return f"{self.provider.name} — {self.label}"

	@property
	def masked_api_key(self) -> str:
		if not self.api_key:
			return "—"
		visible = self.api_key[-4:]
		return f"****{visible}"

	def touch_last_used(self) -> None:
		from django.utils import timezone

		self.last_used_at = timezone.now()
		self.save(update_fields=["last_used_at"])


class ChatSession(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		related_name="ai_sessions",
		on_delete=models.CASCADE,
	)
	provider = models.ForeignKey(Provider, related_name="sessions", on_delete=models.PROTECT)
	credential = models.ForeignKey(
		ProviderCredential,
		related_name="sessions",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	project = models.ForeignKey(
		Project,
		related_name="ai_sessions",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	title = models.CharField(max_length=180, blank=True)
	context_snapshot = models.JSONField(default=dict, blank=True)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("-created_at",)

	def __str__(self) -> str:
		base = self.title or "Sessão de IA"
		return f"{base} ({self.provider.name})"


class ChatMessage(models.Model):
	class Role(models.TextChoices):
		SYSTEM = "system", "System"
		USER = "user", "User"
		ASSISTANT = "assistant", "Assistant"
		TOOL = "tool", "Tool"

	id = models.BigAutoField(primary_key=True)
	session = models.ForeignKey(ChatSession, related_name="messages", on_delete=models.CASCADE)
	role = models.CharField(max_length=24, choices=Role.choices)
	content = models.TextField()
	metadata = models.JSONField(default=dict, blank=True)
	token_count = models.PositiveIntegerField(default=0)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ("created_at", "id")

	def __str__(self) -> str:
		snippet = (self.content[:32] + "…") if len(self.content) > 32 else self.content
		return f"{self.get_role_display()} :: {snippet}"
