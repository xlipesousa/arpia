from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from arpia_core.models import Project


def _default_reference() -> str:
	return uuid.uuid4().hex[:12]


class ScanSession(models.Model):
	class Status(models.TextChoices):
		PLANNED = "planned", "Planejado"
		READY = "ready", "Pronto"
		RUNNING = "running", "Em execução"
		COMPLETED = "completed", "Concluído"
		FAILED = "failed", "Falhou"
		CANCELED = "canceled", "Cancelado"

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	reference = models.CharField(max_length=32, default=_default_reference, unique=True, editable=False)
	project = models.ForeignKey(Project, related_name="scan_sessions", on_delete=models.CASCADE)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		related_name="scan_sessions",
		on_delete=models.CASCADE,
	)
	title = models.CharField(max_length=200)
	status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNED)
	config_snapshot = models.JSONField(default=dict, blank=True)
	macros_snapshot = models.JSONField(default=dict, blank=True)
	report_snapshot = models.JSONField(default=dict, blank=True)
	started_at = models.DateTimeField(null=True, blank=True)
	finished_at = models.DateTimeField(null=True, blank=True)
	last_error = models.TextField(blank=True)
	notes = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("-created_at",)
		indexes = [
			models.Index(fields=["project", "created_at"], name="idx_scan_session_project"),
			models.Index(fields=["status", "created_at"], name="idx_scan_session_status"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"Scan {self.title} ({self.reference})"

	@property
	def is_terminal(self) -> bool:
		return self.status in {
			self.Status.COMPLETED,
			self.Status.FAILED,
			self.Status.CANCELED,
		}

	@property
	def progress_percent(self) -> int:
		value = self.progress or 0
		try:
			return max(0, min(100, int(round(float(value) * 100))))
		except (TypeError, ValueError):  # pragma: no cover - defensivo
			return 0

	@property
	def progress_percent(self) -> int:
		value = self.progress or 0
		try:
			return max(0, min(100, int(round(float(value) * 100))))
		except (TypeError, ValueError):  # pragma: no cover - defensivo
			return 0

	def mark_started(self) -> None:
		self.status = self.Status.RUNNING
		self.started_at = timezone.now()
		self.save(update_fields=["status", "started_at", "updated_at"])

	def mark_finished(self, *, success: bool, error: str = "") -> None:
		self.status = self.Status.COMPLETED if success else self.Status.FAILED
		self.finished_at = timezone.now()
		self.last_error = error
		self.save(update_fields=["status", "finished_at", "last_error", "updated_at"])


class ScanTask(models.Model):
	class Kind(models.TextChoices):
		CONNECTIVITY = "connectivity", "Teste de conectividade"
		DISCOVERY_RUSTSCAN = "discovery_rustscan", "Descoberta rápida (Rustscan)"
		DISCOVERY_NMAP = "discovery_nmap", "Níveis de ruído (Nmap)"
		CUSTOM = "custom", "Personalizado"

	class Status(models.TextChoices):
		PENDING = "pending", "Pendente"
		QUEUED = "queued", "Na fila"
		RUNNING = "running", "Em execução"
		COMPLETED = "completed", "Concluído"
		FAILED = "failed", "Falhou"
		CANCELED = "canceled", "Cancelado"

	session = models.ForeignKey(ScanSession, related_name="tasks", on_delete=models.CASCADE)
	order = models.PositiveIntegerField(default=0)
	kind = models.CharField(max_length=40, choices=Kind.choices, default=Kind.CUSTOM)
	status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
	name = models.CharField(max_length=200)
	tool = models.ForeignKey(
		"arpia_core.Tool",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="scan_tasks",
	)
	script = models.ForeignKey(
		"arpia_core.Script",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="scan_tasks",
	)
	wordlist = models.ForeignKey(
		"arpia_core.Wordlist",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="scan_tasks",
	)
	parameters = models.JSONField(default=dict, blank=True)
	progress = models.FloatField(default=0.0)
	stdout = models.TextField(blank=True)
	stderr = models.TextField(blank=True)
	started_at = models.DateTimeField(null=True, blank=True)
	finished_at = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("session", "order", "id")
		indexes = [
			models.Index(fields=["session", "kind"], name="idx_scan_task_session_kind"),
			models.Index(fields=["status", "updated_at"], name="idx_scan_task_status"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.name} ({self.get_kind_display()})"

	@property
	def is_terminal(self) -> bool:
		return self.status in {
			self.Status.COMPLETED,
			self.Status.FAILED,
			self.Status.CANCELED,
		}


class ScanFinding(models.Model):
	class Kind(models.TextChoices):
		SUMMARY = "summary", "Resumo"
		TARGET = "target", "Alvo"
		PORT = "port", "Porta"
		SERVICE = "service", "Serviço"
		NOTE = "note", "Observação"

	session = models.ForeignKey(ScanSession, related_name="findings", on_delete=models.CASCADE)
	source_task = models.ForeignKey(
		ScanTask,
		related_name="findings",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
	)
	kind = models.CharField(max_length=20, choices=Kind.choices, default=Kind.SUMMARY)
	title = models.CharField(max_length=200)
	summary = models.TextField(blank=True)
	data = models.JSONField(default=dict, blank=True)
	severity = models.CharField(max_length=32, blank=True)
	order = models.PositiveIntegerField(default=0)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ("session", "order", "id")
		indexes = [
			models.Index(fields=["session", "kind"], name="idx_scan_finding_session_kind"),
			models.Index(fields=["severity", "session"], name="idx_scan_finding_severity"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.get_kind_display()} — {self.title}"
