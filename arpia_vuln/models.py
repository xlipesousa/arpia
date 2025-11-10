from __future__ import annotations

import uuid

import logging

from django.conf import settings
from django.db import models
from django.utils import timezone

from arpia_core.models import Project


logger = logging.getLogger(__name__)


def _default_reference() -> str:
	return uuid.uuid4().hex[:12]


class VulnScanSession(models.Model):
	class Status(models.TextChoices):
		PLANNED = "planned", "Planejada"
		READY = "ready", "Pronta"
		RUNNING = "running", "Em execução"
		COMPLETED = "completed", "Concluída"
		FAILED = "failed", "Falhou"
		CANCELED = "canceled", "Cancelada"

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	reference = models.CharField(max_length=32, default=_default_reference, unique=True, editable=False)
	project = models.ForeignKey(Project, related_name="vuln_sessions", on_delete=models.CASCADE)
	owner = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		related_name="vuln_sessions",
		on_delete=models.CASCADE,
	)
	source_scan_session = models.ForeignKey(
		"arpia_scan.ScanSession",
		related_name="vulnerability_sessions",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	title = models.CharField(max_length=200)
	status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNED)
	config_snapshot = models.JSONField(default=dict, blank=True)
	macros_snapshot = models.JSONField(default=dict, blank=True)
	targets_snapshot = models.JSONField(default=dict, blank=True)
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
			models.Index(fields=["project", "created_at"], name="idx_vuln_session_project"),
			models.Index(fields=["status", "created_at"], name="idx_vuln_session_status"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"Vuln scan {self.title} ({self.reference})"

	@property
	def is_terminal(self) -> bool:
		return self.status in {
			self.Status.COMPLETED,
			self.Status.FAILED,
			self.Status.CANCELED,
		}

	def mark_started(self) -> None:
		self.status = self.Status.RUNNING
		self.started_at = timezone.now()
		self.save(update_fields=["status", "started_at", "updated_at"])

	def mark_finished(self, *, success: bool, error: str = "") -> None:
		self.status = self.Status.COMPLETED if success else self.Status.FAILED
		self.finished_at = timezone.now()
		self.last_error = error
		self.save(update_fields=["status", "finished_at", "last_error", "updated_at"])
		self._trigger_hunt_sync(success=success)

	def _trigger_hunt_sync(self, *, success: bool) -> None:
		if not success:
			return
		if not getattr(settings, "ARPIA_HUNT_AUTO_SYNC", True):
			return
		project_id = getattr(self, "project_id", None)
		if not project_id:
			return
		try:
			from arpia_hunt.services import synchronize_findings
		except Exception:  # pragma: no cover - import error inesperado
			logger.exception("Falha ao importar sincronizacao Hunt.")
			return
		try:
			synchronize_findings(
				project_ids=[str(project_id)],
				create_log=False,
				audit_logs=False,
			)
		except Exception:  # pragma: no cover - sincronizacao falhou
			logger.exception("Erro ao sincronizar Hunt apos sessao de vulnerabilidades.")


class VulnTask(models.Model):
	class Kind(models.TextChoices):
		DISCOVERY_NMAP = "discovery_nmap", "Discovery (Nmap)"
		SERVICE_ENUMERATION = "service_enum", "Enumeração de serviços"
		GREENBONE_SCAN = "greenbone_scan", "Greenbone"
		SCRIPT = "script", "Script"
		CUSTOM = "custom", "Personalizado"

	class Status(models.TextChoices):
		PENDING = "pending", "Pendente"
		QUEUED = "queued", "Na fila"
		RUNNING = "running", "Em execução"
		COMPLETED = "completed", "Concluída"
		FAILED = "failed", "Falhou"
		CANCELED = "canceled", "Cancelada"

	session = models.ForeignKey(VulnScanSession, related_name="tasks", on_delete=models.CASCADE)
	order = models.PositiveIntegerField(default=0)
	kind = models.CharField(max_length=32, choices=Kind.choices, default=Kind.CUSTOM)
	status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
	name = models.CharField(max_length=200)
	tool = models.ForeignKey(
		"arpia_core.Tool",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="vuln_tasks",
	)
	script = models.ForeignKey(
		"arpia_core.Script",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="vuln_tasks",
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
			models.Index(fields=["session", "kind"], name="idx_vuln_task_session_kind"),
			models.Index(fields=["status", "updated_at"], name="idx_vuln_task_status"),
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


class VulnerabilityFinding(models.Model):
	class Severity(models.TextChoices):
		CRITICAL = "critical", "Crítica"
		HIGH = "high", "Alta"
		MEDIUM = "medium", "Média"
		LOW = "low", "Baixa"
		INFO = "info", "Informativa"
		UNKNOWN = "unknown", "Indefinida"

	class Status(models.TextChoices):
		OPEN = "open", "Aberta"
		ACKNOWLEDGED = "ack", "Reconhecida"
		RESOLVED = "resolved", "Resolvida"

	session = models.ForeignKey(VulnScanSession, related_name="findings", on_delete=models.CASCADE)
	source_task = models.ForeignKey(
		VulnTask,
		related_name="findings",
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
	)
	cve = models.CharField(max_length=40, blank=True)
	title = models.CharField(max_length=255)
	summary = models.TextField(blank=True)
	severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.UNKNOWN)
	status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
	host = models.CharField(max_length=200, blank=True)
	service = models.CharField(max_length=200, blank=True)
	port = models.PositiveIntegerField(null=True, blank=True)
	protocol = models.CharField(max_length=12, blank=True)
	cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
	cvss_vector = models.CharField(max_length=128, blank=True)
	data = models.JSONField(default=dict, blank=True)
	detected_at = models.DateTimeField(default=timezone.now)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ("session", "-cvss_score", "severity", "id")
		indexes = [
			models.Index(fields=["session", "severity"], name="idx_vuln_finding_severity"),
			models.Index(fields=["cve"], name="idx_vuln_finding_cve"),
			models.Index(fields=["host", "port"], name="idx_vuln_finding_target"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.title} ({self.get_severity_display()})"

	@property
	def display_score(self) -> str:
		if self.cvss_score is None:
			return "—"
		return f"{self.cvss_score:.1f}"
