from django.db import models
from django.utils import timezone


class LogEntry(models.Model):
	"""Entrada de log centralizada para todos os módulos do ARPIA."""

	class Severity(models.TextChoices):
		DEBUG = "DEBUG", "Debug"
		INFO = "INFO", "Info"
		NOTICE = "NOTICE", "Notice"
		WARN = "WARN", "Warn"
		ERROR = "ERROR", "Error"
		CRITICAL = "CRITICAL", "Critical"

	class Channel(models.TextChoices):
		INTERNAL = "internal", "Internal"
		API = "api", "API"
		BATCH = "batch", "Batch"

	version = models.PositiveIntegerField(default=1)
	timestamp = models.DateTimeField(default=timezone.now, db_index=True)
	source_app = models.CharField(max_length=64, db_index=True)
	component = models.CharField(max_length=128, blank=True)
	event_type = models.CharField(max_length=128, db_index=True)
	severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.INFO)
	message = models.CharField(max_length=512)
	details = models.JSONField(default=dict, blank=True)
	context = models.JSONField(default=dict, blank=True)
	correlation = models.JSONField(default=dict, blank=True)
	tags = models.JSONField(default=list, blank=True)

	project_ref = models.CharField(max_length=128, blank=True, db_index=True)
	asset_ref = models.CharField(max_length=128, blank=True)
	user_ref = models.CharField(max_length=128, blank=True)

	ingestion_channel = models.CharField(max_length=16, choices=Channel.choices, default=Channel.INTERNAL)
	ingested_at = models.DateTimeField(auto_now_add=True, db_index=True)

	class Meta:
		ordering = ["-timestamp", "-id"]
		indexes = [
			models.Index(fields=["source_app", "timestamp"], name="idx_log_src_ts"),
			models.Index(fields=["event_type", "timestamp"], name="idx_log_evt_ts"),
			models.Index(fields=["project_ref", "timestamp"], name="idx_log_project_ts"),
			models.Index(fields=["severity", "timestamp"], name="idx_log_sev_ts"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"[{self.timestamp:%Y-%m-%d %H:%M:%S}] {self.source_app} {self.event_type}" 
