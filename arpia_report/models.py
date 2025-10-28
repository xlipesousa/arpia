from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from arpia_core.models import Project
from arpia_scan.models import ScanSession


class BaseReportEntry(models.Model):
	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	project = models.ForeignKey(Project, related_name="%(class)ss", on_delete=models.CASCADE)
	title = models.CharField(max_length=255)
	summary = models.TextField(blank=True)
	payload = models.JSONField(default=dict, blank=True)
	tags = models.JSONField(default=list, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		abstract = True
		ordering = ["-created_at", "-id"]


class ScanReportEntry(BaseReportEntry):
	session = models.OneToOneField(ScanSession, related_name="report_entry", on_delete=models.CASCADE)
	status = models.CharField(max_length=32, blank=True)
	started_at = models.DateTimeField(null=True, blank=True)
	finished_at = models.DateTimeField(null=True, blank=True)

	class Meta(BaseReportEntry.Meta):
		verbose_name = "Relatório de Scan"
		verbose_name_plural = "Relatórios de Scan"


class VulnerabilityReportEntry(BaseReportEntry):
	source_identifier = models.CharField(max_length=128, blank=True)
	severity_distribution = models.JSONField(default=dict, blank=True)
	cves = models.JSONField(default=list, blank=True)

	class Meta(BaseReportEntry.Meta):
		verbose_name = "Relatório de Vulnerabilidades"
		verbose_name_plural = "Relatórios de Vulnerabilidades"


class HuntReportEntry(BaseReportEntry):
	intel_summary = models.JSONField(default=dict, blank=True)
	indicators = models.JSONField(default=list, blank=True)

	class Meta(BaseReportEntry.Meta):
		verbose_name = "Relatório de Hunt"
		verbose_name_plural = "Relatórios de Hunt"


class PentestReportEntry(BaseReportEntry):
	engagement_ref = models.CharField(max_length=128, blank=True)
	findings = models.JSONField(default=list, blank=True)
	recommendations = models.JSONField(default=list, blank=True)

	class Meta(BaseReportEntry.Meta):
		verbose_name = "Relatório de Pentest"
		verbose_name_plural = "Relatórios de Pentest"


class ProjectReport(models.Model):
	class Status(models.TextChoices):
		DRAFT = "draft", "Rascunho"
		IN_REVIEW = "in_review", "Em revisão"
		FINAL = "final", "Final"

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	project = models.ForeignKey(Project, related_name="project_reports", on_delete=models.CASCADE)
	title = models.CharField(max_length=255)
	summary = models.TextField(blank=True)
	payload = models.JSONField(default=dict, blank=True)
	status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
	generated_at = models.DateTimeField(default=timezone.now)
	generated_by = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		null=True,
		blank=True,
		on_delete=models.SET_NULL,
		related_name="generated_reports",
	)
	valid_until = models.DateField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ["-generated_at", "-id"]
		verbose_name = "Relatório de Projeto"
		verbose_name_plural = "Relatórios de Projeto"

	def mark_final(self, user=None):
		self.status = self.Status.FINAL
		if user:
			self.generated_by = user
		self.generated_at = timezone.now()
		self.save(update_fields=["status", "generated_by", "generated_at", "updated_at"])
