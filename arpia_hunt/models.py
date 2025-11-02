from __future__ import annotations

import json
import uuid
from typing import Any, Dict

from django.db import models
from django.db.models import Q
from django.utils import timezone

from arpia_core.models import Asset, Project
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession


class HuntFinding(models.Model):
	"""Entrada normalizada usada pelo módulo Hunt para correlações."""

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	project = models.ForeignKey(Project, related_name="hunt_findings", on_delete=models.CASCADE)
	vulnerability = models.OneToOneField(
		VulnerabilityFinding, related_name="hunt_finding", on_delete=models.CASCADE
	)
	vuln_session = models.ForeignKey(
		VulnScanSession,
		related_name="hunt_findings",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	scan_session = models.ForeignKey(
		"arpia_scan.ScanSession",
		related_name="hunt_findings",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	asset = models.ForeignKey(
		Asset,
		related_name="hunt_findings",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)

	host = models.CharField(max_length=200, blank=True)
	service = models.CharField(max_length=200, blank=True)
	port = models.PositiveIntegerField(null=True, blank=True)
	protocol = models.CharField(max_length=12, blank=True)

	cve = models.CharField(max_length=40, blank=True)
	severity = models.CharField(
		max_length=16,
		choices=VulnerabilityFinding.Severity.choices,
		default=VulnerabilityFinding.Severity.UNKNOWN,
	)
	cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
	cvss_vector = models.CharField(max_length=128, blank=True)
	summary = models.TextField(blank=True)

	context = models.JSONField(default=dict, blank=True)
	tags = models.JSONField(default=list, blank=True)
	source_hash = models.CharField(max_length=64, blank=True, db_index=True)
	is_active = models.BooleanField(default=True)
	detected_at = models.DateTimeField(null=True, blank=True)
	last_synced_at = models.DateTimeField(default=timezone.now)
	blue_profile = models.JSONField(default=dict, blank=True)
	red_profile = models.JSONField(default=dict, blank=True)
	profile_version = models.PositiveIntegerField(default=0)
	last_profiled_at = models.DateTimeField(null=True, blank=True)
	state_version = models.PositiveIntegerField(default=0)
	last_state_snapshot_at = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)
	enrichments = models.ManyToManyField(
		"HuntEnrichment",
		through="HuntFindingEnrichment",
		related_name="findings",
		blank=True,
	)

	class Meta:
		ordering = ("-detected_at", "-cvss_score", "-created_at")
		indexes = [
			models.Index(fields=["project", "severity"], name="idx_hunt_finding_project_sev"),
			models.Index(fields=["cve"], name="idx_hunt_finding_cve"),
			models.Index(fields=["host", "port"], name="idx_hunt_finding_target"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		base = self.cve or self.vulnerability.title
		return f"{base} · {self.host or '—'}:{self.port or '—'}"

	def update_from_payload(self, payload: Dict[str, Any]) -> None:
		"""Atualiza campos a partir do payload normalizado."""
		for field in (
			"host",
			"service",
			"port",
			"protocol",
			"cve",
			"severity",
			"cvss_score",
			"cvss_vector",
			"summary",
			"context",
			"tags",
			"detected_at",
			"source_hash",
			"scan_session",
			"vuln_session",
			"asset",
		):
			if field in payload:
				setattr(self, field, payload[field])
		self.last_synced_at = timezone.now()

	@staticmethod
	def build_source_hash(data: Dict[str, Any]) -> str:
		payload = json.dumps(data, sort_keys=True, default=str)
		return uuid.uuid5(uuid.NAMESPACE_URL, payload).hex

	def _state_payload(self) -> Dict[str, Any]:
		return {
			"project_id": str(self.project_id),
			"vulnerability_id": str(self.vulnerability_id),
			"host": self.host,
			"service": self.service,
			"port": self.port,
			"protocol": self.protocol,
			"cve": self.cve,
			"severity": self.severity,
			"cvss_score": float(self.cvss_score) if self.cvss_score is not None else None,
			"cvss_vector": self.cvss_vector,
			"summary": self.summary,
			"tags": list(self.tags or []),
			"context": dict(self.context or {}),
			"detected_at": self.detected_at.isoformat() if self.detected_at else None,
			"last_synced_at": self.last_synced_at.isoformat() if self.last_synced_at else None,
		}

	def record_state_snapshot(self) -> bool:
		"""Persiste versão da camada de ingestão sempre que o hash mudar."""

		if not self.source_hash:
			return False

		if self.state_snapshots.filter(source_hash=self.source_hash).exists():
			return False

		self.state_version += 1
		self.last_state_snapshot_at = timezone.now()
		self.save(
			update_fields=[
				"state_version",
				"last_state_snapshot_at",
				"updated_at",
			]
		)

		HuntFindingState.objects.create(
			finding=self,
			version=self.state_version,
			source_hash=self.source_hash,
			payload=self._state_payload(),
		)
		return True

	def apply_profiles(
		self,
		*,
		blue_profile: dict,
		red_profile: dict,
		enrichment_ids: list[str],
	) -> bool:
		"""Atualiza perfis Blue/Red e cria snapshot quando houver mudança."""

		if self.blue_profile == blue_profile and self.red_profile == red_profile:
			return False

		self.blue_profile = blue_profile
		self.red_profile = red_profile
		self.profile_version += 1
		self.last_profiled_at = timezone.now()
		self.save(
			update_fields=[
				"blue_profile",
				"red_profile",
				"profile_version",
				"last_profiled_at",
				"updated_at",
			]
		)
		HuntFindingSnapshot.objects.create(
			finding=self,
			version=self.profile_version,
			blue_profile=blue_profile,
			red_profile=red_profile,
			enrichment_ids=enrichment_ids,
		)
		return True


class AttackTactic(models.Model):
	"""Catálogo compacto das táticas MITRE ATT&CK utilizadas pelo Hunt."""

	class Matrix(models.TextChoices):
		ENTERPRISE = "enterprise", "Enterprise"
		ICS = "ics", "ICS"
		MOBILE = "mobile", "Mobile"

	id = models.CharField(primary_key=True, max_length=16)
	name = models.CharField(max_length=128)
	short_description = models.TextField(blank=True)
	matrix = models.CharField(max_length=24, choices=Matrix.choices, default=Matrix.ENTERPRISE)
	order = models.PositiveSmallIntegerField(default=0)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("matrix", "order", "id")
		indexes = [
			models.Index(fields=["matrix", "order"], name="idx_attack_tactic_matrix_order"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.id} · {self.name}"


class AttackTechnique(models.Model):
	"""Catálogo de técnicas/subtécnicas ATT&CK utilizadas para recomendações."""

	id = models.CharField(primary_key=True, max_length=32)
	name = models.CharField(max_length=160)
	description = models.TextField(blank=True)
	is_subtechnique = models.BooleanField(default=False)
	parent = models.ForeignKey(
		"self",
		related_name="subtechniques",
		on_delete=models.CASCADE,
		null=True,
		blank=True,
	)
	tactic = models.ForeignKey(
		AttackTactic,
		related_name="techniques",
		on_delete=models.PROTECT,
	)
	platforms = models.JSONField(default=list, blank=True)
	datasources = models.JSONField(default=list, blank=True)
	external_references = models.JSONField(default=list, blank=True)
	version = models.CharField(max_length=32, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("id",)
		indexes = [
			models.Index(fields=["tactic", "is_subtechnique"], name="idx_attack_tech_tactic_sub"),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.id} · {self.name}"


class CveAttackTechnique(models.Model):
	"""Pivot que descreve o vínculo CVE ↔ técnica ATT&CK e sua confiança."""

	class Source(models.TextChoices):
		HEURISTIC = "heuristic", "Heurística"
		DATASET = "dataset", "Dataset"
		MANUAL = "manual", "Manual"

	class Confidence(models.TextChoices):
		LOW = "low", "Baixa"
		MEDIUM = "medium", "Média"
		HIGH = "high", "Alta"

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	cve = models.CharField(max_length=40, db_index=True)
	technique = models.ForeignKey(
		AttackTechnique,
		related_name="cve_links",
		on_delete=models.CASCADE,
	)
	source = models.CharField(max_length=16, choices=Source.choices, default=Source.HEURISTIC)
	confidence = models.CharField(max_length=8, choices=Confidence.choices, default=Confidence.MEDIUM)
	rationale = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = ("cve", "technique", "source")
		indexes = [
			models.Index(fields=["cve", "confidence"], name="idx_cve_attack_confidence"),
		]
		ordering = ("-updated_at", "-created_at")

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.cve} ↔ {self.technique_id}"


class HuntRecommendation(models.Model):
	"""Sugestões de ações Blue/Red derivadas das heurísticas ATT&CK."""

	class Type(models.TextChoices):
		BLUE = "blue", "Blue Team"
		RED = "red", "Red Team"

	class Generator(models.TextChoices):
		AUTOMATION = "automation", "Automação"
		ANALYST = "analyst", "Analista"
		IMPORT = "import", "Importação"

	id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
	finding = models.ForeignKey(
		HuntFinding,
		related_name="recommendations",
		on_delete=models.CASCADE,
		null=True,
		blank=True,
	)
	technique = models.ForeignKey(
		AttackTechnique,
		related_name="recommendations",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	recommendation_type = models.CharField(max_length=8, choices=Type.choices)
	title = models.CharField(max_length=160)
	summary = models.TextField(blank=True)
	confidence = models.CharField(
		max_length=8,
		choices=CveAttackTechnique.Confidence.choices,
		default=CveAttackTechnique.Confidence.MEDIUM,
	)
	evidence = models.JSONField(default=dict, blank=True)
	tags = models.JSONField(default=list, blank=True)
	generated_by = models.CharField(max_length=16, choices=Generator.choices, default=Generator.AUTOMATION)
	confidence_note = models.CharField(max_length=512, blank=True)
	playbook_slug = models.CharField(max_length=128, blank=True)
	source_enrichment = models.ForeignKey(
		"HuntEnrichment",
		related_name="recommendations",
		on_delete=models.SET_NULL,
		null=True,
		blank=True,
	)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ("-updated_at", "-created_at")
		indexes = [
			models.Index(fields=["finding", "recommendation_type"], name="idx_hunt_rec_finding_type"),
			models.Index(fields=["technique"], name="idx_hunt_rec_technique"),
			models.Index(
				fields=["recommendation_type", "created_at"],
				name="idx_hunt_rec_auto_recent",
				condition=Q(generated_by="automation"),
			),
			models.Index(
				fields=["playbook_slug"],
				name="idx_hunt_rec_playbook",
				condition=Q(playbook_slug__gt=""),
			),
		]

	def __str__(self) -> str:  # pragma: no cover - representação simples
		return f"{self.recommendation_type.upper()} · {self.title}"


class HuntSyncLog(models.Model):
	class Status(models.TextChoices):
		SUCCESS = "success", "Sucesso"
		ERROR = "error", "Erro"

	id = models.BigAutoField(primary_key=True)
	project = models.ForeignKey(
		Project,
		related_name="hunt_sync_runs",
		on_delete=models.CASCADE,
		null=True,
		blank=True,
	)
	status = models.CharField(max_length=12, choices=Status.choices, default=Status.SUCCESS)
	started_at = models.DateTimeField(default=timezone.now)
	finished_at = models.DateTimeField(null=True, blank=True)
	duration_ms = models.PositiveIntegerField(default=0)
	total_processed = models.PositiveIntegerField(default=0)
	created_count = models.PositiveIntegerField(default=0)
	updated_count = models.PositiveIntegerField(default=0)
	skipped_count = models.PositiveIntegerField(default=0)
	error_message = models.TextField(blank=True)

	class Meta:
		ordering = ("-started_at", "-id")

	def mark_finished(self, *, status: str | None = None, error: str | None = None) -> None:
		self.finished_at = timezone.now()
		if status:
			self.status = status
		if error:
			self.error_message = error
		delta = self.finished_at - self.started_at
		self.duration_ms = max(0, int(delta.total_seconds() * 1000))
		self.save(update_fields=[
			"finished_at",
			"status",
			"error_message",
			"duration_ms",
			"total_processed",
			"created_count",
			"updated_count",
			"skipped_count",
		])


class HuntFindingEnrichment(models.Model):
	class Relation(models.TextChoices):
		GENERAL = "general", "Referência"
		BLUE = "blue", "Blue-Team"
		RED = "red", "Red-Team"
		EXPLOIT = "exploit", "Exploit"

	id = models.BigAutoField(primary_key=True)
	finding = models.ForeignKey(
		HuntFinding,
		on_delete=models.CASCADE,
		related_name="enrichment_links",
	)
	enrichment = models.ForeignKey(
		"HuntEnrichment",
		on_delete=models.CASCADE,
		related_name="finding_links",
	)
	relation = models.CharField(max_length=16, choices=Relation.choices, default=Relation.GENERAL)
	linked_at = models.DateTimeField(default=timezone.now)
	last_synced_at = models.DateTimeField(default=timezone.now)

	class Meta:
		unique_together = ("finding", "enrichment")
		ordering = ("-last_synced_at", "-id")

	def touch(self, relation: str | None = None) -> None:
		if relation and relation != self.relation:
			self.relation = relation
		self.last_synced_at = timezone.now()
		self.save(update_fields=["relation", "last_synced_at"])


class HuntFindingSnapshot(models.Model):
	id = models.BigAutoField(primary_key=True)
	finding = models.ForeignKey(
		HuntFinding,
		on_delete=models.CASCADE,
		related_name="snapshots",
	)
	version = models.PositiveIntegerField()
	blue_profile = models.JSONField(default=dict, blank=True)
	red_profile = models.JSONField(default=dict, blank=True)
	enrichment_ids = models.JSONField(default=list, blank=True)
	captured_at = models.DateTimeField(default=timezone.now)

	class Meta:
		unique_together = ("finding", "version")
		ordering = ("-captured_at", "-version")


class HuntFindingState(models.Model):
	id = models.BigAutoField(primary_key=True)
	finding = models.ForeignKey(
		HuntFinding,
		on_delete=models.CASCADE,
		related_name="state_snapshots",
	)
	version = models.PositiveIntegerField()
	source_hash = models.CharField(max_length=64, blank=True, db_index=True)
	payload = models.JSONField(default=dict, blank=True)
	captured_at = models.DateTimeField(default=timezone.now)

	class Meta:
		unique_together = ("finding", "version")
		ordering = ("-captured_at", "-version")


class HuntEnrichment(models.Model):
	"""Armazena metadados externos (NVD, Vulners, Exploit-DB) para um CVE."""

	class Source(models.TextChoices):
		NVD = "nvd", "NVD"
		VULNERS = "vulners", "Vulners"
		EXPLOITDB = "exploitdb", "Exploit DB"

	class Status(models.TextChoices):
		FRESH = "fresh", "Atualizado"
		STALE = "stale", "Expirado"
		ERROR = "error", "Erro"
		SKIPPED = "skipped", "Ignorado"

	id = models.BigAutoField(primary_key=True)
	cve = models.CharField(max_length=40, db_index=True)
	source = models.CharField(max_length=16, choices=Source.choices)
	status = models.CharField(max_length=16, choices=Status.choices, default=Status.FRESH)
	payload = models.JSONField(default=dict, blank=True)
	fetched_at = models.DateTimeField(default=timezone.now)
	expires_at = models.DateTimeField(null=True, blank=True)
	error_message = models.TextField(blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		unique_together = ("cve", "source")
		indexes = [
			models.Index(fields=["source", "status"], name="idx_hunt_enrich_src_status"),
			models.Index(fields=["expires_at"], name="idx_hunt_enrich_exp"),
		]
		ordering = ("-updated_at", "-id")

	def is_expired(self, reference=None) -> bool:
		if not self.expires_at:
			return False
		ref = reference or timezone.now()
		return self.expires_at <= ref

	def mark_fresh(self, payload: dict, expires_at=None) -> None:
		self.status = self.Status.FRESH
		self.payload = payload
		self.error_message = ""
		self.fetched_at = timezone.now()
		self.expires_at = expires_at
		self.save(update_fields=[
			"status",
			"payload",
			"error_message",
			"fetched_at",
			"expires_at",
			"updated_at",
		])

	def mark_error(self, message: str, *, status: str | None = None) -> None:
		self.status = status or self.Status.ERROR
		self.error_message = message[:1000]
		self.save(update_fields=["status", "error_message", "updated_at"])

	def mark_skipped(self, message: str = "") -> None:
		self.status = self.Status.SKIPPED
		self.error_message = message[:1000]
		self.fetched_at = timezone.now()
		self.save(update_fields=["status", "error_message", "fetched_at", "updated_at"])
