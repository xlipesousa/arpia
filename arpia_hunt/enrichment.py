from __future__ import annotations

import json
import os
import subprocess
from datetime import timedelta
from importlib import import_module
from types import ModuleType
from typing import Iterable, Mapping

requests: ModuleType | None
try:
    requests = import_module("requests")
except ModuleNotFoundError:  # pragma: no cover - dependência opcional
    requests = None
from django.utils import timezone

from arpia_log.models import LogEntry

from .log_events import emit_hunt_log
from .models import HuntEnrichment, HuntFinding
from .profiles import derive_profiles


def _remote_enrichment_enabled() -> bool:
	flag = os.getenv("ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT", "0").lower()
	return flag in {"1", "true", "yes", "on"}


def _default_ttl() -> timedelta:
	value = os.getenv("ARPIA_HUNT_ENRICHMENT_TTL_HOURS", "12")
	try:
		hours = int(value)
	except ValueError:
		hours = 12
	return timedelta(hours=max(1, hours))


def enrich_cve(
	cve_id: str,
	*,
	sources: Iterable[str] | None = None,
	enable_remote: bool | None = None,
	force_refresh: bool = False,
	ttl: timedelta | None = None,
) -> dict[str, HuntEnrichment]:
	"""Garante registros de enriquecimento para um CVE nas fontes configuradas."""

	cve = cve_id.upper()
	source_list = list(sources or [
		HuntEnrichment.Source.NVD,
		HuntEnrichment.Source.VULNERS,
		HuntEnrichment.Source.EXPLOITDB,
	])
	enable_remote = _remote_enrichment_enabled() if enable_remote is None else enable_remote
	ttl_value = ttl or _default_ttl()

	results: dict[str, HuntEnrichment] = {}
	for source in source_list:
		record = _resolve_enrichment(
			cve,
			source,
			enable_remote=enable_remote,
			force_refresh=force_refresh,
			ttl=ttl_value,
		)
		results[source] = record
	return results


def _resolve_enrichment(
	cve: str,
	source: str,
	*,
	enable_remote: bool,
	force_refresh: bool,
	ttl: timedelta,
) -> HuntEnrichment:
	record, created = HuntEnrichment.objects.get_or_create(
		cve=cve,
		source=source,
		defaults={
			"status": HuntEnrichment.Status.SKIPPED if not enable_remote else HuntEnrichment.Status.STALE,
			"error_message": "Enriquecimento remoto desabilitado." if not enable_remote else "",
		},
	)

	if not enable_remote:
		if created:
			record.mark_skipped("Enriquecimento remoto desabilitado.")
		emit_hunt_log(
			event_type="hunt.enrichment.skipped",
			message="Enriquecimento remoto desativado para o CVE.",
			component="hunt.enrichment",
			details={"cve": cve, "source": source},
			tags=["pipeline:hunt-enrichment", f"source:{source}"],
		)
		return record

	if not force_refresh and not record.is_expired():
		return record

	try:
		payload, expires_at = _fetch_payload(source, cve, ttl)
		record.mark_fresh(payload, expires_at)
		emit_hunt_log(
			event_type="hunt.enrichment.completed",
			message="Enriquecimento concluído com sucesso.",
			component="hunt.enrichment",
			details={"cve": cve, "source": source, "expires_at": expires_at.isoformat() if expires_at else None},
			tags=["pipeline:hunt-enrichment", f"source:{source}", "status:success"],
		)
	except Exception as exc:  # pragma: no cover - integrações externas
		record.mark_error(str(exc))
		emit_hunt_log(
			event_type="hunt.enrichment.error",
			message="Erro ao enriquecer CVE.",
			component="hunt.enrichment",
			severity=LogEntry.Severity.ERROR,
			details={"cve": cve, "source": source, "error": str(exc)},
			tags=["pipeline:hunt-enrichment", f"source:{source}", "status:error"],
		)
	return record


def _fetch_payload(source: str, cve: str, ttl: timedelta) -> tuple[Mapping[str, object], timezone.datetime | None]:
	if source == HuntEnrichment.Source.NVD:
		payload = _fetch_nvd(cve)
	elif source == HuntEnrichment.Source.VULNERS:
		payload = _fetch_vulners(cve)
	elif source == HuntEnrichment.Source.EXPLOITDB:
		payload = _fetch_exploitdb(cve)
	else:
		raise ValueError(f"Fonte desconhecida: {source}")

	expires_at = timezone.now() + ttl if ttl else None
	return payload, expires_at


def _fetch_nvd(cve: str) -> Mapping[str, object]:
	endpoint = os.getenv("ARPIA_HUNT_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
	headers = {}
	nvd_api_key = os.getenv("ARPIA_HUNT_NVD_API_KEY") or os.getenv("NVD_API_KEY")
	if nvd_api_key:
		headers["apiKey"] = nvd_api_key
	if requests is None:
		raise RuntimeError("Biblioteca requests não está disponível para consultar a NVD.")
	response = requests.get(
		endpoint,
		params={"cveId": cve},
		headers=headers,
		timeout=float(os.getenv("ARPIA_HUNT_NVD_TIMEOUT", "12")),
	)
	response.raise_for_status()
	return response.json()


def _fetch_vulners(cve: str) -> Mapping[str, object]:
	endpoint = os.getenv("ARPIA_HUNT_VULNERS_URL", "https://vulners.com/api/v3/search/id/")
	headers = {"Content-Type": "application/json"}
	api_key = os.getenv("ARPIA_HUNT_VULNERS_API_KEY") or os.getenv("VULNERS_API_KEY")
	if api_key:
		headers["X-ApiKey"] = api_key
	if requests is None:
		raise RuntimeError("Biblioteca requests não está disponível para consultar a Vulners.")
	response = requests.get(
		endpoint,
		params={"id": cve},
		headers=headers,
		timeout=float(os.getenv("ARPIA_HUNT_VULNERS_TIMEOUT", "10")),
	)
	response.raise_for_status()
	return response.json()


def _fetch_exploitdb(cve: str) -> Mapping[str, object]:
	searchsploit_path = os.getenv("ARPIA_HUNT_SEARCHSPLOIT_PATH", "searchsploit")
	process = subprocess.run(
		[searchsploit_path, "-j", cve],
		check=True,
		capture_output=True,
		text=True,
		timeout=int(os.getenv("ARPIA_HUNT_SEARCHSPLOIT_TIMEOUT", "15")),
	)
	stdout = process.stdout.strip()
	if not stdout:
		return {"results": []}
	return json.loads(stdout)


def enrich_finding(
	finding: HuntFinding,
	*,
	enable_remote: bool | None = None,
	force_refresh: bool = False,
	ttl: timedelta | None = None,
) -> tuple[dict[str, HuntEnrichment], bool]:
	"""Sincroniza enriquecimentos para um finding e atualiza perfis Blue/Red."""
	if not finding.cve:
		emit_hunt_log(
			event_type="hunt.enrichment.skipped",
			message="Finding sem CVE associado.",
			component="hunt.enrichment",
			details={"finding_id": str(finding.pk)},
			tags=["pipeline:hunt-enrichment", "reason:missing-cve"],
		)
		return {}, False

	records = enrich_cve(
		finding.cve,
		enable_remote=enable_remote,
		force_refresh=force_refresh,
		ttl=ttl,
	)
	profile_result = derive_profiles(finding, records)
	return records, profile_result.updated


__all__ = ["enrich_cve", "enrich_finding"]
