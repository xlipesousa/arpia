from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from django.utils import timezone

from arpia_log.models import LogEntry

from .log_events import emit_hunt_log
from .models import (
    HuntEnrichment,
    HuntFinding,
    HuntFindingEnrichment,
)


@dataclass
class ProfileResult:
    updated: bool
    blue_profile: dict
    red_profile: dict
    enrichment_ids: list[str]


def derive_profiles(finding: HuntFinding, records: Dict[str, HuntEnrichment]) -> ProfileResult:
    blue_profile = _build_blue_profile(finding, records)
    red_profile = _build_red_profile(records)
    enrichment_ids = [str(record.pk) for record in records.values()]
    updated = finding.apply_profiles(
        blue_profile=blue_profile,
        red_profile=red_profile,
        enrichment_ids=enrichment_ids,
    )
    _sync_links(finding, records.values())
    if updated:
        emit_hunt_log(
            event_type="hunt.profile.updated",
            message="Perfis Blue/Red atualizados para o finding.",
            component="hunt.profile",
            details={
                "finding_id": str(finding.pk),
                "cve": finding.cve,
                "version": finding.profile_version,
            },
            tags=[
                "pipeline:hunt-profile",
                f"project:{finding.project_id}",
                *(f"enrichment:{record.pk}" for record in records.values()),
            ],
        )
    return ProfileResult(
        updated=updated,
        blue_profile=blue_profile,
        red_profile=red_profile,
        enrichment_ids=enrichment_ids,
    )


def _build_blue_profile(finding: HuntFinding, records: Dict[str, HuntEnrichment]) -> dict:
    nvd = records.get(HuntEnrichment.Source.NVD)
    summary = finding.summary or finding.vulnerability.summary
    cvss_data = {}
    references: list[str] = []

    if nvd and nvd.payload:
        metrics = _extract_nested(nvd.payload, ["vulnerabilities", 0, "cve", "metrics"])
        if metrics:
            cvss_data = metrics
        references = _extract_reference_urls(nvd.payload)

    return {
        "summary": summary,
        "severity": finding.severity,
        "cvss": cvss_data,
        "references": references,
        "updated_at": timezone.now().isoformat(),
    }


def _build_red_profile(records: Dict[str, HuntEnrichment]) -> dict:
    exploits: list[dict] = []
    vulners = records.get(HuntEnrichment.Source.VULNERS)
    exploitdb = records.get(HuntEnrichment.Source.EXPLOITDB)

    if vulners and vulners.payload:
        exploits.extend(
            {
                "source": "vulners",
                "id": item.get("id"),
                "title": item.get("title"),
                "score": item.get("cvss"),
                "url": item.get("href") or item.get("url"),
            }
            for item in vulners.payload.get("data", {}).get("documents", [])
        )

    if exploitdb and exploitdb.payload:
        for item in exploitdb.payload.get("RESULTS_EXPLOIT", []) or []:
            exploits.append(
                {
                    "source": "exploitdb",
                    "title": item.get("title"),
                    "path": item.get("path"),
                    "author": item.get("author"),
                    "type": item.get("type"),
                }
            )

    return {
        "exploits": exploits,
        "updated_at": timezone.now().isoformat(),
    }


def _sync_links(finding: HuntFinding, records: Iterable[HuntEnrichment]) -> None:
    for record in records:
        link, _created = HuntFindingEnrichment.objects.get_or_create(
            finding=finding,
            enrichment=record,
            defaults={
                "relation": _relation_for_source(record.source),
            },
        )
        link.touch(relation=_relation_for_source(record.source))


def _relation_for_source(source: str) -> str:
    if source == HuntEnrichment.Source.NVD:
        return HuntFindingEnrichment.Relation.BLUE
    if source == HuntEnrichment.Source.VULNERS:
        return HuntFindingEnrichment.Relation.RED
    if source == HuntEnrichment.Source.EXPLOITDB:
        return HuntFindingEnrichment.Relation.EXPLOIT
    return HuntFindingEnrichment.Relation.GENERAL


def _extract_nested(payload: dict, path: list) -> dict:
    current = payload
    for key in path:
        if isinstance(key, int):
            if isinstance(current, list) and len(current) > key:
                current = current[key]
            else:
                return {}
        else:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return {}
    return current if isinstance(current, dict) else {}


def _extract_reference_urls(payload: dict) -> list[str]:
    if not isinstance(payload, dict):
        return []

    references: list[str] = []
    seen: set[str] = set()
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        return references

    for entry in vulnerabilities:
        if isinstance(entry, dict):
            cve_data = entry.get("cve")
            candidates = cve_data if isinstance(cve_data, list) else [cve_data]
        elif isinstance(entry, list):
            candidates = entry
        else:
            continue

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            references_block = candidate.get("references")
            if isinstance(references_block, dict):
                reference_data = references_block.get("reference_data", [])
            elif isinstance(references_block, list):
                reference_data = references_block
            else:
                reference_data = []

            for ref in reference_data:
                if isinstance(ref, dict):
                    url = ref.get("url") or ref.get("href")
                elif isinstance(ref, str):
                    url = ref
                else:
                    url = None
                if url and url not in seen:
                    seen.add(url)
                    references.append(url)

    return references


__all__ = ["derive_profiles", "ProfileResult"]
