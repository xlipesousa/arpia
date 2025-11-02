from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, MutableMapping, Optional, Set, Tuple

from django.db import transaction

from ..models import (
    CveAttackTechnique,
    HuntEnrichment,
    HuntFinding,
    HuntRecommendation,
)


@dataclass(slots=True)
class RecommendationSyncResult:
    created: int = 0
    updated: int = 0
    deleted: int = 0

    @property
    def changed(self) -> bool:
        return any((self.created, self.updated, self.deleted))


def _pick_enrichment(record_map: Mapping[str, HuntEnrichment], *sources: str) -> Optional[HuntEnrichment]:
    for src in sources:
        record = record_map.get(src)
        if record is not None:
            return record
    return None


def _build_blue_payload(mapping: CveAttackTechnique) -> MutableMapping[str, object]:
    technique = mapping.technique
    tactic = technique.tactic
    title = f"Mitigar {technique.name}"[:160]
    rationale = mapping.rationale.strip() if mapping.rationale else ""
    summary_parts = [
        f"Aplicar controles alinhados à tática {tactic.id} ({tactic.name}) para reduzir {technique.name}.",
    ]
    if rationale:
        summary_parts.append(rationale)
    summary = " ".join(summary_parts)
    tags = ["mitigation", f"tactic:{tactic.id}", f"technique:{technique.id}"]
    evidence = {
        "cve": mapping.cve,
        "technique_id": technique.id,
        "tactic_id": tactic.id,
        "source": mapping.source,
        "confidence": mapping.confidence,
    }
    return {
        "title": title,
        "summary": summary,
        "tags": tags,
        "evidence": evidence,
    }


def _build_red_payload(mapping: CveAttackTechnique) -> MutableMapping[str, object]:
    technique = mapping.technique
    tactic = technique.tactic
    title = f"Simular {technique.name}"[:160]
    rationale = mapping.rationale.strip() if mapping.rationale else ""
    summary_parts = [
        f"Planejar exercício para técnica {technique.id} ({technique.name}) na tática {tactic.id} ({tactic.name}).",
        "Validar detecções e playbooks existentes.",
    ]
    if rationale:
        summary_parts.append(rationale)
    summary = " ".join(summary_parts)
    tags = ["simulation", f"tactic:{tactic.id}", f"technique:{technique.id}"]
    evidence = {
        "cve": mapping.cve,
        "technique_id": technique.id,
        "tactic_id": tactic.id,
        "source": mapping.source,
        "confidence": mapping.confidence,
    }
    return {
        "title": title,
        "summary": summary,
        "tags": tags,
        "evidence": evidence,
    }


@transaction.atomic
def sync_recommendations_for_finding(
    finding: HuntFinding,
    records: Mapping[str, HuntEnrichment] | None = None,
) -> RecommendationSyncResult:
    result = RecommendationSyncResult()
    records = records or {}

    if not finding.cve:
        deleted = finding.recommendations.filter(
            generated_by=HuntRecommendation.Generator.AUTOMATION
        ).delete()[0]
        result.deleted += deleted
        return result

    mappings = list(
        CveAttackTechnique.objects.filter(cve=finding.cve.upper())
        .select_related("technique", "technique__tactic")
        .order_by("technique_id")
    )

    existing: dict[Tuple[str | None, str], HuntRecommendation] = {
        (rec.technique_id, rec.recommendation_type): rec
        for rec in finding.recommendations.filter(
            generated_by=HuntRecommendation.Generator.AUTOMATION
        ).select_related("technique")
    }
    desired_keys: Set[Tuple[str | None, str]] = set()

    nvd_record = _pick_enrichment(records, HuntEnrichment.Source.NVD)
    offensive_record = _pick_enrichment(
        records,
        HuntEnrichment.Source.VULNERS,
        HuntEnrichment.Source.EXPLOITDB,
    )

    for mapping in mappings:
        technique = mapping.technique

        # Blue recommendation
        blue_payload = _build_blue_payload(mapping)
        blue_key = (technique.id, HuntRecommendation.Type.BLUE)
        desired_keys.add(blue_key)
        blue_rec = existing.get(blue_key)
        created_blue = False
        if blue_rec is None:
            blue_rec = HuntRecommendation(
                finding=finding,
                technique=technique,
                recommendation_type=HuntRecommendation.Type.BLUE,
                generated_by=HuntRecommendation.Generator.AUTOMATION,
            )
            created_blue = True

        changed = _apply_payload(
            blue_rec,
            blue_payload,
            nvd_record if nvd_record and nvd_record.cve == finding.cve else None,
            mapping.confidence,
        )
        if created_blue:
            blue_rec.save()
            result.created += 1
        elif changed:
            blue_rec.save()
            result.updated += 1
        existing[blue_key] = blue_rec

        # Red recommendation
        red_payload = _build_red_payload(mapping)
        red_key = (technique.id, HuntRecommendation.Type.RED)
        desired_keys.add(red_key)
        red_rec = existing.get(red_key)
        created_red = False
        if red_rec is None:
            red_rec = HuntRecommendation(
                finding=finding,
                technique=technique,
                recommendation_type=HuntRecommendation.Type.RED,
                generated_by=HuntRecommendation.Generator.AUTOMATION,
            )
            created_red = True

        changed = _apply_payload(
            red_rec,
            red_payload,
            offensive_record if offensive_record and offensive_record.cve == finding.cve else None,
            mapping.confidence,
        )
        if created_red:
            red_rec.save()
            result.created += 1
        elif changed:
            red_rec.save()
            result.updated += 1
        existing[red_key] = red_rec

    for key, rec in list(existing.items()):
        if key not in desired_keys:
            rec.delete()
            result.deleted += 1

    return result


def _apply_payload(
    recommendation: HuntRecommendation,
    payload: Mapping[str, object],
    enrichment: Optional[HuntEnrichment],
    confidence: str,
) -> bool:
    updated = False
    if recommendation.title != payload["title"]:
        recommendation.title = payload["title"]
        updated = True
    if recommendation.summary != payload["summary"]:
        recommendation.summary = payload["summary"]
        updated = True
    tags = list(payload["tags"])
    if recommendation.tags != tags:
        recommendation.tags = tags  # type: ignore[arg-type]
        updated = True
    evidence = payload["evidence"]
    if recommendation.evidence != evidence:
        recommendation.evidence = evidence  # type: ignore[arg-type]
        updated = True
    if recommendation.confidence != confidence:
        recommendation.confidence = confidence
        updated = True
    if recommendation.generated_by != HuntRecommendation.Generator.AUTOMATION:
        recommendation.generated_by = HuntRecommendation.Generator.AUTOMATION
        updated = True
    enrichment_id = enrichment.pk if enrichment else None
    if recommendation.source_enrichment_id != enrichment_id:
        recommendation.source_enrichment = enrichment
        updated = True
    return updated


__all__ = [
    "RecommendationSyncResult",
    "sync_recommendations_for_finding",
]
