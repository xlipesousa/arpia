from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional

from django.db import transaction

from ..models import (
    AttackTechnique,
    CveAttackTechnique,
    HuntEnrichment,
    HuntFinding,
)

logger = logging.getLogger(__name__)


_CONFIDENCE_ORDER: dict[str, int] = {
    CveAttackTechnique.Confidence.HIGH: 3,
    CveAttackTechnique.Confidence.MEDIUM: 2,
    CveAttackTechnique.Confidence.LOW: 1,
}


@dataclass(slots=True)
class HeuristicRule:
    technique_id: str
    confidence: str
    keywords: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    rationale: str = ""

    def matches(self, *, corpus: str, cwes: set[str]) -> bool:
        if self.keywords:
            if not all(keyword in corpus for keyword in self.keywords):
                return False
        if self.cwes:
            if not any(cwe in cwes for cwe in self.cwes):
                return False
        return bool(self.keywords or self.cwes)


@dataclass(slots=True)
class HeuristicMatch:
    technique_id: str
    confidence: str
    rationale: str


@dataclass(slots=True)
class HeuristicSyncResult:
    created: int = 0
    updated: int = 0
    deleted: int = 0

    @property
    def changed(self) -> bool:
        return any((self.created, self.updated, self.deleted))


_KEYWORD_RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        technique_id="T1190",
        confidence=CveAttackTechnique.Confidence.HIGH,
        keywords=("remote code execution", "public"),
        rationale="Descrição menciona Remote Code Execution em superfície pública, sugerindo exploração web.",
    ),
    HeuristicRule(
        technique_id="T1059",
        confidence=CveAttackTechnique.Confidence.MEDIUM,
        keywords=("command execution", "script"),
        rationale="Descrição referencia execução de comandos/scripts, alinhado à técnica Command and Scripting Interpreter.",
    ),
    HeuristicRule(
        technique_id="T1548",
        confidence=CveAttackTechnique.Confidence.MEDIUM,
        keywords=("privilege escalation",),
        rationale="Descrição aponta elevação de privilégio local, relacionada à técnica Abuse Elevation Control Mechanism.",
    ),
)

_CWE_RULES: tuple[HeuristicRule, ...] = (
    HeuristicRule(
        technique_id="T1190",
        confidence=CveAttackTechnique.Confidence.MEDIUM,
        cwes=("CWE-79", "CWE-89", "CWE-352"),
        rationale="CWE associado a exploração de aplicações expostas (injeções/falhas de sessão).",
    ),
    HeuristicRule(
        technique_id="T1203",
        confidence=CveAttackTechnique.Confidence.MEDIUM,
        cwes=("CWE-94", "CWE-119"),
        rationale="CWE aponta falhas de execução de código/estouro de memória, alinhando-se a Exploitação do Cliente.",
    ),
)

_ALL_RULES: tuple[HeuristicRule, ...] = _KEYWORD_RULES + _CWE_RULES


def _extract_text_corpus(*, finding: Optional[HuntFinding], records: Mapping[str, HuntEnrichment]) -> str:
    parts: list[str] = []
    if finding and finding.summary:
        parts.append(finding.summary.lower())
    if finding and finding.vulnerability and finding.vulnerability.summary:
        parts.append(finding.vulnerability.summary.lower())

    nvd = records.get(HuntEnrichment.Source.NVD) if records else None
    if nvd and nvd.payload:
        vulnerabilities = nvd.payload.get("vulnerabilities", []) or []
        for entry in vulnerabilities:
            descriptions = entry.get("cve", {}).get("descriptions", []) or []
            for desc in descriptions:
                value = desc.get("value")
                if value:
                    parts.append(str(value).lower())

    vulners = records.get(HuntEnrichment.Source.VULNERS) if records else None
    if vulners and vulners.payload:
        for document in vulners.payload.get("data", {}).get("documents", []) or []:
            summary = document.get("title") or document.get("description")
            if summary:
                parts.append(str(summary).lower())

    exploitdb = records.get(HuntEnrichment.Source.EXPLOITDB) if records else None
    if exploitdb and exploitdb.payload:
        for item in exploitdb.payload.get("RESULTS_EXPLOIT", []) or []:
            title = item.get("title")
            description = item.get("description")
            if title:
                parts.append(str(title).lower())
            if description:
                parts.append(str(description).lower())

    return " ".join(parts)


def _extract_cwes(records: Mapping[str, HuntEnrichment]) -> set[str]:
    cwes: set[str] = set()
    nvd = records.get(HuntEnrichment.Source.NVD) if records else None
    if nvd and nvd.payload:
        for entry in nvd.payload.get("vulnerabilities", []) or []:
            weaknesses = entry.get("cve", {}).get("weaknesses", []) or []
            for weakness in weaknesses:
                descriptions = weakness.get("description", []) or []
                for desc in descriptions:
                    value = desc.get("value")
                    if value:
                        cwes.add(str(value).upper())
    return cwes


def _merge_matches(matches: Iterable[HeuristicMatch]) -> dict[str, HeuristicMatch]:
    merged: dict[str, HeuristicMatch] = {}
    for match in matches:
        existing = merged.get(match.technique_id)
        if existing is None:
            merged[match.technique_id] = match
            continue
        if _CONFIDENCE_ORDER[match.confidence] > _CONFIDENCE_ORDER[existing.confidence]:
            merged[match.technique_id] = match
    return merged


def evaluate_heuristics(
    *,
    cve: str,
    finding: Optional[HuntFinding] = None,
    records: Mapping[str, HuntEnrichment] | None = None,
) -> dict[str, HeuristicMatch]:
    records = records or {}
    corpus = _extract_text_corpus(finding=finding, records=records)
    cwe_values = _extract_cwes(records)

    matches: list[HeuristicMatch] = []
    if not corpus and not cwe_values:
        return {}

    for rule in _ALL_RULES:
        if rule.matches(corpus=corpus, cwes=cwe_values):
            matches.append(
                HeuristicMatch(
                    technique_id=rule.technique_id,
                    confidence=rule.confidence,
                    rationale=rule.rationale,
                )
            )

    return _merge_matches(matches)


@transaction.atomic
def sync_heuristic_mappings(
    *,
    cve: str,
    finding: Optional[HuntFinding] = None,
    records: Mapping[str, HuntEnrichment] | None = None,
) -> HeuristicSyncResult:
    cve_normalized = cve.upper()
    records = records or {}
    result = HeuristicSyncResult()

    matches = evaluate_heuristics(cve=cve_normalized, finding=finding, records=records)
    if not matches:
        deleted = CveAttackTechnique.objects.filter(
            cve=cve_normalized,
            source=CveAttackTechnique.Source.HEURISTIC,
        ).delete()[0]
        if deleted:
            result.deleted += deleted
            logger.info("Removi %s vínculos heurísticos para %s", deleted, cve_normalized)
        return result

    existing = {
        item.technique_id: item
        for item in CveAttackTechnique.objects.filter(
            cve=cve_normalized,
            source=CveAttackTechnique.Source.HEURISTIC,
        ).select_related("technique")
    }

    processed: set[str] = set()

    for technique_id, match in matches.items():
        try:
            technique = AttackTechnique.objects.get(pk=technique_id)
        except AttackTechnique.DoesNotExist:
            logger.warning(
                "Técnica %s não encontrada durante heurística para %s. Ignorando.",
                technique_id,
                cve_normalized,
            )
            continue

        processed.add(technique_id)

        existing_mapping = existing.get(technique_id)
        if existing_mapping is None:
            CveAttackTechnique.objects.create(
                cve=cve_normalized,
                technique=technique,
                source=CveAttackTechnique.Source.HEURISTIC,
                confidence=match.confidence,
                rationale=match.rationale,
            )
            result.created += 1
            continue

        changed = False
        if existing_mapping.confidence != match.confidence:
            existing_mapping.confidence = match.confidence
            changed = True
        if existing_mapping.rationale != match.rationale:
            existing_mapping.rationale = match.rationale
            changed = True

        if changed:
            existing_mapping.save(update_fields=["confidence", "rationale", "updated_at"])
            result.updated += 1

    to_delete = [tech_id for tech_id in existing.keys() if tech_id not in processed]
    if to_delete:
        deleted = CveAttackTechnique.objects.filter(
            cve=cve_normalized,
            source=CveAttackTechnique.Source.HEURISTIC,
            technique_id__in=to_delete,
        ).delete()[0]
        if deleted:
            result.deleted += deleted
            logger.info(
                "Removi %s vínculos heurísticos obsoletos para %s (%s)",
                deleted,
                cve_normalized,
                ", ".join(to_delete),
            )

    return result


__all__ = [
    "HeuristicMatch",
    "HeuristicSyncResult",
    "evaluate_heuristics",
    "sync_heuristic_mappings",
]
