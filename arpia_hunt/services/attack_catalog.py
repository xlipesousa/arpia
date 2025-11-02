from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Mapping, MutableMapping, Sequence

from django.db import transaction

from ..models import AttackTactic, AttackTechnique


logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CatalogSyncResult:
    tactics: int
    techniques: int


class CatalogImportError(RuntimeError):
    """Erro durante importação do catálogo ATT&CK."""


def _normalize_tactic(record: Mapping[str, object]) -> MutableMapping[str, object]:
    payload = dict(record)
    payload.setdefault("matrix", AttackTactic.Matrix.ENTERPRISE)
    payload.setdefault("order", 0)
    return payload


def _normalize_technique(record: Mapping[str, object]) -> MutableMapping[str, object]:
    payload = dict(record)
    payload.setdefault("is_subtechnique", False)
    payload.setdefault("platforms", [])
    payload.setdefault("datasources", [])
    payload.setdefault("external_references", [])
    payload.setdefault("version", "")
    payload.setdefault("matrix", AttackTactic.Matrix.ENTERPRISE)
    return payload


def load_catalog_from_fixture(path: Path) -> dict[str, List[MutableMapping[str, object]]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:  # pragma: no cover - validado antes dos testes
        raise CatalogImportError(f"Fixture não encontrada: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CatalogImportError(f"Fixture ATT&CK inválida: {exc}") from exc

    tactics: list[MutableMapping[str, object]] = []
    techniques: list[MutableMapping[str, object]] = []
    for entry in data:
        model_name = entry.get("model")
        pk = entry.get("pk")
        fields = dict(entry.get("fields", {}))
        fields["id"] = pk
        if model_name == "arpia_hunt.attacktactic":
            tactics.append(_normalize_tactic(fields))
        elif model_name == "arpia_hunt.attacktechnique":
            techniques.append(_normalize_technique(fields))
    return {"tactics": tactics, "techniques": techniques}


@transaction.atomic
def sync_attack_catalog(
    *,
    tactics: Sequence[Mapping[str, object]],
    techniques: Sequence[Mapping[str, object]],
) -> CatalogSyncResult:
    tactic_count = 0
    for tactic_data in tactics:
        payload = _normalize_tactic(tactic_data)
        AttackTactic.objects.update_or_create(
            id=payload["id"],
            defaults={
                "name": payload.get("name", ""),
                "short_description": payload.get("short_description", ""),
                "matrix": payload.get("matrix", AttackTactic.Matrix.ENTERPRISE),
                "order": int(payload.get("order", 0)),
            },
        )
        tactic_count += 1

    technique_count = 0
    fallback_assignments: defaultdict[str, dict[str, object]] = defaultdict(
        lambda: {"matrix": None, "techniques": []}
    )
    pending_parent_links: list[tuple[str, str]] = []
    for technique_data in techniques:
        payload = _normalize_technique(technique_data)
        matrix = str(payload.get("matrix") or AttackTactic.Matrix.ENTERPRISE)
        tactic_id = payload.get("tactic") or payload.get("tactic_id")
        if tactic_id is None:
            technique_id = str(payload.get("id"))
            fallback_tactic_id, matrix_choice = _ensure_fallback_tactic(matrix)
            tactic_id = fallback_tactic_id
            payload["tactic"] = tactic_id
            info = fallback_assignments[tactic_id]
            if info["matrix"] is None:
                info["matrix"] = matrix_choice
            info["techniques"].append(technique_id)

        defaults = {
            "name": payload.get("name", ""),
            "description": payload.get("description", ""),
            "is_subtechnique": bool(payload.get("is_subtechnique", False)),
            "tactic_id": tactic_id,
            "platforms": list(payload.get("platforms", [])),
            "datasources": list(payload.get("datasources", [])),
            "external_references": list(payload.get("external_references", [])),
            "version": payload.get("version", ""),
        }
        parent_external = payload.get("parent") or payload.get("parent_id")
        if parent_external:
            parent_id = str(parent_external)
            if AttackTechnique.objects.filter(id=parent_id).exists():
                defaults["parent_id"] = parent_id
            else:
                pending_parent_links.append((str(payload["id"]), parent_id))
        AttackTechnique.objects.update_or_create(
            id=payload["id"],
            defaults=defaults,
        )
        technique_count += 1

    for technique_id, parent_id in pending_parent_links:
        if AttackTechnique.objects.filter(id=parent_id).exists():
            AttackTechnique.objects.filter(id=technique_id).update(parent_id=parent_id)
        else:
            raise CatalogImportError(f"Técnica {technique_id} referencia parent inexistente {parent_id}.")

    if fallback_assignments:
        for tactic_id, info in fallback_assignments.items():
            matrix_choice = info["matrix"]
            matrix_label = getattr(matrix_choice, "label", str(matrix_choice))
            matrix_value = getattr(matrix_choice, "value", str(matrix_choice))
            logger.warning(
                "Atribuí %s técnicas à tática sintética %s (%s/%s): %s",
                len(info["techniques"]),
                tactic_id,
                matrix_value,
                matrix_label,
                ", ".join(sorted(info["techniques"])),
            )

    return CatalogSyncResult(tactics=tactic_count, techniques=technique_count)


_FALLBACK_TACTIC_MAP: dict[AttackTactic.Matrix, dict[str, object]] = {
    AttackTactic.Matrix.ENTERPRISE: {
        "id": "ENT-UNASSIGNED",
        "name": "Sem tática definida (Enterprise)",
        "order": 999,
    },
    AttackTactic.Matrix.MOBILE: {
        "id": "MOB-UNASSIGNED",
        "name": "Sem tática definida (Mobile)",
        "order": 999,
    },
    AttackTactic.Matrix.ICS: {
        "id": "ICS-UNASSIGNED",
        "name": "Sem tática definida (ICS)",
        "order": 999,
    },
}

_FALLBACK_CACHE: set[str] = set()


def _ensure_fallback_tactic(matrix: str) -> tuple[str, AttackTactic.Matrix]:
    try:
        matrix_choice = AttackTactic.Matrix(matrix)
    except ValueError:
        matrix_choice = AttackTactic.Matrix.ENTERPRISE

    definition = _FALLBACK_TACTIC_MAP.get(matrix_choice, _FALLBACK_TACTIC_MAP[AttackTactic.Matrix.ENTERPRISE])
    tactic_id = str(definition["id"])

    if tactic_id not in _FALLBACK_CACHE:
        AttackTactic.objects.update_or_create(
            id=tactic_id,
            defaults={
                "name": str(definition["name"]),
                "short_description": "Gerada automaticamente para técnicas sem tática oficial.",
                "matrix": matrix_choice,
                "order": int(definition["order"]),
            },
        )
        _FALLBACK_CACHE.add(tactic_id)

    return tactic_id, matrix_choice


def load_from_pyattck(matrix: str = AttackTactic.Matrix.ENTERPRISE) -> dict[str, List[MutableMapping[str, object]]]:
    try:
        from pyattck import Attck
    except ImportError as exc:  # pragma: no cover - dependência opcional
        raise CatalogImportError("pyattck não está instalado. Adicione-o às dependências.") from exc

    try:
        attack = Attck()
    except TypeError:
        attack = Attck(load_remote=True)

    if matrix == AttackTactic.Matrix.ENTERPRISE:
        attack_matrix = attack.enterprise
    elif matrix == AttackTactic.Matrix.ICS:
        attack_matrix = attack.ics
    elif matrix == AttackTactic.Matrix.MOBILE:
        attack_matrix = attack.mobile
    else:  # pragma: no cover - matriz já validada externamente
        raise CatalogImportError(f"Matriz ATT&CK desconhecida: {matrix}")

    tactics: list[MutableMapping[str, object]] = []
    for tactic in attack_matrix.tactics:
        tactic_refs = _normalize_external_references(getattr(tactic, "external_references", []))
        external_id = _extract_external_id(tactic_refs)
        tactics.append(
            _normalize_tactic(
                {
                    "id": external_id,
                    "name": tactic.name,
                    "short_description": getattr(tactic, "short_description", ""),
                    "matrix": matrix,
                    "order": getattr(tactic, "matrix_position", 0) or 0,
                }
            )
        )

    techniques: list[MutableMapping[str, object]] = []
    for technique in attack_matrix.techniques:
        technique_refs = _normalize_external_references(getattr(technique, "external_references", []))
        external_id = _extract_external_id(technique_refs)
        tactic_ids = []
        for tactic in getattr(technique, "tactics", []):
            tactic_refs = _normalize_external_references(getattr(tactic, "external_references", []))
            tactic_external_id = _extract_external_id(tactic_refs)
            if tactic_external_id:
                tactic_ids.append(tactic_external_id)
        tactic_id = tactic_ids[0] if tactic_ids else None
        parent_external = None
        parent = getattr(technique, "parent", None)
        if parent is not None:
            parent_refs = _normalize_external_references(getattr(parent, "external_references", []))
            parent_external = _extract_external_id(parent_refs)

        techniques.append(
            _normalize_technique(
                {
                    "id": external_id,
                    "name": technique.name,
                    "description": getattr(technique, "description", ""),
                    "is_subtechnique": bool(getattr(technique, "is_subtechnique", False)),
                    "parent": parent_external,
                    "tactic": tactic_id,
                    "platforms": list(getattr(technique, "platforms", [])),
                    "datasources": list(getattr(technique, "datasources", [])),
                    "external_references": technique_refs,
                    "version": str(getattr(technique, "version", "")),
                    "matrix": matrix,
                }
            )
        )

    return {"tactics": tactics, "techniques": techniques}


def merge_catalogs(
    *datasets: Mapping[str, Iterable[Mapping[str, object]]]
) -> dict[str, list[MutableMapping[str, object]]]:
    tactic_map: dict[str, MutableMapping[str, object]] = {}
    technique_map: dict[str, MutableMapping[str, object]] = {}

    for dataset in datasets:
        for tactic in dataset.get("tactics", []) or []:
            tactic_id = tactic.get("id")
            if tactic_id is None:
                continue
            tactic_map[str(tactic_id)] = dict(tactic)
        for technique in dataset.get("techniques", []) or []:
            technique_id = technique.get("id")
            if technique_id is None:
                continue
            technique_map[str(technique_id)] = dict(technique)

    return {
        "tactics": list(tactic_map.values()),
        "techniques": list(technique_map.values()),
    }


def _normalize_external_references(references: Iterable[Any]) -> list[MutableMapping[str, object]]:
    normalized: list[MutableMapping[str, object]] = []
    for reference in references or []:
        if isinstance(reference, Mapping):
            normalized.append(dict(reference))
            continue

        data: dict[str, object] = {}
        external_id = getattr(reference, "external_id", None) or getattr(reference, "externalId", None)
        if external_id:
            data["external_id"] = external_id

        for attr in ("source_name", "url", "description"):
            value = getattr(reference, attr, None)
            if value:
                data[attr] = value

        if not data and hasattr(reference, "__dict__"):
            for key, value in reference.__dict__.items():
                if key in {"external_id", "source_name", "url", "description"} and value is not None:
                    data[key] = value

        if not data:
            data["value"] = str(reference)

        normalized.append(data)

    return normalized


def _extract_external_id(references: Iterable[Mapping[str, object]]) -> str | None:
    for ref in references or []:
        external_id = ref.get("external_id")
        if external_id:
            return str(external_id)
    return None


__all__ = [
    "CatalogImportError",
    "CatalogSyncResult",
    "load_catalog_from_fixture",
    "load_from_pyattck",
    "merge_catalogs",
    "sync_attack_catalog",
]
