from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Mapping, MutableMapping, Sequence

from django.db import transaction

from ..models import AttackTactic, AttackTechnique


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
    pending_parent_links: list[tuple[str, str]] = []
    for technique_data in techniques:
        payload = _normalize_technique(technique_data)
        tactic_id = payload.get("tactic") or payload.get("tactic_id")
        if tactic_id is None:
            raise CatalogImportError(f"Técnica {payload.get('id')} sem tática associada.")

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

    return CatalogSyncResult(tactics=tactic_count, techniques=technique_count)


def load_from_pyattck(matrix: str = AttackTactic.Matrix.ENTERPRISE) -> dict[str, List[MutableMapping[str, object]]]:
    try:
        from pyattck import Attck
    except ImportError as exc:  # pragma: no cover - dependência opcional
        raise CatalogImportError("pyattck não está instalado. Adicione-o às dependências.") from exc

    attack = Attck(load_only=matrix)
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
        external_id = _extract_external_id(tactic.external_references)
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
        external_id = _extract_external_id(technique.external_references)
        tactic_ids = [
            _extract_external_id(t.external_references)
            for t in getattr(technique, "tactics", [])
            if _extract_external_id(t.external_references)
        ]
        tactic_id = tactic_ids[0] if tactic_ids else None
        parent_external = None
        parent = getattr(technique, "parent", None)
        if parent is not None:
            parent_external = _extract_external_id(parent.external_references)

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
                    "external_references": list(getattr(technique, "external_references", [])),
                    "version": str(getattr(technique, "version", "")),
                }
            )
        )

    return {"tactics": tactics, "techniques": techniques}


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
    "sync_attack_catalog",
]
