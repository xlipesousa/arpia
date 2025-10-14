"""Helpers para registrar eventos de projetos no arpia_log."""
from __future__ import annotations

import datetime as _dt
import uuid
from decimal import Decimal
from typing import Any, Dict, Iterable, Optional

from django.utils import timezone

from arpia_log.models import LogEntry
from arpia_log.services import log_event


def _serialize_value(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _serialize_value(val) for key, val in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize_value(item) for item in value]
    if isinstance(value, _dt.datetime):
        if timezone.is_naive(value):
            value = timezone.make_aware(value, timezone.get_current_timezone())
        return value.isoformat()
    if isinstance(value, _dt.date):
        return value.isoformat()
    if isinstance(value, _dt.time):
        return value.isoformat()
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:  # pragma: no cover - fallback em caso de objeto inesperado
            pass
    if hasattr(value, "pk"):
        return getattr(value, "pk")
    return str(value)


def _merge_details(base: Dict[str, Any], extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in (extra or {}).items():
        merged[key] = _serialize_value(value)
    return merged


def log_project_event(
    project,
    *,
    event_type: str,
    message: str,
    request=None,
    severity: str = LogEntry.Severity.INFO,
    details: Optional[Dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
) -> LogEntry:
    base_details: Dict[str, Any] = {
        "project_id": _serialize_value(project.pk),
        "project_slug": project.slug,
        "project_name": project.name,
        "owner_id": getattr(project.owner, "pk", None),
        "owner_username": getattr(project.owner, "username", None),
    }
    payload_details = _merge_details(base_details, details)

    context = {
        "owner": {
            "id": getattr(project.owner, "pk", None),
            "username": getattr(project.owner, "username", ""),
            "email": getattr(project.owner, "email", ""),
        }
    }

    return log_event(
        source_app="arpia_project",
        component="project_service",
        event_type=event_type,
        message=message,
        severity=severity,
        details=payload_details,
        context=context,
        tags=list(tags or ["project"]),
        request=request,
    )


def log_project_created(project, *, request=None) -> LogEntry:
    return log_project_event(
        project,
        event_type="PROJECT_CREATED",
        message=f"Projeto '{project.name}' criado.",
        request=request,
        tags=["project", "crud", "create"],
    )


def log_project_updated(project, *, changes: Dict[str, Any], request=None) -> Optional[LogEntry]:
    if not changes:
        return None
    normalized = {
        field: {
            "from": _serialize_value(values[0]),
            "to": _serialize_value(values[1]),
        }
        for field, values in changes.items()
    }
    return log_project_event(
        project,
        event_type="PROJECT_UPDATED",
        message=f"Projeto '{project.name}' atualizado.",
        request=request,
        details={"changes": normalized},
        tags=["project", "crud", "update"],
    )


def log_project_deleted(project, *, request=None, extra: Optional[Dict[str, Any]] = None) -> LogEntry:
    return log_project_event(
        project,
        event_type="PROJECT_DELETED",
        message=f"Projeto '{project.name}' removido.",
        request=request,
        severity=LogEntry.Severity.NOTICE,
        details=_merge_details({"status": project.status}, extra),
        tags=["project", "crud", "delete"],
    )


def log_project_member_added(project, membership, *, request=None) -> LogEntry:
    return log_project_event(
        project,
        event_type="PROJECT_MEMBER_ADDED",
        message=f"Usuário '{membership.user.username}' recebeu acesso ao projeto.",
        request=request,
        details={
            "membership_id": membership.pk,
            "member_id": membership.user_id,
            "member_username": getattr(membership.user, "username", None),
            "role": membership.role,
        },
        tags=["project", "share", "create"],
    )


def log_project_member_updated(project, membership, *, previous_role: str, request=None) -> LogEntry:
    return log_project_event(
        project,
        event_type="PROJECT_MEMBER_UPDATED",
        message=f"Permissões de '{membership.user.username}' atualizadas.",
        request=request,
        details={
            "membership_id": membership.pk,
            "member_id": membership.user_id,
            "member_username": getattr(membership.user, "username", None),
            "role": {
                "from": previous_role,
                "to": membership.role,
            },
        },
        tags=["project", "share", "update"],
    )


def log_project_member_removed(project, membership, *, request=None) -> LogEntry:
    return log_project_event(
        project,
        event_type="PROJECT_MEMBER_REMOVED",
        message=f"Acesso de '{membership.user.username}' ao projeto foi revogado.",
        request=request,
        details={
            "membership_id": membership.pk,
            "member_id": membership.user_id,
            "member_username": getattr(membership.user, "username", None),
            "role": membership.role,
        },
        tags=["project", "share", "delete"],
    )
