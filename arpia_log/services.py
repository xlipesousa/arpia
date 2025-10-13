from __future__ import annotations

import secrets
from typing import Any, Dict, Iterable, Optional

from django.conf import settings
from django.utils import timezone
from rest_framework import exceptions

from .models import LogEntry
from .serializers import LogEntrySerializer


def _merge_dict(base: Optional[Dict[str, Any]], extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    merged: Dict[str, Any] = dict(base or {})
    for key, value in (extra or {}).items():
        if value is None:
            continue
        merged[key] = value
    return merged


def log_event(
    *,
    source_app: str,
    event_type: str,
    message: str,
    severity: str = LogEntry.Severity.INFO,
    timestamp: Optional[Any] = None,
    component: str = "",
    details: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    correlation: Optional[Dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
    version: int = 1,
    request=None,
    channel: str = LogEntry.Channel.INTERNAL,
) -> LogEntry:
    """Persistir um evento de log padronizado."""

    if not source_app:
        raise exceptions.ValidationError({"source_app": "Obrigatório"})
    if not event_type:
        raise exceptions.ValidationError({"event_type": "Obrigatório"})

    payload: Dict[str, Any] = {
        "version": version,
        "timestamp": timestamp or timezone.now(),
        "source_app": source_app,
        "component": component,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "details": details or {},
        "context": context or {},
        "correlation": correlation or {},
        "tags": list(tags or []),
        "ingestion_channel": channel,
    }

    if request and hasattr(request, "user") and getattr(request.user, "is_authenticated", False):
        payload["context"] = _merge_dict(payload["context"], {
            "actor": {
                "id": request.user.pk,
                "username": getattr(request.user, "username", ""),
                "email": getattr(request.user, "email", ""),
            }
        })
        payload["correlation"] = _merge_dict(payload["correlation"], {"user_id": request.user.pk})

    serializer = LogEntrySerializer(data=payload)
    serializer.is_valid(raise_exception=True)
    return serializer.save()


def log_event_from_payload(data: Dict[str, Any], *, channel: str = LogEntry.Channel.API, request=None) -> LogEntry:
    """Persistir evento já serializado vindo de API externa."""

    payload = dict(data)
    payload.setdefault("ingestion_channel", channel)

    if request and hasattr(request, "user") and getattr(request.user, "is_authenticated", False):
        context = payload.get("context") or {}
        context.setdefault("actor", {
            "id": request.user.pk,
            "username": getattr(request.user, "username", ""),
        })
        payload["context"] = context

    serializer = LogEntrySerializer(data=payload)
    serializer.is_valid(raise_exception=True)
    return serializer.save()


def validate_ingest_token(token_header: Optional[str]) -> bool:
    """Valida token de ingestão se configurado."""

    configured = getattr(settings, "ARPIA_LOG_INGEST_TOKEN", None)
    if not configured:
        return True
    if not token_header:
        return False
    parts = token_header.split()
    if len(parts) != 2 or parts[0].lower() != "token":
        return False
    provided = parts[1].strip()
    return secrets.compare_digest(provided, configured)
