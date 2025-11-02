from __future__ import annotations

from typing import Any

from django.utils import timezone

from arpia_log.models import LogEntry


def emit_hunt_log(
    *,
    event_type: str,
    message: str,
    severity: str | None = None,
    component: str = "hunt",
    project_ref: str | None = None,
    details: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> LogEntry:
    """Registra um evento do módulo Hunt no agregador central de logs."""

    severity_value = severity or LogEntry.Severity.INFO

    entry = LogEntry.objects.create(
        timestamp=timezone.now(),
        source_app="arpia_hunt",
        component=component,
        event_type=event_type,
        severity=severity_value,
        message=message[:512],
        details=details or {},
        context=context or {},
        tags=tags or [],
        project_ref=project_ref or "",
        ingestion_channel=LogEntry.Channel.INTERNAL,
    )
    return entry


__all__ = ["emit_hunt_log"]
