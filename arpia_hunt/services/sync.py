from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable, Optional, Sequence

from arpia_core.models import Project
from arpia_log.models import LogEntry
from arpia_vuln.models import VulnerabilityFinding

from ..log_events import emit_hunt_log
from ..models import HuntFinding, HuntSyncLog

logger = logging.getLogger(__name__)


@dataclass
class SyncResult:
    total: int = 0
    created: int = 0
    updated: int = 0
    skipped: int = 0
    log_entry: Optional[HuntSyncLog] = None
    audit_log_id: Optional[int] = None

    def as_dict(self) -> dict[str, int]:
        return {
            "total": self.total,
            "created": self.created,
            "updated": self.updated,
            "skipped": self.skipped,
        }


def _build_tags(vuln: VulnerabilityFinding) -> list[str]:
    items: list[str] = [f"severity:{vuln.severity}"]
    if vuln.cve:
        items.append(f"cve:{vuln.cve.lower()}")
    if vuln.status:
        items.append(f"status:{vuln.status}")
    if vuln.service:
        items.append(f"service:{vuln.service.lower()}")
    if vuln.host:
        items.append(f"host:{vuln.host.lower()}")
    return items


def _build_context(vuln: VulnerabilityFinding) -> dict:
    return {
        "vulnerability": {
            "id": str(vuln.pk),
            "title": vuln.title,
            "summary": vuln.summary,
            "data": vuln.data or {},
            "session_id": str(vuln.session_id),
            "source_task_id": vuln.source_task_id,
        },
        "host": {
            "name": vuln.host,
            "service": vuln.service,
            "port": vuln.port,
            "protocol": vuln.protocol,
        },
    }


def _hash_payload(vuln: VulnerabilityFinding, context: dict) -> str:
    hash_payload = {
        "project_id": str(vuln.session.project_id),
        "vulnerability_id": str(vuln.pk),
        "cve": vuln.cve or "",
        "severity": vuln.severity,
        "cvss_score": float(vuln.cvss_score) if vuln.cvss_score is not None else None,
        "cvss_vector": vuln.cvss_vector,
        "summary": vuln.summary,
        "host": vuln.host,
        "service": vuln.service,
        "port": vuln.port,
        "protocol": vuln.protocol,
        "status": vuln.status,
        "context": context,
    }
    return HuntFinding.build_source_hash(hash_payload)


def synchronize_findings(
    *,
    projects: Optional[Iterable[Project]] = None,
    project_ids: Optional[Iterable[str]] = None,
    limit: Optional[int] = None,
    create_log: bool = True,
    audit_logs: Optional[bool] = None,
) -> SyncResult:
    """Sincroniza achados do módulo de vulnerabilidades para o Hunt."""

    queryset = VulnerabilityFinding.objects.select_related(
        "session__project",
        "session__source_scan_session",
    ).order_by("-detected_at")

    if projects:
        queryset = queryset.filter(session__project__in=list(projects))
    if project_ids:
        queryset = queryset.filter(session__project_id__in=list(project_ids))
    if limit:
        queryset = queryset[:limit]

    audit_logs = create_log if audit_logs is None else audit_logs
    project_id_list: Sequence[str] = list(project_ids or [])
    tags = ["pipeline:hunt-sync"]
    if project_id_list:
        tags.extend([f"project:{pid}" for pid in project_id_list])

    log_entry: Optional[HuntSyncLog] = None
    if create_log:
        log_entry = HuntSyncLog.objects.create(
            project=None,
            status=HuntSyncLog.Status.SUCCESS,
        )

    audit_start = None
    if audit_logs:
        audit_start = emit_hunt_log(
            event_type="hunt.sync.started",
            message="Sincronização do Hunt iniciada.",
            component="hunt.sync",
            details={
                "project_ids": project_id_list,
                "limit": limit,
            },
            tags=tags,
        )

    result = SyncResult(log_entry=log_entry, audit_log_id=audit_start.id if audit_start else None)

    try:
        for vuln in queryset:
            result.total += 1
            payload_context = _build_context(vuln)
            source_hash = _hash_payload(vuln, payload_context)
            defaults = {
                "project": vuln.session.project,
                "vuln_session": vuln.session,
                "scan_session": vuln.session.source_scan_session,
                "host": vuln.host,
                "service": vuln.service,
                "port": vuln.port,
                "protocol": vuln.protocol,
                "cve": vuln.cve,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "cvss_vector": vuln.cvss_vector,
                "summary": vuln.summary,
                "context": payload_context,
                "tags": _build_tags(vuln),
                "detected_at": vuln.detected_at,
                "source_hash": source_hash,
            }

            hunt_finding, created = HuntFinding.objects.get_or_create(
                vulnerability=vuln,
                defaults=defaults,
            )

            if created:
                result.created += 1
                hunt_finding.record_state_snapshot()
                continue

            if hunt_finding.source_hash == source_hash:
                result.skipped += 1
                continue

            hunt_finding.update_from_payload(
                {
                    "vuln_session": vuln.session,
                    "scan_session": vuln.session.source_scan_session,
                    "host": vuln.host,
                    "service": vuln.service,
                    "port": vuln.port,
                    "protocol": vuln.protocol,
                    "cve": vuln.cve,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "cvss_vector": vuln.cvss_vector,
                    "summary": vuln.summary,
                    "context": payload_context,
                    "tags": _build_tags(vuln),
                    "detected_at": vuln.detected_at,
                    "source_hash": source_hash,
                }
            )
            hunt_finding.save()
            result.updated += 1
            hunt_finding.record_state_snapshot()

        if log_entry:
            log_entry.total_processed = result.total
            log_entry.created_count = result.created
            log_entry.updated_count = result.updated
            log_entry.skipped_count = result.skipped
            log_entry.mark_finished()

        if audit_logs:
            emit_hunt_log(
                event_type="hunt.sync.completed",
                message="Sincronização do Hunt concluída.",
                component="hunt.sync",
                severity=LogEntry.Severity.INFO,
                details=result.as_dict(),
                context={
                    "sync_log_id": log_entry.id if log_entry else None,
                    "start_log_id": audit_start.id if audit_start else None,
                },
                tags=[*tags, "status:success"],
            )

    except Exception as exc:  # pragma: no cover - fluxo de erro
        logger.exception("Erro durante sincronização Hunt")
        if log_entry:
            log_entry.status = HuntSyncLog.Status.ERROR
            log_entry.error_message = str(exc)
            log_entry.total_processed = result.total
            log_entry.created_count = result.created
            log_entry.updated_count = result.updated
            log_entry.skipped_count = result.skipped
            log_entry.mark_finished(status=HuntSyncLog.Status.ERROR, error=str(exc))
        if audit_logs:
            emit_hunt_log(
                event_type="hunt.sync.error",
                message="Erro durante sincronização do Hunt.",
                component="hunt.sync",
                severity=LogEntry.Severity.ERROR,
                details={
                    "error": str(exc),
                    "total": result.total,
                    "created": result.created,
                    "updated": result.updated,
                    "skipped": result.skipped,
                },
                context={"start_log_id": audit_start.id if audit_start else None},
                tags=[*tags, "status:error"],
            )
        raise

    return result


__all__ = [
    "SyncResult",
    "synchronize_findings",
]
