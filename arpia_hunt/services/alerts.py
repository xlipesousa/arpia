from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from typing import Iterable, Mapping, Sequence
from urllib import error as urllib_error
from urllib import request as urllib_request

from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.db.models import Count, F, Q
from django.utils import timezone

from arpia_log.models import LogEntry
from arpia_log.services import log_event
from arpia_vuln.models import VulnerabilityFinding

from ..models import CveAttackTechnique, HuntAlert, HuntFinding, HuntRecommendation


CRITICAL_CVSS_THRESHOLD = Decimal("9.0")
BLUE_REVIEW_MIN_BLUE_RECOMMENDATIONS = 2
SEVERITY_ORDER = {
    VulnerabilityFinding.Severity.CRITICAL: 5,
    VulnerabilityFinding.Severity.HIGH: 4,
    VulnerabilityFinding.Severity.MEDIUM: 3,
    VulnerabilityFinding.Severity.LOW: 2,
    VulnerabilityFinding.Severity.INFO: 1,
    VulnerabilityFinding.Severity.UNKNOWN: 0,
}


def _settings_dict() -> Mapping[str, object]:
    config = getattr(settings, "HUNT_ALERTS", {})
    if isinstance(config, Mapping):
        return config
    return {}


def _get_list_setting(key: str) -> Sequence[str]:
    value = _settings_dict().get(key, [])
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, Iterable):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _get_email_sender() -> str:
    config = _settings_dict()
    sender = str(config.get("EMAIL_SENDER", "") or "").strip()
    if sender:
        return sender
    return getattr(settings, "DEFAULT_FROM_EMAIL", "alerts@arpia.local")


def _get_sla_minutes(kind: str) -> int:
    config = _settings_dict()
    mapping = config.get("SLA_MINUTES", {})
    if isinstance(mapping, Mapping):
        raw = mapping.get(kind)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                pass
    try:
        return int(config.get("DEFAULT_SLA_MINUTES", 120))
    except (TypeError, ValueError):
        return 120


def _get_webhook_url() -> str:
    value = str(_settings_dict().get("WEBHOOK_URL", "") or "").strip()
    return value


def _collect_metrics(finding: HuntFinding) -> dict[str, object]:
    recommendation_counts = (
        finding.recommendations.values("recommendation_type")
        .annotate(total=Count("id"))
    )
    counts = {item["recommendation_type"]: item["total"] for item in recommendation_counts}
    blue_count = counts.get(HuntRecommendation.Type.BLUE, 0)
    red_count = counts.get(HuntRecommendation.Type.RED, 0)
    automation_high_exists = finding.recommendations.filter(
        generated_by=HuntRecommendation.Generator.AUTOMATION,
        confidence=CveAttackTechnique.Confidence.HIGH,
    ).exists()
    cvss_score = finding.cvss_score or (finding.vulnerability.cvss_score if finding.vulnerability else None)
    severity = finding.severity or (finding.vulnerability.severity if finding.vulnerability else VulnerabilityFinding.Severity.UNKNOWN)

    return {
        "blue_count": blue_count,
        "red_count": red_count,
        "automation_high_exists": automation_high_exists,
        "cvss_score": Decimal(str(cvss_score)) if cvss_score is not None else None,
        "severity": severity,
    }


def _activate_alert(finding: HuntFinding, kind: str, metadata: dict[str, object], *, severity: str) -> HuntAlert:
    with transaction.atomic():
        try:
            alert = HuntAlert.objects.select_for_update().get(finding=finding, kind=kind, is_active=True)
            HuntAlert.objects.filter(pk=alert.pk).update(
                metadata=metadata,
                last_triggered_at=timezone.now(),
                trigger_count=F("trigger_count") + 1,
                updated_at=timezone.now(),
            )
            alert.refresh_from_db()
            created = False
        except HuntAlert.DoesNotExist:
            alert = HuntAlert.objects.create(
                finding=finding,
                kind=kind,
                metadata=metadata,
                is_active=True,
                first_triggered_at=timezone.now(),
                last_triggered_at=timezone.now(),
            )
            created = True

    _dispatch_alert(alert, severity=severity, event="triggered" if created else "updated")
    return alert


def _resolve_alert(finding: HuntFinding, kind: str) -> HuntAlert | None:
    try:
        alert = HuntAlert.objects.get(finding=finding, kind=kind, is_active=True)
    except HuntAlert.DoesNotExist:
        return None

    alert.is_active = False
    alert.resolved_at = timezone.now()
    alert.save(update_fields=["is_active", "resolved_at", "updated_at"])
    _dispatch_alert(alert, severity=LogEntry.Severity.INFO, event="resolved")
    return alert


def _severity_rank(value: str | None) -> int:
    if not value:
        return 0
    return SEVERITY_ORDER.get(value, 0)


def _build_common_payload(alert: HuntAlert, *, sla_minutes: int) -> dict[str, object]:
    finding = alert.finding
    base = {
        "alert_id": alert.pk,
        "finding_id": str(finding.pk),
        "project_id": str(finding.project_id) if finding.project_id else None,
        "project_name": getattr(finding.project, "name", None),
        "kind": alert.kind,
        "sla_minutes": sla_minutes,
        "sla_due_at": (alert.last_triggered_at + timedelta(minutes=sla_minutes)).isoformat(),
        "metadata": alert.metadata,
    }
    if finding.vulnerability:
        base.update(
            {
                "cve": finding.cve or finding.vulnerability.cve,
                "severity": finding.severity or finding.vulnerability.severity,
                "cvss_score": alert.metadata.get("cvss_score"),
            }
        )
    return base


def _dispatch_alert(alert: HuntAlert, *, severity: str, event: str) -> None:
    sla_minutes = _get_sla_minutes(alert.kind)
    payload = _build_common_payload(alert, sla_minutes=sla_minutes)

    message = f"{alert.get_kind_display()} · {payload.get('project_name') or 'Projeto desconhecido'}"
    tags = [f"alert:{alert.kind}"]
    if alert.kind == HuntAlert.Kind.PRIORITY_CRITICAL:
        tags.extend(["team:blue", "team:red"])
    elif alert.kind == HuntAlert.Kind.AUTOMATION_HIGH:
        tags.append("team:red")
    else:
        tags.append("team:blue")

    log_event(
        source_app="arpia_hunt",
        component="hunt.alerts",
        event_type=f"hunt.alert.{event}",
        message=message,
    severity=severity,
        details=payload,
        tags=tags,
    )

    _dispatch_email(alert, payload, event)
    _dispatch_webhook(alert, payload, event)


def _dispatch_email(alert: HuntAlert, payload: dict[str, object], event: str) -> None:
    recipients: list[str] = []
    if alert.kind == HuntAlert.Kind.PRIORITY_CRITICAL:
        recipients = list({_email for _email in _get_list_setting("BLUE_EMAILS") + _get_list_setting("RED_EMAILS")})
    elif alert.kind == HuntAlert.Kind.AUTOMATION_HIGH:
        recipients = _get_list_setting("RED_EMAILS")
    else:
        recipients = _get_list_setting("BLUE_EMAILS")

    if not recipients:
        return

    subject = f"[ARPIA][Hunt] {alert.get_kind_display()} ({event})"
    lines = [
        subject,
        "",
        f"Finding: {payload.get('finding_id')}",
    ]
    if payload.get("project_name"):
        lines.append(f"Projeto: {payload['project_name']}")
    if payload.get("cve"):
        lines.append(f"CVE: {payload['cve']}")
    if payload.get("severity"):
        lines.append(f"Severidade: {payload['severity']}")
    if payload.get("metadata"):
        lines.append("Detalhes:")
        for key, value in payload["metadata"].items():
            lines.append(f"  - {key}: {value}")
    lines.append("")
    lines.append(f"SLA: responder em {payload['sla_minutes']} minutos (até {payload['sla_due_at']})")

    send_mail(
        subject=subject,
        message="\n".join(lines),
        from_email=_get_email_sender(),
        recipient_list=list(dict.fromkeys(recipients)),
        fail_silently=True,
    )


def _dispatch_webhook(alert: HuntAlert, payload: dict[str, object], event: str) -> None:
    url = _get_webhook_url()
    if not url:
        return

    body = json.dumps(
        {
            "event": f"hunt.alert.{event}",
            "kind": alert.kind,
            "finding": payload,
            "timestamp": timezone.now().isoformat(),
        }
    ).encode("utf-8")

    request = urllib_request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib_request.urlopen(request, timeout=5):  # noqa: S310 - controlled URL from settings
            pass
    except urllib_error.URLError as exc:  # pragma: no cover - falha de infra não bloqueia
        log_event(
            source_app="arpia_hunt",
            component="hunt.alerts",
            event_type="hunt.alert.webhook_error",
            message=f"Falha ao enviar webhook para {url}",
            severity="WARNING",
            details={"error": str(exc)},
            tags=["alert:webhook"],
        )


def _should_trigger_priority(metrics: Mapping[str, object]) -> bool:
    cvss = metrics.get("cvss_score")
    red_count = metrics.get("red_count", 0)
    return bool(cvss is not None and Decimal(cvss) >= CRITICAL_CVSS_THRESHOLD and int(red_count) > 0)


def _should_trigger_automation(metrics: Mapping[str, object]) -> bool:
    return bool(metrics.get("automation_high_exists"))


def _should_trigger_blue_review(metrics: Mapping[str, object]) -> bool:
    blue_count = int(metrics.get("blue_count", 0))
    severity_rank = _severity_rank(metrics.get("severity"))
    return blue_count >= BLUE_REVIEW_MIN_BLUE_RECOMMENDATIONS and severity_rank >= _severity_rank(
        VulnerabilityFinding.Severity.MEDIUM
    )


def evaluate_alerts_for_finding(finding: HuntFinding | str) -> dict[str, list[HuntAlert]]:
    if not isinstance(finding, HuntFinding):
        finding = HuntFinding.objects.select_related("project", "vulnerability").prefetch_related("recommendations").get(pk=finding)

    metrics = _collect_metrics(finding)
    results: dict[str, list[HuntAlert]] = {"triggered": [], "resolved": []}

    if _should_trigger_priority(metrics):
        alert = _activate_alert(
            finding,
            HuntAlert.Kind.PRIORITY_CRITICAL,
            {
                "red_recommendations": metrics["red_count"],
                "cvss_score": str(metrics.get("cvss_score")) if metrics.get("cvss_score") is not None else None,
            },
            severity=LogEntry.Severity.CRITICAL,
        )
        results["triggered"].append(alert)
    else:
        resolved = _resolve_alert(finding, HuntAlert.Kind.PRIORITY_CRITICAL)
        if resolved:
            results["resolved"].append(resolved)

    if _should_trigger_automation(metrics):
        alert = _activate_alert(
            finding,
            HuntAlert.Kind.AUTOMATION_HIGH,
            {
                "automation_high": True,
                "cvss_score": str(metrics.get("cvss_score")) if metrics.get("cvss_score") is not None else None,
            },
            severity=LogEntry.Severity.WARN,
        )
        results["triggered"].append(alert)
    else:
        resolved = _resolve_alert(finding, HuntAlert.Kind.AUTOMATION_HIGH)
        if resolved:
            results["resolved"].append(resolved)

    if _should_trigger_blue_review(metrics):
        alert = _activate_alert(
            finding,
            HuntAlert.Kind.BLUE_REVIEW,
            {
                "blue_recommendations": metrics["blue_count"],
                "severity": metrics.get("severity"),
            },
            severity=LogEntry.Severity.NOTICE,
        )
        results["triggered"].append(alert)
    else:
        resolved = _resolve_alert(finding, HuntAlert.Kind.BLUE_REVIEW)
        if resolved:
            results["resolved"].append(resolved)

    return results


def evaluate_all_findings(queryset: Iterable[HuntFinding] | None = None) -> dict[str, int]:
    if queryset is None:
        queryset = HuntFinding.objects.select_related("project", "vulnerability")

    summary = {"triggered": 0, "resolved": 0}
    for finding in queryset:
        result = evaluate_alerts_for_finding(finding)
        summary["triggered"] += len(result["triggered"])
        summary["resolved"] += len(result["resolved"])
    return summary
