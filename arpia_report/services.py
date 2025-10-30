from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from django.utils import timezone

from arpia_core.models import Project
from arpia_scan.models import ScanFinding, ScanSession
from arpia_vuln.models import VulnScanSession, VulnerabilityFinding

from .models import (
    HuntReportEntry,
    PentestReportEntry,
    ProjectReport,
    ScanReportEntry,
    VulnerabilityReportEntry,
)


@dataclass(slots=True)
class SectionItem:
    title: str
    summary: str
    payload: Dict[str, Any]
    metadata: Dict[str, Any]
    link: Optional[str] = None


@dataclass(slots=True)
class SectionData:
    key: str
    label: str
    description: str
    items: List[SectionItem]
    empty_text: str


class ReportAggregator:
    """Aggregates report information across ARPIA modules."""

    def __init__(self, *, project: Project, session: Optional[ScanSession] = None):
        self.project = project
        self.session = session

    def build_sections(self) -> Dict[str, SectionData]:
        scan_section = self._build_scan_section()
        vuln_section = self._build_vuln_section()
        hunt_section = self._build_hunt_section()
        pentest_section = self._build_pentest_section()
        return {
            scan_section.key: scan_section,
            vuln_section.key: vuln_section,
            hunt_section.key: hunt_section,
            pentest_section.key: pentest_section,
        }

    def build_project_report(self) -> Dict[str, Any]:
        report = (
            ProjectReport.objects.filter(project=self.project)
            .order_by("-generated_at", "-id")
            .first()
        )
        if not report:
            report = self.ensure_project_report()

        return {
            "status": report.status,
            "title": report.title,
            "summary": report.summary,
            "generated_at": report.generated_at,
            "valid_until": report.valid_until,
            "payload": report.payload,
        }

    # ---------------------------------------------------------------------
    # Scan section helpers
    # ---------------------------------------------------------------------

    def _build_scan_section(self) -> SectionData:
        entries: List[SectionItem] = []

        report_entry = None
        if self.session and hasattr(self.session, "report_entry"):
            report_entry = getattr(self.session, "report_entry")
        if not report_entry and self.session:
            report_entry = (
                ScanReportEntry.objects.filter(project=self.project, session=self.session)
                .select_related("session", "project")
                .order_by("-created_at", "-id")
                .first()
            )
        if not report_entry and self.session is None:
            report_entry = (
                ScanReportEntry.objects.filter(project=self.project)
                .select_related("session", "project")
                .order_by("-created_at", "-id")
                .first()
            )

        if report_entry:
            payload = report_entry.payload or {}
            entries.append(
                SectionItem(
                    title=report_entry.title or (report_entry.session.title if report_entry.session else "Relatório de scan"),
                    summary=report_entry.summary,
                    payload=payload,
                    metadata={
                        "status": report_entry.status,
                        "started_at": report_entry.started_at,
                        "finished_at": report_entry.finished_at,
                        "session_id": str(report_entry.session.pk) if report_entry.session else None,
                    },
                )
            )
        elif self.session and self.session.report_snapshot:
            payload = self.session.report_snapshot or {}
            entries.append(
                SectionItem(
                    title=self.session.title,
                    summary=payload.get("summary", {}).get("message", ""),
                    payload=payload,
                    metadata={
                        "status": self.session.status,
                        "started_at": self.session.started_at,
                        "finished_at": self.session.finished_at,
                        "session_id": str(self.session.pk),
                    },
                )
            )

        return SectionData(
            key="scan",
            label="Relatórios de Scan",
            description="Resumo dos artefatos coletados durante as sessões de varredura.",
            items=entries,
            empty_text="Nenhum relatório de scan consolidado até o momento.",
        )

    # ---------------------------------------------------------------------
    # Vulnerability section helpers
    # ---------------------------------------------------------------------

    def _build_vuln_section(self) -> SectionData:
        entries = [
            self._entry_to_section_item(entry)
            for entry in VulnerabilityReportEntry.objects.filter(project=self.project).order_by("-created_at", "-id")
        ]
        if not entries:
            fallback_item = self._build_vuln_fallback_item()
            if fallback_item:
                entries = [fallback_item]

        return SectionData(
            key="vuln",
            label="Relatórios de Vulnerabilidades",
            description="Exibe vulnerabilidades encontradas e respectivas CVEs.",
            items=entries,
            empty_text="Nenhuma vulnerabilidade consolidada.",
        )

    def _build_vuln_fallback_item(self) -> Optional[SectionItem]:
        candidates = (
            VulnScanSession.objects.filter(project=self.project)
            .prefetch_related("findings")
            .order_by("-finished_at", "-started_at", "-created_at")
        )
        session = None
        findings: List[VulnerabilityFinding] = []

        for candidate in candidates:
            candidate_findings = list(candidate.findings.all())
            if candidate_findings:
                session = candidate
                findings = candidate_findings
                break

        if not session or not findings:
            return None

        severity_counts: Dict[str, int] = {}
        cves: set[str] = set()
        sources: set[str] = set()
        open_total = 0
        hosts: set[str] = set()
        max_cvss: Optional[float] = None

        for finding in findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
            if finding.status == VulnerabilityFinding.Status.OPEN:
                open_total += 1
            if finding.cve:
                cves.add(finding.cve)
            data = finding.data or {}
            for cve_code in data.get("cves") or []:
                cves.add(cve_code)
            source_kind = data.get("source_kind") or data.get("source")
            if source_kind:
                sources.add(source_kind)
            if finding.host:
                hosts.add(finding.host)
            if finding.cvss_score is not None:
                score = float(finding.cvss_score)
                if max_cvss is None or score > max_cvss:
                    max_cvss = score

        artifacts: List[Dict[str, str]] = []
        finding_payload: List[Dict[str, Any]] = []
        for finding in findings:
            data = finding.data or {}
            artifact_path = data.get("file_path")
            if artifact_path:
                artifacts.append(
                    {
                        "path": artifact_path,
                        "source": data.get("source_kind") or data.get("source"),
                    }
                )
            finding_payload.append(
                {
                    "id": str(finding.pk),
                    "title": finding.title,
                    "summary": finding.summary,
                    "severity": finding.severity,
                    "status": finding.status,
                    "host": finding.host,
                    "service": finding.service,
                    "port": finding.port,
                    "protocol": finding.protocol,
                    "cve": finding.cve,
                    "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
                    "cvss_vector": finding.cvss_vector,
                }
            )

        summary_text = (
            f"{len(findings)} vulnerabilidade(s) identificadas — {open_total} abertas."
        )

        payload: Dict[str, Any] = {
            "generated_at": timezone.now().isoformat(),
            "session": {
                "id": str(session.pk),
                "reference": session.reference,
                "title": session.title,
                "status": session.status,
                "started_at": session.started_at,
                "finished_at": session.finished_at,
            },
            "summary": {
                "totals": {"total": len(findings), "open": open_total},
                "severity": severity_counts,
                "cves": sorted(cves),
                "hosts_impacted": len(hosts),
                "sources": sorted(sources),
                "max_cvss": max_cvss,
            },
            "artifacts": artifacts,
            "findings": finding_payload,
        }

        metadata = {
            "severity_distribution": severity_counts,
            "cves": sorted(cves),
            "source_identifier": f"vuln-session:{session.pk}",
        }

        return SectionItem(
            title=f"Resumo automático — {session.title}",
            summary=summary_text,
            payload=payload,
            metadata=metadata,
        )

    # ---------------------------------------------------------------------
    # Hunt section helpers
    # ---------------------------------------------------------------------

    def _build_hunt_section(self) -> SectionData:
        entries = [
            self._entry_to_section_item(entry)
            for entry in HuntReportEntry.objects.filter(project=self.project)
        ]
        return SectionData(
            key="hunt",
            label="Relatórios de Hunt",
            description="Indicadores e inteligência coletada durante as atividades de hunt.",
            items=entries,
            empty_text="Nenhuma atividade de threat hunt registrada.",
        )

    # ---------------------------------------------------------------------
    # Pentest section helpers
    # ---------------------------------------------------------------------

    def _build_pentest_section(self) -> SectionData:
        entries = [
            self._entry_to_section_item(entry)
            for entry in PentestReportEntry.objects.filter(project=self.project)
        ]
        return SectionData(
            key="pentest",
            label="Relatórios de Pentest",
            description="Resultados das execuções de pentest e recomendações.",
            items=entries,
            empty_text="Nenhum relatório de pentest disponível.",
        )

    # ---------------------------------------------------------------------

    def _entry_to_section_item(self, entry: Optional[Any]) -> SectionItem:
        if not entry:
            return SectionItem(title="", summary="", payload={}, metadata={})

        metadata = {
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "tags": entry.tags,
        }

        if isinstance(entry, VulnerabilityReportEntry):
            metadata.update(
                {
                    "severity_distribution": entry.severity_distribution,
                    "cves": entry.cves,
                    "source_identifier": entry.source_identifier,
                }
            )
        elif isinstance(entry, HuntReportEntry):
            metadata.update(
                {
                    "intel_summary": entry.intel_summary,
                    "indicators": entry.indicators,
                }
            )
        elif isinstance(entry, PentestReportEntry):
            metadata.update(
                {
                    "engagement_ref": entry.engagement_ref,
                    "findings": entry.findings,
                    "recommendations": entry.recommendations,
                }
            )

        return SectionItem(
            title=entry.title,
            summary=entry.summary,
            payload=entry.payload or {},
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def collect_findings_summary(self) -> Dict[str, int]:
        """Summaries findings per source to assist project final report."""
        counters = {"scan": 0, "vuln": 0, "hunt": 0, "pentest": 0}

        counters["scan"] = (
            ScanFinding.objects.filter(session__project=self.project).count()
        )
        counters["vuln"] = len(
            VulnerabilityReportEntry.objects.filter(project=self.project)
        )
        counters["hunt"] = len(
            HuntReportEntry.objects.filter(project=self.project)
        )
        counters["pentest"] = len(
            PentestReportEntry.objects.filter(project=self.project)
        )
        return counters

    def ensure_project_report(self) -> ProjectReport:
        report = (
            ProjectReport.objects.filter(project=self.project, status=ProjectReport.Status.DRAFT)
            .order_by("-generated_at", "-id")
            .first()
        )
        if report:
            return report

        counters = self.collect_findings_summary()
        payload = {
            "generated_at": timezone.now().isoformat(),
            "totals": counters,
        }
        return ProjectReport.objects.create(
            project=self.project,
            title=f"Relatório consolidado — {self.project.name}",
            summary="Relatório inicial consolidando os dados disponíveis nas atividades.",
            payload=payload,
        )