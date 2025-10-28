from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

from django.utils import timezone

from arpia_core.models import Project
from arpia_scan.models import ScanFinding, ScanSession

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
            for entry in VulnerabilityReportEntry.objects.filter(project=self.project)
        ]
        return SectionData(
            key="vuln",
            label="Relatórios de Vulnerabilidades",
            description="Exibe vulnerabilidades encontradas e respectivas CVEs.",
            items=entries,
            empty_text="Nenhuma vulnerabilidade consolidada.",
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