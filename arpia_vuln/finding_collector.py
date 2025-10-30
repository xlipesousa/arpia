from __future__ import annotations

import json
from collections import Counter
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import VulnScanSession, VulnTask, VulnerabilityFinding
from .parsers import ParsedFinding, parse_greenbone_vulnerabilities, parse_nmap_vulnerabilities


def _relative_to_base(path: Path) -> str:
    base_dir = Path(settings.BASE_DIR)
    try:
        return str(path.resolve().relative_to(base_dir))
    except (ValueError, RuntimeError):
        return str(path.resolve())


def _map_severity(value: Optional[str]) -> str:
    normalized = (value or "").strip().lower()
    choices = set(VulnerabilityFinding.Severity.values)
    if normalized in choices:
        return normalized
    return VulnerabilityFinding.Severity.UNKNOWN


def _decimal_score(score: Optional[float]) -> Optional[Decimal]:
    if score is None:
        return None
    try:
        return Decimal(str(score)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    except Exception:  # pragma: no cover - defensivo
        return None


class VulnerabilityFindingCollector:
    """Consolida artefatos gerados durante o pipeline de vulnerabilidades."""

    NMAP_TARGETED_NSE_SLUG = "nmap-targeted-nse"
    LEGACY_NMAP_VULN_SLUGS = {"nmap-vuln-nse"}

    def __init__(self, session: VulnScanSession) -> None:
        self.session = session
        self.project = session.project
        self.base_dir = Path(settings.BASE_DIR)
        self.tasks = list(session.tasks.select_related("script"))
        self._candidate_dirs = self._detect_candidate_dirs()
        self.artifact_index: Dict[str, Dict[str, Optional[str]]] = {}

    def collect(self, *, clean: bool = True) -> Dict[str, object]:
        """Parseia arquivos de saída e atualiza VulnerabilityFinding."""
        parsed_items: List[Tuple[ParsedFinding, Optional[VulnTask]]] = []
        parsed_items.extend(self._collect_from_nmap())
        parsed_items.extend(self._collect_from_greenbone())
        return self._persist_findings(parsed_items, clean=clean)

    def _collect_from_nmap(self) -> List[Tuple[ParsedFinding, Optional[VulnTask]]]:
        results: List[Tuple[ParsedFinding, Optional[VulnTask]]] = []
        for task in self.tasks:
            slug = (task.script.slug if task.script else "").strip()
            if slug == self.NMAP_TARGETED_NSE_SLUG:
                patterns: Sequence[str] = ("nmap_nse_targeted_*.xml",)
                source_label = "nmap_targeted_nse"
            elif slug in self.LEGACY_NMAP_VULN_SLUGS:
                patterns = ("nmap_vuln_*.xml",)
                source_label = "nmap_vuln"
            else:
                continue

            for path, relative in self._iter_artifacts(task, patterns):
                xml_payload = path.read_text(encoding="utf-8", errors="ignore")
                for finding in parse_nmap_vulnerabilities(xml_payload, source=source_label, file_path=relative):
                    results.append((finding, task))
        return results

    def _collect_from_greenbone(self) -> List[Tuple[ParsedFinding, Optional[VulnTask]]]:
        results: List[Tuple[ParsedFinding, Optional[VulnTask]]] = []
        for task in self.tasks:
            if task.kind != VulnTask.Kind.GREENBONE_SCAN:
                continue
            params = task.parameters or {}
            report_path_value = params.get("report_path")
            resolved = self._resolve_path(report_path_value)
            if not resolved:
                continue
            relative = _relative_to_base(resolved)
            self._register_artifact(relative, task)
            xml_payload = resolved.read_text(encoding="utf-8", errors="ignore")
            for finding in parse_greenbone_vulnerabilities(xml_payload, file_path=relative):
                results.append((finding, task))
        return results

    def _persist_findings(
        self,
        parsed_items: List[Tuple[ParsedFinding, Optional[VulnTask]]],
        *,
        clean: bool,
    ) -> Dict[str, object]:
        existing_map: Dict[Tuple, VulnerabilityFinding] = {}
        for finding in self.session.findings.all():
            existing_map[finding_fingerprint(finding)] = finding

        seen: set[Tuple] = set()

        with transaction.atomic():
            for parsed, task in parsed_items:
                fingerprint = self._parsed_fingerprint(parsed)
                seen.add(fingerprint)
                if fingerprint in existing_map:
                    self._update_finding(existing_map[fingerprint], parsed, task)
                else:
                    existing_map[fingerprint] = self._create_finding(parsed, task)

            if clean and parsed_items:
                for fingerprint, finding in list(existing_map.items()):
                    if fingerprint not in seen:
                        finding.delete()
                        del existing_map[fingerprint]

        summary = self._build_summary(existing_map.values())
        self._update_session_snapshot(summary)
        return summary

    def _create_finding(self, parsed: ParsedFinding, task: Optional[VulnTask]) -> VulnerabilityFinding:
        finding = VulnerabilityFinding(
            session=self.session,
            source_task=task,
            cve=(parsed.cves[0].upper() if parsed.cves else ""),
            title=parsed.title[:255],
            summary=parsed.summary,
            severity=_map_severity(parsed.severity),
            host=parsed.host,
            service=parsed.service,
            port=parsed.port,
            protocol=parsed.protocol,
            cvss_score=_decimal_score(parsed.cvss_score),
            cvss_vector=parsed.cvss_vector or "",
            data=self._build_data(parsed),
        )
        finding.save()
        return finding

    def _update_finding(
        self,
        finding: VulnerabilityFinding,
        parsed: ParsedFinding,
        task: Optional[VulnTask],
    ) -> None:
        changed = False
        new_title = parsed.title[:255]
        if finding.title != new_title:
            finding.title = new_title
            changed = True
        if finding.summary != parsed.summary:
            finding.summary = parsed.summary
            changed = True
        new_severity = _map_severity(parsed.severity)
        if finding.severity != new_severity:
            finding.severity = new_severity
            changed = True
        if finding.host != parsed.host:
            finding.host = parsed.host
            changed = True
        if finding.service != parsed.service:
            finding.service = parsed.service
            changed = True
        if finding.port != parsed.port:
            finding.port = parsed.port
            changed = True
        if finding.protocol != parsed.protocol:
            finding.protocol = parsed.protocol
            changed = True
        new_score = _decimal_score(parsed.cvss_score)
        if finding.cvss_score != new_score:
            finding.cvss_score = new_score
            changed = True
        if finding.cvss_vector != (parsed.cvss_vector or ""):
            finding.cvss_vector = parsed.cvss_vector or ""
            changed = True
        new_cve = parsed.cves[0].upper() if parsed.cves else ""
        if finding.cve != new_cve:
            finding.cve = new_cve
            changed = True
        data_payload = self._build_data(parsed)
        if finding.data != data_payload:
            finding.data = data_payload
            changed = True
        if task and finding.source_task_id != task.id:
            finding.source_task = task
            changed = True

        if changed:
            save_fields = [
                "title",
                "summary",
                "severity",
                "host",
                "service",
                "port",
                "protocol",
                "cvss_score",
                "cvss_vector",
                "cve",
                "data",
                "source_task",
            ]
            finding.save(update_fields=save_fields)

    def _build_data(self, parsed: ParsedFinding) -> Dict[str, object]:
        payload = dict(parsed.data or {})
        payload["cves"] = parsed.cves
        payload["references"] = parsed.references
        payload["source"] = payload.get("source") or parsed.source
        payload["source_kind"] = (parsed.source or "").lower()
        payload["scanner"] = parsed.scanner
        if isinstance(parsed.data, dict):
            payload.setdefault("file_path", parsed.data.get("file_path"))
        payload["collected_at"] = timezone.now().isoformat()
        return payload

    def _build_summary(self, findings: Iterable[VulnerabilityFinding]) -> Dict[str, object]:
        items = list(findings)
        severity_counts = Counter(finding.severity for finding in items)
        severity_summary = {key: severity_counts.get(key, 0) for key in VulnerabilityFinding.Severity.values}
        cves: set[str] = set()
        sources: set[str] = set()
        hosts: set[str] = set()
        task_ids: set[str] = set()
        max_score: Optional[Decimal] = None

        for finding in items:
            if finding.cve:
                cves.add(finding.cve.upper())
            data = finding.data or {}
            for extra_cve in data.get("cves", []):
                cves.add(str(extra_cve).upper())
            source_kind = data.get("source_kind") or data.get("source")
            if source_kind:
                sources.add(str(source_kind))
            if finding.host:
                hosts.add(finding.host)
            if finding.source_task_id:
                task_ids.add(str(finding.source_task_id))
            if finding.cvss_score is not None:
                if max_score is None or finding.cvss_score > max_score:
                    max_score = finding.cvss_score

        open_total = sum(1 for finding in items if finding.status == VulnerabilityFinding.Status.OPEN)

        summary = {
            "total": len(items),
            "open_total": open_total,
            "by_severity": severity_summary,
            "cves": sorted(cves),
            "sources": sorted(sources),
            "hosts_impacted": len(hosts),
            "tasks": sorted(task_ids),
            "max_cvss": float(max_score) if max_score is not None else None,
            "artifacts": sorted(
                self.artifact_index.values(),
                key=lambda item: item.get("path") or "",
            ),
            "last_collected_at": timezone.now().isoformat(),
        }
        return summary

    def _update_session_snapshot(self, summary: Dict[str, object]) -> None:
        report_snapshot = json.loads(json.dumps(self.session.report_snapshot or {}, ensure_ascii=False))
        report_snapshot.setdefault("findings", {})
        report_snapshot["findings"].update(summary)
        self.session.report_snapshot = report_snapshot
        self.session.save(update_fields=["report_snapshot", "updated_at"])

    def _iter_artifacts(
        self,
        task: VulnTask,
        patterns: Sequence[str],
    ) -> List[Tuple[Path, str]]:
        results: List[Tuple[Path, str]] = []
        seen_relatives: set[str] = set()
        params = task.parameters or {}
        candidates = params.get("artifacts")
        if isinstance(candidates, str):
            candidates = [candidates]
        elif not isinstance(candidates, list):
            candidates = []

        for candidate in candidates:
            resolved = self._resolve_path(candidate)
            if not resolved:
                continue
            relative = _relative_to_base(resolved)
            if relative in seen_relatives:
                continue
            seen_relatives.add(relative)
            self._register_artifact(relative, task)
            results.append((resolved, relative))

        if not results:
            for directory in self._candidate_dirs:
                for pattern in patterns:
                    for resolved in directory.glob(pattern):
                        relative = _relative_to_base(resolved)
                        if relative in seen_relatives:
                            continue
                        seen_relatives.add(relative)
                        self._register_artifact(relative, task)
                        results.append((resolved, relative))

        return results

    def _register_artifact(self, relative: str, task: VulnTask) -> None:
        slug = task.script.slug if task and task.script else None
        source: Optional[str]
        if task.kind == VulnTask.Kind.GREENBONE_SCAN:
            source = "greenbone"
        elif slug == self.NMAP_TARGETED_NSE_SLUG:
            source = "nmap_targeted_nse"
        elif slug in self.LEGACY_NMAP_VULN_SLUGS:
            source = "nmap_vuln"
        else:
            source = task.kind if task else None

        self.artifact_index[relative] = {
            "path": relative,
            "task_id": str(task.id) if task else None,
            "task_kind": task.kind if task else None,
            "script": task.script.slug if task and task.script else None,
            "source": source,
        }

    def _resolve_path(self, value: Optional[str]) -> Optional[Path]:
        if not value:
            return None
        path = Path(value)
        if not path.is_absolute():
            path = self.base_dir / path
        path = path.resolve()
        return path if path.exists() else None

    def _detect_candidate_dirs(self) -> List[Path]:
        recon_root = self.base_dir / "recon"
        candidates: set[Path] = set()
        slug = (self.project.slug or "").strip()
        if slug:
            candidates.add(recon_root / slug)
            candidates.add(recon_root / slug / "vuln")
        name = (self.project.name or "").strip()
        if name:
            sanitized = name.replace(" ", "_")
            candidates.add(recon_root / sanitized)
            candidates.add(recon_root / sanitized / "vuln")
        return sorted(path for path in candidates if path.exists())

    def _parsed_fingerprint(self, parsed: ParsedFinding) -> Tuple:
        return (str(self.session.id),) + parsed.fingerprint()


def finding_fingerprint(finding: VulnerabilityFinding) -> Tuple:
    """Gera fingerprint consistente para localizar findings existentes."""
    session_id = str(finding.session_id)
    host = (finding.host or "").strip().lower()
    port = finding.port or 0
    data_obj = finding.data if isinstance(finding.data, dict) else {}
    source = data_obj.get("source_kind") or data_obj.get("source") or "unknown"
    cve_set = {str(finding.cve or "").upper()}
    for item in data_obj.get("cves", []):
        cve_set.add(str(item).upper())
    cves = tuple(sorted(cve_set))
    title = (finding.title or "").strip().lower()
    return (session_id, source, host, port, cves, title)
