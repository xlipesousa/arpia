import copy
import json
import os
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from pathlib import Path
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from arpia_core.models import Project
from django.utils import timezone

from arpia_hunt.models import (
    AttackTactic,
    AttackTechnique,
    CveAttackTechnique,
    HuntEnrichment,
    HuntFinding,
    HuntFindingEnrichment,
    HuntFindingSnapshot,
    HuntFindingState,
    HuntRecommendation,
    HuntSyncLog,
)
from arpia_hunt.services import sync_recommendations_for_finding, synchronize_findings
from arpia_hunt.enrichment import enrich_cve, enrich_finding
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession
from arpia_log.models import LogEntry
from django.db import IntegrityError

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def load_json_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open(encoding="utf-8") as stream:
        return json.load(stream)


class SynchronizeFindingsTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user("hunter", "hunter@example.com", "hunter")
        self.project = Project.objects.create(owner=self.user, name="Projeto Hunt", slug="projeto-hunt")
        self.session = VulnScanSession.objects.create(
            project=self.project,
            owner=self.user,
            title="Sessão Vuln",
        )

    def _create_vulnerability(self, **overrides) -> VulnerabilityFinding:
        defaults = {
            "session": self.session,
            "title": "Apache HTTPD outdated",
            "summary": "Servidor Apache vulnerável à execução remota.",
            "severity": VulnerabilityFinding.Severity.HIGH,
            "status": VulnerabilityFinding.Status.OPEN,
            "host": "192.168.1.10",
            "service": "http",
            "port": 80,
            "protocol": "tcp",
            "cve": "CVE-2024-0001",
            "cvss_score": Decimal("8.5"),
        }
        defaults.update(overrides)
        return VulnerabilityFinding.objects.create(**defaults)

    def test_sync_creates_hunt_finding_and_log(self):
        vuln = self._create_vulnerability()

        result = synchronize_findings()

        self.assertEqual(result.created, 1)
        self.assertEqual(HuntFinding.objects.count(), 1)
        hunt_entry = HuntFinding.objects.get()
        self.assertEqual(hunt_entry.vulnerability, vuln)
        self.assertEqual(hunt_entry.cve, vuln.cve)
        self.assertEqual(hunt_entry.project, self.project)
        self.assertEqual(hunt_entry.state_version, 1)
        self.assertEqual(hunt_entry.state_snapshots.count(), 1)
        state_snapshot = hunt_entry.state_snapshots.get()
        self.assertEqual(state_snapshot.source_hash, hunt_entry.source_hash)
        self.assertIn("summary", state_snapshot.payload)
        self.assertTrue(HuntSyncLog.objects.exists())
        self.assertTrue(LogEntry.objects.filter(event_type="hunt.sync.completed").exists())

    def test_sync_updates_when_vulnerability_changes(self):
        vuln = self._create_vulnerability(summary="Versão antiga.")
        synchronize_findings()

        hunt_entry = HuntFinding.objects.get()
        original_hash = hunt_entry.source_hash

        vuln.summary = "Versão antiga expõe RCE crítico."  # altera conteúdo
        vuln.save()

        result = synchronize_findings()

        hunt_entry.refresh_from_db()
        self.assertNotEqual(hunt_entry.source_hash, original_hash)
        self.assertEqual(result.updated, 1)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(hunt_entry.state_version, 2)
        self.assertEqual(hunt_entry.state_snapshots.count(), 2)
        self.assertGreaterEqual(LogEntry.objects.filter(event_type="hunt.sync.completed").count(), 2)

    def test_sync_skips_without_creating_additional_state_snapshot(self):
        self._create_vulnerability()
        synchronize_findings()

        hunt_entry = HuntFinding.objects.get()
        self.assertEqual(hunt_entry.state_version, 1)

        result = synchronize_findings()
        hunt_entry.refresh_from_db()

        self.assertEqual(result.skipped, result.total)
        self.assertEqual(hunt_entry.state_version, 1)
        self.assertEqual(hunt_entry.state_snapshots.count(), 1)


class EnrichmentServiceTests(TestCase):
    def test_enrich_cve_creates_skipped_records_when_remote_disabled(self):
        records = enrich_cve("CVE-2024-9999", enable_remote=False)
        self.assertEqual(set(records.keys()), {"nvd", "vulners", "exploitdb"})
        for source, record in records.items():
            self.assertEqual(record.cve, "CVE-2024-9999")
            self.assertEqual(record.source, source)
            self.assertEqual(record.status, HuntEnrichment.Status.SKIPPED)
            self.assertTrue(record.error_message)
            self.assertTrue(LogEntry.objects.filter(event_type="hunt.enrichment.skipped", details__source=source).exists())

    def test_enrich_cve_reuses_fresh_record(self):
        record = HuntEnrichment.objects.create(
            cve="CVE-2025-1234",
            source=HuntEnrichment.Source.NVD,
            status=HuntEnrichment.Status.FRESH,
            payload={"placeholder": True},
            fetched_at=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=6),
        )
        result = enrich_cve("CVE-2025-1234", enable_remote=False)
        self.assertEqual(result[HuntEnrichment.Source.NVD].pk, record.pk)
        self.assertEqual(result[HuntEnrichment.Source.NVD].payload, {"placeholder": True})


class FindingProfilesTests(TestCase):
    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user("hunter", "hunter@example.com", "hunter")
        self.project = Project.objects.create(owner=self.user, name="Projeto Hunt", slug="projeto-hunt")
        self.session = VulnScanSession.objects.create(
            project=self.project,
            owner=self.user,
            title="Sessão Vuln",
        )

    def _create_finding(self, **overrides) -> HuntFinding:
        defaults = {
            "title": "Apache HTTPD outdated",
            "summary": "Servidor Apache vulnerável à execução remota.",
            "severity": VulnerabilityFinding.Severity.HIGH,
            "status": VulnerabilityFinding.Status.OPEN,
            "host": "192.168.1.10",
            "service": "http",
            "port": 80,
            "protocol": "tcp",
            "cve": "CVE-2024-9999",
            "cvss_score": Decimal("8.5"),
        }
        defaults.update(overrides)
        vuln = VulnerabilityFinding.objects.create(session=self.session, **defaults)
        synchronize_findings()
        return HuntFinding.objects.get(vulnerability=vuln)

    @mock.patch.dict(os.environ, {"ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT": "1"})
    @mock.patch("arpia_hunt.enrichment.search_exploitdb")
    @mock.patch("arpia_hunt.enrichment.fetch_vulners_cve")
    @mock.patch("arpia_hunt.enrichment.fetch_nvd_cve")
    def test_enrich_finding_updates_profiles_and_creates_snapshot(self, mock_nvd, mock_vulners, mock_exploit):
        finding = self._create_finding()
        mock_nvd.return_value = load_json_fixture("nvd_cve.json")
        mock_vulners.return_value = load_json_fixture("vulners_cve.json")
        mock_exploit.return_value = load_json_fixture("exploitdb_results.json")

        records, changed = enrich_finding(finding, enable_remote=True, force_refresh=True)
        finding.refresh_from_db()
        self.assertTrue(changed)
        self.assertEqual(finding.profile_version, 1)
        self.assertIn("references", finding.blue_profile)
        self.assertGreaterEqual(len(finding.red_profile.get("exploits", [])), 1)
        self.assertEqual(HuntFindingSnapshot.objects.filter(finding=finding).count(), 1)
        self.assertTrue(
            HuntFindingEnrichment.objects.filter(finding=finding, enrichment__in=records.values()).exists()
        )

    @mock.patch.dict(os.environ, {"ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT": "1"})
    @mock.patch("arpia_hunt.enrichment.search_exploitdb")
    @mock.patch("arpia_hunt.enrichment.fetch_vulners_cve")
    @mock.patch("arpia_hunt.enrichment.fetch_nvd_cve")
    def test_enrich_finding_generates_automatic_recommendations(self, mock_nvd, mock_vulners, mock_exploit):
        attack_tactic = AttackTactic.objects.create(
            id="TA0001",
            name="Initial Access",
            order=1,
        )
        attack_technique = AttackTechnique.objects.create(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=attack_tactic,
        )
        CveAttackTechnique.objects.create(
            cve="CVE-2024-9999",
            technique=attack_technique,
            source=CveAttackTechnique.Source.HEURISTIC,
            confidence=CveAttackTechnique.Confidence.HIGH,
            rationale="Exploit público conhecido.",
        )

        finding = self._create_finding()

        mock_nvd.return_value = load_json_fixture("nvd_cve.json")
        mock_vulners.return_value = load_json_fixture("vulners_cve.json")
        mock_exploit.return_value = load_json_fixture("exploitdb_results.json")

        records, changed = enrich_finding(finding, enable_remote=True, force_refresh=True)
        self.assertTrue(changed)

        recs = list(
            finding.recommendations.filter(
                generated_by=HuntRecommendation.Generator.AUTOMATION
            ).order_by("recommendation_type")
        )
        self.assertEqual(len(recs), 2)
        self.assertEqual({rec.recommendation_type for rec in recs}, {"blue", "red"})
        self.assertTrue(all(rec.technique_id == "T1190" for rec in recs))
        self.assertEqual(recs[0].confidence, CveAttackTechnique.Confidence.HIGH)
        self.assertIn("technique:T1190", recs[0].tags)

    @mock.patch.dict(os.environ, {"ARPIA_HUNT_ENABLE_REMOTE_ENRICHMENT": "1"})
    @mock.patch("arpia_hunt.enrichment.search_exploitdb")
    @mock.patch("arpia_hunt.enrichment.fetch_vulners_cve")
    @mock.patch("arpia_hunt.enrichment.fetch_nvd_cve")
    def test_hunt_enrich_command_reprocesses_findings(self, mock_nvd, mock_vulners, mock_exploit):
        finding = self._create_finding()
        nvd_payload = load_json_fixture("nvd_cve.json")
        vulners_payload = load_json_fixture("vulners_cve.json")
        mock_nvd.return_value = copy.deepcopy(nvd_payload)
        mock_vulners.return_value = copy.deepcopy(vulners_payload)
        mock_exploit.return_value = {"RESULTS_EXPLOIT": []}

        call_command("hunt_enrich", "--limit", "1")
        finding.refresh_from_db()
        self.assertEqual(finding.profile_version, 1)

        nvd_updated = copy.deepcopy(nvd_payload)
        metrics = nvd_updated["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]
        metrics["baseScore"] = 8.0
        references = nvd_updated["vulnerabilities"][0]["cve"]["references"]["reference_data"]
        references.append({"url": "https://nvd.example/ref2"})
        mock_nvd.return_value = nvd_updated

        vulners_updated = copy.deepcopy(vulners_payload)
        vulners_updated["data"]["documents"].append(
            {"id": "EXP-2", "title": "Exploit 2", "href": "https://vulners.example/2"}
        )
        mock_vulners.return_value = vulners_updated

        call_command("hunt_enrich", "--limit", "1", "--force")
        finding.refresh_from_db()
        self.assertEqual(finding.profile_version, 2)
        self.assertGreaterEqual(HuntFindingSnapshot.objects.filter(finding=finding).count(), 2)
        self.assertTrue(LogEntry.objects.filter(event_type="hunt.enrichment.batch").exists())


class SchedulerCommandTests(TestCase):
    def test_hunt_schedule_preview_logs_event(self):
        out = StringIO()
        call_command("hunt_schedule", stdout=out, stderr=StringIO())

        content = out.getvalue().strip().splitlines()
        self.assertGreaterEqual(len(content), 2)
        self.assertTrue(content[0].startswith("*/30"))
        self.assertTrue(LogEntry.objects.filter(event_type="hunt.scheduler.preview").exists())


class AttackMappingTests(TestCase):
    def test_attack_catalog_fixture_loaddata(self):
        fixture_path = str(FIXTURE_DIR / "attack_catalog.json")
        call_command("loaddata", fixture_path, verbosity=0)
        self.assertTrue(AttackTactic.objects.filter(pk="TA0001").exists())
        self.assertTrue(AttackTechnique.objects.filter(pk="T1190").exists())

    def test_import_attack_catalog_command(self):
        fixture_path = str(FIXTURE_DIR / "attack_catalog.json")
        call_command("import_attack_catalog", "--from-file", fixture_path)
        self.assertTrue(AttackTactic.objects.filter(pk="TA0001").exists())
        self.assertTrue(AttackTechnique.objects.filter(pk="T1190").exists())

        def test_sync_recommendations_removes_obsolete_entries(self):
            tactic = AttackTactic.objects.create(id="TA0001", name="Initial Access", order=1)
            technique = AttackTechnique.objects.create(id="T1190", name="Exploit Public-Facing Application", tactic=tactic)
            mapping = CveAttackTechnique.objects.create(
                cve="CVE-2024-9999",
                technique=technique,
                source=CveAttackTechnique.Source.DATASET,
                confidence=CveAttackTechnique.Confidence.MEDIUM,
            )
            enrichment = HuntEnrichment.objects.create(
                cve="CVE-2024-9999",
                source=HuntEnrichment.Source.NVD,
                status=HuntEnrichment.Status.FRESH,
                payload={},
            )
            user_model = get_user_model()
            user = user_model.objects.create_user("recommend", "recommend@example.com", "hunter")
            project = Project.objects.create(owner=user, name="Projeto Rec", slug="projeto-rec")
            session = VulnScanSession.objects.create(project=project, owner=user, title="Sessão Vuln")
            vuln = VulnerabilityFinding.objects.create(
                session=session,
                title="Exploit público",
                severity=VulnerabilityFinding.Severity.HIGH,
                status=VulnerabilityFinding.Status.OPEN,
                host="10.0.0.1",
                service="http",
                port=80,
                protocol="tcp",
                cve="CVE-2024-9999",
            )
            finding = HuntFinding.objects.create(
                project=project,
                vulnerability=vuln,
                vuln_session=session,
                cve=vuln.cve,
                summary=vuln.summary,
                severity=vuln.severity,
            )

            sync_recommendations_for_finding(
                finding,
                {
                    HuntEnrichment.Source.NVD: enrichment,
                },
            )
            self.assertEqual(
                finding.recommendations.filter(generated_by=HuntRecommendation.Generator.AUTOMATION).count(),
                2,
            )

            mapping.delete()
            sync_recommendations_for_finding(
                finding,
                {
                    HuntEnrichment.Source.NVD: enrichment,
                },
            )
            self.assertEqual(
                finding.recommendations.filter(generated_by=HuntRecommendation.Generator.AUTOMATION).count(),
                0,
            )

    def test_cve_attack_technique_unique_constraint(self):
        fixture = load_json_fixture("attack_mapping.json")
        tactic_data = fixture["tactic"]
        technique_data = fixture["technique"]
        mapping_data = fixture["mapping"]

        tactic = AttackTactic.objects.create(
            id=tactic_data["id"],
            name=tactic_data["name"],
            short_description=tactic_data.get("short_description", ""),
            matrix=tactic_data.get("matrix", AttackTactic.Matrix.ENTERPRISE),
            order=tactic_data.get("order", 0),
        )

        technique = AttackTechnique.objects.create(
            id=technique_data["id"],
            name=technique_data["name"],
            description=technique_data.get("description", ""),
            is_subtechnique=technique_data.get("is_subtechnique", False),
            tactic=tactic,
            platforms=technique_data.get("platforms", []),
            datasources=technique_data.get("datasources", []),
            external_references=technique_data.get("external_references", []),
            version=technique_data.get("version", ""),
        )

        CveAttackTechnique.objects.create(
            cve=mapping_data["cve"],
            technique=technique,
            source=mapping_data.get("source", CveAttackTechnique.Source.HEURISTIC),
            confidence=mapping_data.get("confidence", CveAttackTechnique.Confidence.MEDIUM),
            rationale=mapping_data.get("rationale", ""),
        )

        with self.assertRaises(IntegrityError):
            CveAttackTechnique.objects.create(
                cve=mapping_data["cve"],
                technique=technique,
                source=mapping_data.get("source", CveAttackTechnique.Source.HEURISTIC),
                confidence=mapping_data.get("confidence", CveAttackTechnique.Confidence.MEDIUM),
                rationale="duplicated",
            )

    def test_hunt_recommendation_links_finding_and_enrichment(self):
        fixture = load_json_fixture("attack_mapping.json")
        tactic = AttackTactic.objects.create(
            id="TA0001",
            name="Initial Access",
            order=1,
        )
        technique = AttackTechnique.objects.create(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=tactic,
        )

        user_model = get_user_model()
        user = user_model.objects.create_user("attck", "attck@example.com", "hunter")
        project = Project.objects.create(owner=user, name="Projeto ATT&CK", slug="projeto-attck")
        session = VulnScanSession.objects.create(project=project, owner=user, title="Sessão Vuln")
        vuln = VulnerabilityFinding.objects.create(
            session=session,
            title="Exploit público",
            summary="Serviço exposto com exploit disponível.",
            severity=VulnerabilityFinding.Severity.HIGH,
            status=VulnerabilityFinding.Status.OPEN,
            host="10.0.0.1",
            service="http",
            port=80,
            protocol="tcp",
            cve=fixture["mapping"]["cve"],
        )
        finding = HuntFinding.objects.create(
            project=project,
            vulnerability=vuln,
            vuln_session=session,
            cve=vuln.cve,
            summary=vuln.summary,
            severity=vuln.severity,
        )
        enrichment = HuntEnrichment.objects.create(
            cve=vuln.cve,
            source=HuntEnrichment.Source.NVD,
            status=HuntEnrichment.Status.FRESH,
            payload={"references": ["https://nvd.example"]},
        )

        recommendation = HuntRecommendation.objects.create(
            finding=finding,
            technique=technique,
            recommendation_type=HuntRecommendation.Type.BLUE,
            title="Aplicar correção",
            summary="Aplicar patch fornecido pelo vendor.",
            confidence=CveAttackTechnique.Confidence.HIGH,
            evidence={"cve": vuln.cve},
            tags=["patch", "mitigation"],
            generated_by=HuntRecommendation.Generator.AUTOMATION,
            source_enrichment=enrichment,
        )

        self.assertEqual(finding.recommendations.count(), 1)
        self.assertEqual(recommendation.technique, technique)
        self.assertEqual(recommendation.source_enrichment, enrichment)
        self.assertIn("cve", recommendation.evidence)
