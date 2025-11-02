import os
from datetime import timedelta
from decimal import Decimal
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from arpia_core.models import Project
from django.utils import timezone

from arpia_hunt.models import (
    HuntEnrichment,
    HuntFinding,
    HuntFindingEnrichment,
    HuntFindingSnapshot,
    HuntSyncLog,
)
from arpia_hunt.services import synchronize_findings
from arpia_hunt.enrichment import enrich_cve, enrich_finding
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession
from arpia_log.models import LogEntry


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
        self.assertGreaterEqual(LogEntry.objects.filter(event_type="hunt.sync.completed").count(), 2)


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
    @mock.patch("arpia_hunt.enrichment._fetch_exploitdb")
    @mock.patch("arpia_hunt.enrichment._fetch_vulners")
    @mock.patch("arpia_hunt.enrichment._fetch_nvd")
    def test_enrich_finding_updates_profiles_and_creates_snapshot(self, mock_nvd, mock_vulners, mock_exploit):
        finding = self._create_finding()
        mock_nvd.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                        "references": {"reference_data": [{"url": "https://nvd.example/ref"}]},
                    },
                }
            ]
        }
        mock_vulners.return_value = {
            "data": {"documents": [{"id": "EXP-1", "title": "Exploit 1", "href": "https://vulners.example"}]}
        }
        mock_exploit.return_value = {"RESULTS_EXPLOIT": [{"title": "ExploitDB", "path": "exploits/web/1"}]}

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
    @mock.patch("arpia_hunt.enrichment._fetch_exploitdb")
    @mock.patch("arpia_hunt.enrichment._fetch_vulners")
    @mock.patch("arpia_hunt.enrichment._fetch_nvd")
    def test_hunt_enrich_command_reprocesses_findings(self, mock_nvd, mock_vulners, mock_exploit):
        finding = self._create_finding()
        mock_nvd.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}]},
                        "references": {"reference_data": [{"url": "https://nvd.example/ref"}]},
                    },
                }
            ]
        }
        mock_vulners.return_value = {
            "data": {"documents": [{"id": "EXP-1", "title": "Exploit 1", "href": "https://vulners.example"}]}
        }
        mock_exploit.return_value = {"RESULTS_EXPLOIT": []}

        call_command("hunt_enrich", "--limit", "1")
        finding.refresh_from_db()
        self.assertEqual(finding.profile_version, 1)

        mock_nvd.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.0}}]},
                        "references": {"reference_data": [{"url": "https://nvd.example/ref2"}]},
                    },
                }
            ]
        }
        mock_vulners.return_value = {
            "data": {"documents": [{"id": "EXP-2", "title": "Exploit 2", "href": "https://vulners.example/2"}]}
        }

        call_command("hunt_enrich", "--limit", "1", "--force")
        finding.refresh_from_db()
        self.assertEqual(finding.profile_version, 2)
        self.assertGreaterEqual(HuntFindingSnapshot.objects.filter(finding=finding).count(), 2)
        self.assertTrue(LogEntry.objects.filter(event_type="hunt.enrichment.batch").exists())
