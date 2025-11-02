from decimal import Decimal
from typing import Sequence

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from arpia_core.models import Project
from arpia_hunt.models import (
    AttackTactic,
    AttackTechnique,
    CveAttackTechnique,
    HuntFinding,
    HuntRecommendation,
)
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession


class HuntApiViewTests(APITestCase):
    maxDiff = None

    def setUp(self):
        user_model = get_user_model()
        self.user = user_model.objects.create_user("apiuser", "api@example.com", "hunter")
        self.client.force_authenticate(user=self.user)

        self.project = Project.objects.create(owner=self.user, name="Projeto API", slug="projeto-api")
        self.other_project = Project.objects.create(owner=self.user, name="Projeto Extra", slug="projeto-extra")

        self.session = VulnScanSession.objects.create(project=self.project, owner=self.user, title="Sessão API")
        self.other_session = VulnScanSession.objects.create(project=self.other_project, owner=self.user, title="Sessão Extra")

        self.vuln = VulnerabilityFinding.objects.create(
            session=self.session,
            title="Apache Remote Execution",
            summary="Execução remota crítica em Apache HTTPD",
            severity=VulnerabilityFinding.Severity.CRITICAL,
            status=VulnerabilityFinding.Status.OPEN,
            host="10.0.0.5",
            service="http",
            port=80,
            protocol="tcp",
            cve="CVE-2024-4242",
            cvss_score=Decimal("9.8"),
        )

        self.finding = HuntFinding.objects.create(
            project=self.project,
            vulnerability=self.vuln,
            vuln_session=self.session,
            cve=self.vuln.cve,
            summary=self.vuln.summary,
            severity=self.vuln.severity,
            detected_at=timezone.now(),
            blue_profile={"summary": "Aplicar correções oficiais e reforçar WAF."},
            red_profile={"exploits": [{"title": "PoC pública", "source": "ExploitDB"}]},
            profile_version=1,
            last_profiled_at=timezone.now(),
        )

        self.tactic = AttackTactic.objects.create(id="TA0001", name="Initial Access", order=1)
        self.technique = AttackTechnique.objects.create(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=self.tactic,
        )

        self.mapping = CveAttackTechnique.objects.create(
            cve=self.finding.cve,
            technique=self.technique,
            source=CveAttackTechnique.Source.HEURISTIC,
            confidence=CveAttackTechnique.Confidence.HIGH,
            rationale="Resumo menciona RCE público.",
        )

        self.blue_rec = HuntRecommendation.objects.create(
            finding=self.finding,
            technique=self.technique,
            recommendation_type=HuntRecommendation.Type.BLUE,
            title="Aplicar atualizações críticas",
            summary="Aplique o patch oficial e ajuste regras de firewall.",
            confidence=CveAttackTechnique.Confidence.HIGH,
            generated_by=HuntRecommendation.Generator.AUTOMATION,
            tags=[f"technique:{self.technique.id}", "strategy:mitigate"],
            confidence_note="Validada contra relatório de pentest interno.",
            playbook_slug="blue-hardening",
        )
        self.red_rec = HuntRecommendation.objects.create(
            finding=self.finding,
            technique=self.technique,
            recommendation_type=HuntRecommendation.Type.RED,
            title="Simular exploração externa",
            summary="Reproduza o exploit para validar monitoramento.",
            confidence=CveAttackTechnique.Confidence.MEDIUM,
            generated_by=HuntRecommendation.Generator.ANALYST,
            tags=["strategy:simulate"],
            playbook_slug="",
        )

        # Recomendações adicionais para testar filtros combinados
        other_vuln = VulnerabilityFinding.objects.create(
            session=self.other_session,
            title="Tomcat misconfig",
            summary="Exposição de painel gerencial Tomcat",
            severity=VulnerabilityFinding.Severity.HIGH,
            status=VulnerabilityFinding.Status.OPEN,
            host="10.0.0.9",
            service="http",
            port=8080,
            protocol="tcp",
            cve="CVE-2024-9999",
            cvss_score=Decimal("7.5"),
        )
        other_finding = HuntFinding.objects.create(
            project=self.other_project,
            vulnerability=other_vuln,
            vuln_session=self.other_session,
            cve=other_vuln.cve,
            summary=other_vuln.summary,
            severity=other_vuln.severity,
            detected_at=timezone.now(),
            profile_version=0,
        )
        HuntRecommendation.objects.create(
            finding=other_finding,
            recommendation_type=HuntRecommendation.Type.BLUE,
            title="Restringir painel",
            summary="Limite o acesso ao painel Tomcat",
            confidence=CveAttackTechnique.Confidence.LOW,
            generated_by=HuntRecommendation.Generator.AUTOMATION,
        )

    @override_settings(ARPIA_HUNT_API_BETA=False)
    def test_feature_flag_blocks_access(self):
        response = self.client.get(reverse("hunt-finding-list"))
        self.assertEqual(response.status_code, 404)

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_findings_list_returns_counts_and_heuristics(self):
        response = self.client.get(reverse("hunt-finding-list"))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertGreater(len(payload["results"]), 0)
        item = payload["results"][0]
        self.assertEqual(item["recommendation_counts"], {"total": 2, "blue": 1, "red": 1})
        technique_ids = {heur["technique_id"] for heur in item["applied_heuristics"]}
        self.assertIn(self.technique.id, technique_ids)

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_profiles_action_embeds_recommendations(self):
        response = self.client.get(reverse("hunt-finding-profiles", args=[self.finding.id]))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["finding_id"], str(self.finding.id))
        self.assertEqual(payload["recommendation_counts"], {"total": 2, "blue": 1, "red": 1})
        rec_payload = payload["recommendations"][0]
        self.assertIn("confidence_note", rec_payload)
        self.assertIn("playbook_slug", rec_payload)

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_recommendations_list_supports_combined_filters(self):
        response = self.client.get(
            reverse("hunt-recommendation-list"),
            {
                "project": ",".join([str(self.project.id), str(self.other_project.id)]),
                "confidence": "high,medium",
                "type": "blue,red",
            },
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        returned_projects = {item["project_id"] for item in payload["results"]}
        self.assertIn(str(self.project.id), returned_projects)
        # medium rec belongs to main project only
        confidences = {item["confidence"] for item in payload["results"]}
        self.assertTrue({"high", "medium"}.issubset(confidences))

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_recommendation_detail_includes_new_optional_fields(self):
        response = self.client.get(reverse("hunt-recommendation-detail", args=[self.blue_rec.id]))
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["id"], str(self.blue_rec.id))
        self.assertEqual(payload["confidence_note"], "Validada contra relatório de pentest interno.")
        self.assertEqual(payload["playbook_slug"], "blue-hardening")
        self.assertEqual(payload["generated_by"], HuntRecommendation.Generator.AUTOMATION)
        self.assertIsNone(payload["source_enrichment_id"])

        # Ensure heuristics are embedded in detail payload
        heuristics: Sequence[dict[str, object]] = payload["heuristics"]
        self.assertGreater(len(heuristics), 0)
        technique_ids = {item["technique_id"] for item in heuristics}
        self.assertIn(self.technique.id, technique_ids)

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_recommendations_search_filter(self):
        response = self.client.get(
            reverse("hunt-recommendation-list"),
            {"search": "exploração"},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        titles = {item["title"] for item in payload["results"]}
        self.assertIn("Simular exploração externa", titles)

    @override_settings(ARPIA_HUNT_API_BETA=True)
    def test_recommendations_support_generator_filter(self):
        response = self.client.get(
            reverse("hunt-recommendation-list"),
            {"generated_by": HuntRecommendation.Generator.ANALYST},
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        generators = {item["generated_by"] for item in payload["results"]}
        self.assertEqual(generators, {HuntRecommendation.Generator.ANALYST})

        response_multi = self.client.get(
            reverse("hunt-recommendation-list"),
            {"generated_by": ",".join([HuntRecommendation.Generator.ANALYST, HuntRecommendation.Generator.AUTOMATION])},
        )
        self.assertEqual(response_multi.status_code, 200)
        payload_multi = response_multi.json()
        self.assertGreaterEqual(len(payload_multi["results"]), 2)
        generator_values = {item["generated_by"] for item in payload_multi["results"]}
        self.assertTrue({HuntRecommendation.Generator.ANALYST, HuntRecommendation.Generator.AUTOMATION}.issubset(generator_values))
