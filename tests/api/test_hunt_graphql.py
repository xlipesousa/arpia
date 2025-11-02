from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from arpia_core.models import Project
from arpia_hunt.models import (
    AttackTactic,
    AttackTechnique,
    CveAttackTechnique,
    HuntFinding,
    HuntRecommendation,
)
from arpia_hunt.services import synchronize_findings
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession


@override_settings(ARPIA_HUNT_API_BETA=True)
class HuntGraphQLTests(TestCase):
    maxDiff = None

    def setUp(self):
        user_model = get_user_model()
        self.password = "hunter"
        self.user = user_model.objects.create_user("graphql", "graphql@example.com", self.password)
        self.project = Project.objects.create(owner=self.user, name="Projeto GraphQL", slug="projeto-graphql")
        self.session = VulnScanSession.objects.create(project=self.project, owner=self.user, title="Sessão GraphQL")
        self.secondary_project = Project.objects.create(
            owner=self.user,
            name="Projeto Complementar",
            slug="projeto-complementar",
        )
        self.secondary_session = VulnScanSession.objects.create(
            project=self.secondary_project,
            owner=self.user,
            title="Sessão Secundária",
        )

        primary_vuln = VulnerabilityFinding.objects.create(
            session=self.session,
            title="Apache HTTPD outdated",
            summary="Servidor Apache vulnerável à execução remota.",
            severity=VulnerabilityFinding.Severity.HIGH,
            status=VulnerabilityFinding.Status.OPEN,
            host="192.168.1.10",
            service="http",
            port=80,
            protocol="tcp",
            cve="CVE-2024-9999",
            cvss_score=Decimal("8.5"),
        )
        secondary_vuln = VulnerabilityFinding.objects.create(
            session=self.secondary_session,
            title="OpenSSH default config",
            summary="Configuração padrão sem endurecimento.",
            severity=VulnerabilityFinding.Severity.MEDIUM,
            status=VulnerabilityFinding.Status.OPEN,
            host="10.0.0.5",
            service="ssh",
            port=22,
            protocol="tcp",
            cve="CVE-2023-4242",
            cvss_score=Decimal("6.4"),
        )
        synchronize_findings()

        self.finding = HuntFinding.objects.get(vulnerability=primary_vuln)
        self.secondary_finding = HuntFinding.objects.get(vulnerability=secondary_vuln)
        now = timezone.now()
        self.finding.blue_profile = {"summary": "Mitigações priorizadas."}
        self.finding.red_profile = {"summary": "Caminhos ofensivos."}
        self.finding.profile_version = 2
        self.finding.last_profiled_at = now
        self.finding.save(update_fields=["blue_profile", "red_profile", "profile_version", "last_profiled_at", "updated_at"])

        self.secondary_finding.blue_profile = {"summary": "Mitigação alternativa."}
        self.secondary_finding.red_profile = {"summary": "Caminhos alternativos."}
        self.secondary_finding.profile_version = 1
        self.secondary_finding.last_profiled_at = now - timedelta(minutes=30)
        self.secondary_finding.save(
            update_fields=["blue_profile", "red_profile", "profile_version", "last_profiled_at", "updated_at"]
        )

        self.tactic = AttackTactic.objects.create(id="TA0001", name="Initial Access", order=1)
        self.secondary_tactic = AttackTactic.objects.create(id="TA0002", name="Execution", order=2)
        self.technique = AttackTechnique.objects.create(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic=self.tactic,
        )
        self.secondary_technique = AttackTechnique.objects.create(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic=self.secondary_tactic,
        )
        CveAttackTechnique.objects.create(
            cve=self.finding.cve,
            technique=self.technique,
            source=CveAttackTechnique.Source.HEURISTIC,
            confidence=CveAttackTechnique.Confidence.HIGH,
            rationale="Resumo menciona RCE público.",
        )
        CveAttackTechnique.objects.create(
            cve=self.secondary_finding.cve,
            technique=self.secondary_technique,
            source=CveAttackTechnique.Source.DATASET,
            confidence=CveAttackTechnique.Confidence.MEDIUM,
            rationale="Correlação via heurística secundária.",
        )
        self.blue_recommendation = HuntRecommendation.objects.create(
            finding=self.finding,
            technique=self.technique,
            recommendation_type=HuntRecommendation.Type.BLUE,
            title="Aplicar mitigação",
            summary="Atualizar serviço.",
            confidence=CveAttackTechnique.Confidence.HIGH,
            generated_by=HuntRecommendation.Generator.AUTOMATION,
        )
        self.red_recommendation = HuntRecommendation.objects.create(
            finding=self.finding,
            technique=self.technique,
            recommendation_type=HuntRecommendation.Type.RED,
            title="Simular exploração",
            summary="Executar playbook ofensivo.",
            confidence=CveAttackTechnique.Confidence.MEDIUM,
            generated_by=HuntRecommendation.Generator.ANALYST,
        )
        self.secondary_recommendation = HuntRecommendation.objects.create(
            finding=self.secondary_finding,
            technique=self.secondary_technique,
            recommendation_type=HuntRecommendation.Type.RED,
            title="Reforçar monitoração",
            summary="Validar vetores alternativos.",
            confidence=CveAttackTechnique.Confidence.MEDIUM,
            generated_by=HuntRecommendation.Generator.AUTOMATION,
        )

        self.client.login(username=self.user.username, password=self.password)
        self.graphql_url = reverse("hunt-graphql")

    def _execute_graphql(self, query: str, variables: dict[str, object] | None = None) -> dict:
        response = self.client.post(
            self.graphql_url,
            data=json.dumps({"query": query, "variables": variables or {}}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("errors", payload)
        return payload["data"]

    def test_hunt_findings_query_returns_profiles(self):
        query = """
        query HuntFindings($projectIds: [UUID!]) {
          huntFindings(projectIds: $projectIds, limit: 10) {
            totalCount
            results {
              id
              projectId
              projectName
              vulnerabilityTitle
              cve
              recommendationCounts {
                total
                blue
                red
              }
              appliedHeuristics {
                techniqueId
                source
                confidence
                technique {
                  id
                  name
                  tacticId
                  tacticName
                }
              }
            }
          }
        }
        """
        variables = {"projectIds": [str(self.project.pk)]}
        response = self.client.post(
            self.graphql_url,
            data=json.dumps({"query": query, "variables": variables}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("errors", payload)
        data = payload["data"]["huntFindings"]
        self.assertEqual(data["totalCount"], 1)
        result = data["results"][0]
        self.assertEqual(result["cve"], self.finding.cve)
        self.assertEqual(result["recommendationCounts"], {"total": 2, "blue": 1, "red": 1})
        heuristics = result["appliedHeuristics"]
        self.assertEqual(len(heuristics), 1)
        self.assertEqual(heuristics[0]["techniqueId"], self.technique.id)
        self.assertEqual(heuristics[0]["technique"]["tacticId"], self.tactic.id)

    def test_hunt_findings_query_supports_pagination(self):
        query = """
        query PaginatedFindings($limit: Int, $offset: Int) {
          huntFindings(limit: $limit, offset: $offset) {
            totalCount
            results {
              id
              cve
            }
          }
        }
        """
        first_page = self._execute_graphql(query, {"limit": 1, "offset": 0})["huntFindings"]
        self.assertEqual(first_page["totalCount"], 2)
        self.assertEqual(len(first_page["results"]), 1)
        self.assertEqual(first_page["results"][0]["id"], str(self.finding.pk))

        second_page = self._execute_graphql(query, {"limit": 1, "offset": 1})["huntFindings"]
        self.assertEqual(second_page["totalCount"], 2)
        self.assertEqual(len(second_page["results"]), 1)
        self.assertEqual(second_page["results"][0]["id"], str(self.secondary_finding.pk))

    def test_hunt_recommendations_query_returns_detail(self):
        query = """
        query HuntRecommendations($findingIds: [UUID!]) {
          huntRecommendations(findingIds: $findingIds) {
            totalCount
            results {
              id
              recommendationType
              confidence
              generatedBy
              finding {
                id
                cve
                severity
              }
              heuristics {
                techniqueId
                confidence
              }
            }
          }
        }
        """
        variables = {"findingIds": [str(self.finding.pk)]}
        response = self.client.post(
            self.graphql_url,
            data=json.dumps({"query": query, "variables": variables}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertNotIn("errors", payload)
        data = payload["data"]["huntRecommendations"]
        self.assertEqual(data["totalCount"], 2)
        rec_ids = {item["recommendationType"] for item in data["results"]}
        self.assertSetEqual(rec_ids, {"blue", "red"})
        blue_rec = next(item for item in data["results"] if item["recommendationType"] == "blue")
        self.assertEqual(blue_rec["confidence"], CveAttackTechnique.Confidence.HIGH)
        self.assertEqual(blue_rec["finding"]["id"], str(self.finding.pk))
        self.assertEqual(len(blue_rec["heuristics"]), 1)
        self.assertEqual(blue_rec["heuristics"][0]["techniqueId"], self.technique.id)

    def test_hunt_recommendations_query_supports_filters_and_pagination(self):
        query = """
        query FilteredRecommendations(
          $projectIds: [UUID!]
          $types: [String!]
          $generators: [String!]
          $limit: Int
          $offset: Int
        ) {
          huntRecommendations(
            projectIds: $projectIds
            recommendationTypes: $types
            generators: $generators
            limit: $limit
            offset: $offset
          ) {
            totalCount
            results {
              id
              recommendationType
              generatedBy
              finding {
                id
                projectId
              }
            }
          }
        }
        """

        primary_results = self._execute_graphql(query, {"projectIds": [str(self.project.pk)]})["huntRecommendations"]
        self.assertEqual(primary_results["totalCount"], 2)
        self.assertTrue(
            all(item["finding"]["id"] == str(self.finding.pk) for item in primary_results["results"])
        )

        secondary_results = self._execute_graphql(query, {"projectIds": [str(self.secondary_project.pk)]})[
            "huntRecommendations"
        ]
        self.assertEqual(secondary_results["totalCount"], 1)
        self.assertEqual(secondary_results["results"][0]["id"], str(self.secondary_recommendation.pk))

        red_results = self._execute_graphql(query, {"types": ["red"]})["huntRecommendations"]
        self.assertEqual(red_results["totalCount"], 2)
        self.assertTrue(all(item["recommendationType"] == "red" for item in red_results["results"]))

        automation_results = self._execute_graphql(query, {"generators": ["automation"]})["huntRecommendations"]
        self.assertTrue(all(item["generatedBy"] == "automation" for item in automation_results["results"]))
        self.assertSetEqual(
            {item["id"] for item in automation_results["results"]},
            {str(self.blue_recommendation.pk), str(self.secondary_recommendation.pk)},
        )

        second_page = self._execute_graphql(query, {"limit": 1, "offset": 1})["huntRecommendations"]
        self.assertEqual(second_page["totalCount"], 3)
        self.assertEqual(len(second_page["results"]), 1)
        self.assertEqual(second_page["results"][0]["id"], str(self.red_recommendation.pk))