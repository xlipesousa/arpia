from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase
from django.urls import reverse

from arpia_core.models import Project
from arpia_scan.models import ScanSession
from .views import ReportLandingView


class ReportModuleTests(TestCase):
	def setUp(self):
		self.owner = get_user_model().objects.create_user(
			username="reporter",
			email="reporter@example.com",
			password="pass1234",
		)
		self.guest = get_user_model().objects.create_user(
			username="guest",
			email="guest@example.com",
			password="pass1234",
		)
		self.project = Project.objects.create(owner=self.owner, name="Projeto Relatório", slug="projeto-relatorio")
		self.session = ScanSession.objects.create(project=self.project, owner=self.owner, title="Sessão relatório")
		self.snapshot = {
			"version": 1,
			"timing": {
				"started_at": "2025-10-15T10:00:00+00:00",
				"finished_at": "2025-10-15T10:10:00+00:00",
				"duration_seconds": 600,
			},
			"stats": {
				"total_tasks": 3,
				"completed_tasks": 2,
				"failed_tasks": 1,
				"status_counts": {"completed": 2, "failed": 1},
				"total_findings": 2,
				"open_ports": 4,
				"services_count": 2,
			},
			"timeline": [
				{
					"label": "Descoberta",
					"kind": "discovery",
					"status": "completed",
					"started_at": "2025-10-15T10:00:00+00:00",
					"finished_at": "2025-10-15T10:03:00+00:00",
					"duration_seconds": 180,
				},
				{
					"label": "Scan Nmap",
					"kind": "scan",
					"status": "failed",
					"started_at": "2025-10-15T10:04:00+00:00",
					"finished_at": "2025-10-15T10:10:00+00:00",
					"duration_seconds": 360,
				},
			],
			"tasks": [
				{
					"id": 1,
					"name": "Descoberta",
					"kind": "discovery_rustscan",
					"status": "completed",
					"status_display": "Concluído",
					"started_at": "2025-10-15T10:00:00+00:00",
					"finished_at": "2025-10-15T10:03:00+00:00",
				}
			],
			"insights": [
				{"level": "info", "message": "2 host(s) com portas abertas."},
				{"level": "warning", "message": "1 tarefa falhou durante o scan."},
			],
			"targets": {
				"hosts_count": 2,
				"open_ports": 4,
				"configured_hosts": ["10.0.0.1"],
				"configured_ports": ["22", "80"],
				"hosts": [
					{
						"host": "10.0.0.5",
						"hostname": "srv-app",
						"severity": "medium",
						"ports": [
							{"port": 80, "protocol": "tcp", "service": "http", "severity": "medium"},
							{"port": 443, "protocol": "tcp", "service": "https", "severity": "low"},
						],
					}
				],
			},
			"services": {
				"count": 2,
				"items": [
					{"service": "http", "occurrences": [{"host": "10.0.0.5", "port": 80}]},
					{"service": "https", "occurrences": [{"host": "10.0.0.5", "port": 443}]},
				],
			},
			"findings": [
				{
					"id": 101,
					"kind": "summary",
					"kind_display": "Resumo",
					"title": "Resumo executivo",
					"summary": "Visão geral do scan",
					"severity": "low",
				}
			],
			"summary": {
				"message": "Scan parcial devido à falha na etapa Nmap.",
			},
		}
		self.session.report_snapshot = self.snapshot
		self.session.save(update_fields=["report_snapshot"])
		self.factory = RequestFactory()

	def test_landing_requires_login(self):
		url = reverse("arpia_report:report_home")
		response = self.client.get(url)
		self.assertEqual(response.status_code, 302)
		self.assertIn("/login/", response.url)

	def test_landing_provides_enriched_context(self):
		report_url = reverse("arpia_report:report_home")
		request = self.factory.get(report_url, {"session": str(self.session.pk)})
		request.user = self.owner
		view = ReportLandingView()
		view.request = request
		view.args = ()
		view.kwargs = {}
		context = view.get_context_data()
		self.assertTrue(context["has_report"])
		self.assertIn("status_chart", context)
		status_chart = context["status_chart"]
		self.assertEqual(status_chart[0]["count"], 2)
		self.assertIn("report_highlights", context)
		highlights = context["report_highlights"]
		self.assertGreaterEqual(len(highlights), 1)
		self.assertIn("report_json", context)

	def test_landing_without_snapshot_marks_empty_state(self):
		empty_session = ScanSession.objects.create(project=self.project, owner=self.owner, title="Sem snapshot")
		report_url = reverse("arpia_report:report_home")
		request = self.factory.get(report_url, {"session": str(empty_session.pk)})
		request.user = self.owner
		view = ReportLandingView()
		view.request = request
		view.args = ()
		view.kwargs = {}
		context = view.get_context_data()
		self.assertFalse(context["has_report"])

	def test_api_requires_authentication(self):
		url = reverse("arpia_report:api_session_report", args=[self.session.pk])
		response = self.client.get(url)
		self.assertEqual(response.status_code, 302)
		self.assertIn("/login/", response.url)

	def test_api_blocks_unauthorized_user(self):
		self.client.login(username="guest", password="pass1234")
		url = reverse("arpia_report:api_session_report", args=[self.session.pk])
		response = self.client.get(url)
		self.assertEqual(response.status_code, 403)

	def test_api_returns_report_payload(self):
		self.client.login(username="reporter", password="pass1234")
		url = reverse("arpia_report:api_session_report", args=[self.session.pk])
		response = self.client.get(url)
		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertEqual(payload["session"]["id"], str(self.session.pk))
		self.assertEqual(payload["report"]["stats"]["total_tasks"], 3)
