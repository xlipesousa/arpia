import base64
import json
import os
import shutil
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import Mock, patch

import xml.etree.ElementTree as ET

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from arpia_core.models import Project, ProjectMembership
from arpia_scan.models import ScanSession
from arpia_report.services import ReportAggregator

from .models import VulnScanSession, VulnTask, VulnerabilityFinding
from .reporting import MAX_EVIDENCE_LENGTH, upsert_vulnerability_report_entry
from .services import (
	GreenboneCliError,
	GreenboneConfig,
	GreenboneScanExecutor,
	GreenboneCliRunner,
	VulnGreenboneExecutionError,
	VulnScriptExecutionError,
	plan_vulnerability_session,
	run_greenbone_scan,
	run_targeted_nmap_scans,
)


class VulnViewsSmokeTests(TestCase):
	@classmethod
	def setUpTestData(cls):
		user_model = get_user_model()
		cls.owner = user_model.objects.create_user("owner", password="test1234")
		cls.member = user_model.objects.create_user("member", password="test1234")
		cls.other = user_model.objects.create_user("outsider", password="test1234")

		cls.project = Project.objects.create(owner=cls.owner, name="Projeto Vuln", slug="projeto-vuln")
		ProjectMembership.objects.create(project=cls.project, user=cls.member)

		cls.session = VulnScanSession.objects.create(
			project=cls.project,
			owner=cls.owner,
			title="Sessão inicial",
			status=VulnScanSession.Status.COMPLETED,
			report_snapshot={
				"stats": {"total_findings": 1, "critical": 1},
				"insights": [{"level": "info", "message": "Sessão concluída"}],
			},
		)

		cls.task = VulnTask.objects.create(
			session=cls.session,
			order=1,
			kind=VulnTask.Kind.SERVICE_ENUMERATION,
			status=VulnTask.Status.COMPLETED,
			name="Enumeração Nmap",
			progress=100,
			stdout="service nmap output",
		)

		cls.finding = VulnerabilityFinding.objects.create(
			session=cls.session,
			source_task=cls.task,
			cve="CVE-2024-0001",
			title="Shellshock",
			summary="Falha crítica em serviço exposto",
			severity=VulnerabilityFinding.Severity.CRITICAL,
			status=VulnerabilityFinding.Status.OPEN,
			host="10.0.0.5",
			service="http",
			port=80,
			protocol="tcp",
			cvss_score=9.8,
			data={"proof": "curl exploit"},
		)

	def test_dashboard_requires_login(self):
		response = self.client.get(reverse("arpia_vuln:dashboard"))
		self.assertEqual(response.status_code, 302)
		self.assertIn("login", response.headers.get("Location", ""))

	def test_dashboard_renders_for_owner(self):
		self.client.force_login(self.owner)
		response = self.client.get(reverse("arpia_vuln:dashboard"))
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "Gestão de vulnerabilidades")
		self.assertContains(response, self.session.title)
		self.assertContains(response, self.finding.cve)

	def test_dashboard_renders_for_member(self):
		self.client.force_login(self.member)
		response = self.client.get(reverse("arpia_vuln:dashboard"))
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, self.session.title)

	def test_session_detail_requires_membership(self):
		url = reverse("arpia_vuln:session_detail", args=[self.session.pk])

		self.client.force_login(self.other)
		response = self.client.get(url)
		self.assertEqual(response.status_code, 404)

		self.client.force_login(self.member)
		response = self.client.get(url)
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, self.finding.title)

	def test_session_report_preview_view(self):
		url = reverse("arpia_vuln:session_report_preview", args=[self.session.pk])
		self.client.force_login(self.owner)
		response = self.client.get(url)
		self.assertEqual(response.status_code, 200)
		self.assertContains(response, "Relatório da sessão")
		self.assertContains(response, "Achados consolidados")
		self.assertContains(response, self.finding.title)
		self.assertContains(response, self.finding.cve)

	def test_dashboard_api_returns_snapshot(self):
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_dashboard_snapshot")
		response = self.client.get(url, {"project": str(self.project.pk)})
		self.assertEqual(response.status_code, 200)
		payload = response.json()
		self.assertIn("metrics", payload)
		self.assertEqual(payload["metrics"].get("recent_sessions"), 1)
		self.assertEqual(payload["metrics"].get("recent_findings"), 1)
		self.assertIn("links", payload)
		self.assertIn("scan_dashboard", payload["links"])

	def test_dashboard_api_blocks_unknown_project(self):
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_dashboard_snapshot")
		response = self.client.get(url, {"project": "00000000-0000-0000-0000-000000000000"})
		self.assertEqual(response.status_code, 404)


class VulnServicesTests(TestCase):
	def setUp(self):
		user_model = get_user_model()
		self.owner = user_model.objects.create_user("operator", password="test1234")
		self.project = Project.objects.create(
			owner=self.owner,
			name="Projeto Teste Vuln",
			slug="projeto-teste-vuln",
			hosts="192.168.0.10",
			networks="192.168.0.0/24",
		)
		self.scan_session = ScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão de descoberta",
			status=ScanSession.Status.COMPLETED,
		)
		self.scan_session.report_snapshot = {
			"targets": {
				"hosts": [
					{
						"host": "192.168.0.10",
						"ports": [
							{"port": 22, "protocol": "tcp", "status": "open", "service": "ssh"},
							{"port": 80, "protocol": "tcp", "status": "open", "service": "http"},
						],
					}
				],
				"open_ports": 2,
			},
		}
		self.scan_session.save(update_fields=["report_snapshot"])

		self.vuln_session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão consolidada",
			status=VulnScanSession.Status.COMPLETED,
		)
		task = VulnTask.objects.create(
			session=self.vuln_session,
			order=1,
			kind=VulnTask.Kind.SCRIPT,
			status=VulnTask.Status.COMPLETED,
			name="Nmap NSE",
		)
		VulnerabilityFinding.objects.create(
			session=self.vuln_session,
			source_task=task,
			cve="CVE-2025-0001",
			title="Execução remota",
			summary="Falha crítica permitindo execução remota de código",
			severity=VulnerabilityFinding.Severity.CRITICAL,
			status=VulnerabilityFinding.Status.OPEN,
			host="10.10.10.5",
			service="https",
			port=443,
			protocol="tcp",
			cvss_score=9.8,
			cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			data={
				"file_path": "recon/projeto-api-vuln/vuln/report.xml",
				"source_kind": "nmap_targeted_nse",
				"scanner": "nmap",
				"references": ["https://example.com/vuln"],
				"collected_at": timezone.now().isoformat(),
			},
		)
		summary = {
			"total": 1,
			"open_total": 1,
			"by_severity": {
				"critical": 1,
				"high": 0,
				"medium": 0,
				"low": 0,
				"info": 0,
				"unknown": 0,
			},
			"cves": ["CVE-2025-0001"],
			"sources": ["nmap_targeted_nse"],
			"hosts_impacted": 1,
			"max_cvss": 9.8,
			"artifacts": [
				{
					"path": "recon/projeto-api-vuln/vuln/report.xml",
					"source": "nmap_targeted_nse",
				},
			],
			"last_collected_at": timezone.now().isoformat(),
		}
		upsert_vulnerability_report_entry(self.vuln_session, summary)
		self.session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão de teste",
		)
		self.session.source_scan_session = self.scan_session
		self.session.save(update_fields=["source_scan_session"])
		self.temp_dir = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.temp_dir, True)

	@patch("arpia_vuln.services.subprocess.run")
	def test_run_targeted_nmap_scans_success(self, mocked_run):
		mocked_run.side_effect = [
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap targeted scan para 192.168.0.10 (22,80)",
				stderr="",
			),
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap NSE (default,safe,vuln) para 192.168.0.10 (22,80)",
				stderr="",
			),
		]

		tasks = run_targeted_nmap_scans(self.session, triggered_by=self.owner)
		self.session.refresh_from_db()

		self.assertEqual(len(tasks), 2)
		first_task = tasks[0]
		self.assertEqual(first_task.status, VulnTask.Status.COMPLETED)
		self.assertEqual(first_task.parameters.get("unique_ports"), [22, 80])
		self.assertEqual(self.session.status, VulnScanSession.Status.RUNNING)
		targets_snapshot = self.session.targets_snapshot or {}
		self.assertEqual(targets_snapshot.get("unique_tcp_ports"), [22, 80])
		report_snapshot = self.session.report_snapshot or {}
		targeted_runs = report_snapshot.get("targeted_runs", [])
		self.assertEqual(len(targeted_runs), 2)
		self.assertEqual(targets_snapshot.get("script"), "nmap-targeted-nse")
		self.assertEqual(targeted_runs[-1].get("script"), "nmap-targeted-nse")

	def test_plan_session_uses_project_macros_without_scan(self):
		self.project.ports = "22/tcp\n443/tcp"
		self.project.save(update_fields=["ports"])

		session = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão fallback",
			source_scan_session=None,
		)
		session.refresh_from_db()
		snapshot = session.targets_snapshot or {}
		hosts = [item.get("host") for item in snapshot.get("hosts", [])]
		self.assertIn("192.168.0.10", hosts)
		self.assertEqual(snapshot.get("unique_tcp_ports"), [22, 443])
		self.assertEqual(snapshot.get("stats", {}).get("total_hosts"), len(hosts))
		self.assertTrue(snapshot.get("fallback_used"))

	@patch("arpia_vuln.services.subprocess.run")
	def test_targeted_scans_use_macro_fallback(self, mocked_run):
		self.project.ports = "22/tcp\n443/tcp"
		self.project.save(update_fields=["ports"])

		session = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão fallback targeted",
			source_scan_session=None,
		)
		session.refresh_from_db()

		mocked_run.side_effect = [
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap targeted scan para 192.168.0.10 (22,443)",
				stderr="",
			),
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap NSE (default,safe,vuln) para 192.168.0.10 (22,443)",
				stderr="",
			),
		]

		tasks = run_targeted_nmap_scans(session, triggered_by=self.owner)
		session.refresh_from_db()

		self.assertEqual(len(tasks), 2)
		self.assertEqual(tasks[0].parameters.get("unique_ports"), [22, 443])
		snapshot = session.targets_snapshot or {}
		self.assertEqual(snapshot.get("unique_tcp_ports"), [22, 443])
		self.assertEqual(snapshot.get("stats", {}).get("total_hosts"), 1)
		self.assertEqual(snapshot.get("script"), "nmap-targeted-nse")

	@patch("arpia_vuln.services.subprocess.run")
	def test_run_targeted_nmap_scans_failure_sets_status(self, mocked_run):
		mocked_run.return_value = CompletedProcess(
			args=["/bin/bash"],
			returncode=1,
			stdout="",
			stderr="erro na execução",
		)

		with self.assertRaises(VulnScriptExecutionError):
			run_targeted_nmap_scans(self.session, triggered_by=self.owner, include_nse=False)

		self.session.refresh_from_db()
		task = self.session.tasks.first()
		self.assertEqual(self.session.status, VulnScanSession.Status.FAILED)
		self.assertIsNotNone(task)
		self.assertEqual(task.status, VulnTask.Status.FAILED)
		self.assertIn("código 1", self.session.last_error)

	@patch("arpia_vuln.services.GreenboneCliRunner.run")
	@patch("arpia_vuln.services._load_greenbone_config")
	def test_run_greenbone_scan_success(self, mocked_config, mocked_runner_run):
		config = GreenboneConfig(
			mode="tls",
			username="admin",
			password="secret",
			hostname="127.0.0.1",
			port=9390,
			socket_path=None,
			scanner_id="scanner-1",
			scan_config_id="config-1",
			report_format_id="format-1",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=3,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)
		mocked_config.return_value = config

		report_payload = base64.b64encode(
			b"<report><result_count severity='high'>2</result_count></report>"
		).decode()
		mocked_runner_run.side_effect = [
			"<create_target_response id=\"target-1\" status=\"201\"/>",
			"<create_task_response id=\"task-1\" status=\"201\"/>",
			"<start_task_response status=\"202\"><report_id id=\"report-1\">report-1</report_id></start_task_response>",
			"<get_tasks_response status=\"200\"><task id=\"task-1\"><status>Done</status><progress>100</progress><report id=\"report-1\"/></task></get_tasks_response>",
			f"<get_reports_response status=\"200\"><report><content>{report_payload}</content></report></get_reports_response>",
		]

		task = run_greenbone_scan(self.session, triggered_by=self.owner)
		self.session.refresh_from_db()
		task.refresh_from_db()

		self.assertEqual(mocked_runner_run.call_count, 5)
		create_target_xml = mocked_runner_run.call_args_list[0].args[0]
		self.assertIn("<port_list>", create_target_xml)
		self.assertIn("T:22,80", create_target_xml)
		self.assertEqual(task.status, VulnTask.Status.COMPLETED)
		self.assertEqual(self.session.status, VulnScanSession.Status.COMPLETED)
		self.assertEqual(task.parameters.get("status"), "Done")
		self.assertEqual(task.parameters.get("report_id"), "report-1")
		self.assertEqual(task.parameters.get("unique_ports"), [22, 80])
		self.assertEqual(task.parameters.get("port_range"), "T:22,80")
		self.assertIn("report_path", task.parameters)
		report_path = Path(task.parameters["report_path"])
		self.assertTrue(report_path.exists())
		snapshot = self.session.report_snapshot or {}
		last_report = snapshot.get("greenbone_last_report", {})
		self.assertEqual(last_report.get("report_id"), "report-1")
		self.assertEqual(last_report.get("summary", {}).get("status"), "Done")
		self.assertEqual(last_report.get("severity_counts", {}).get("high"), 2)

	@patch("arpia_vuln.services.GreenboneCliRunner.run")
	@patch("arpia_vuln.services._load_greenbone_config")
	def test_run_greenbone_scan_failure_marks_session(self, mocked_config, mocked_runner_run):
		config = GreenboneConfig(
			mode="tls",
			username="admin",
			password="secret",
			hostname="127.0.0.1",
			port=9390,
			socket_path=None,
			scanner_id="scanner-1",
			scan_config_id="config-1",
			report_format_id="format-1",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=1,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)
		mocked_config.return_value = config
		mocked_runner_run.side_effect = GreenboneCliError("falha ao conectar")

		with self.assertRaises(VulnGreenboneExecutionError):
			run_greenbone_scan(self.session, triggered_by=self.owner)

		self.session.refresh_from_db()
		task = self.session.tasks.filter(kind=VulnTask.Kind.GREENBONE_SCAN).first()
		self.assertIsNotNone(task)
		self.assertEqual(task.status, VulnTask.Status.FAILED)
		self.assertEqual(self.session.status, VulnScanSession.Status.FAILED)
		self.assertIn("falha ao conectar", self.session.last_error)

	@patch("arpia_vuln.services.GreenboneScanExecutor._ensure_service_available")
	@patch("arpia_vuln.services._load_greenbone_config")
	def test_run_greenbone_scan_service_unavailable_creates_failed_task(self, mocked_config, mocked_ensure):
		config = GreenboneConfig(
			mode="tls",
			username="admin",
			password="secret",
			hostname="127.0.0.1",
			port=9390,
			socket_path=None,
			scanner_id="scanner-1",
			scan_config_id="config-1",
			report_format_id="format-1",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=1,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)
		mocked_config.return_value = config
		mocked_ensure.side_effect = VulnGreenboneExecutionError("serviço indisponível")

		with self.assertRaises(VulnGreenboneExecutionError):
			run_greenbone_scan(self.session, triggered_by=self.owner)

		self.session.refresh_from_db()
		task = self.session.tasks.filter(kind=VulnTask.Kind.GREENBONE_SCAN).first()
		self.assertIsNotNone(task)
		self.assertEqual(task.status, VulnTask.Status.FAILED)
		self.assertEqual(self.session.status, VulnScanSession.Status.FAILED)
		self.assertIn("serviço indisponível", self.session.last_error)

	@patch("arpia_vuln.services.os.access")
	@patch("arpia_vuln.services.subprocess.run")
	@patch("arpia_vuln.services.shutil.which")
	def test_socket_permission_attempts_fix(self, mocked_which, mocked_run, mocked_access):
		socket_file = self.temp_dir / "gvmd.sock"
		socket_file.write_text("")
		config = GreenboneConfig(
			mode="socket",
			username="admin",
			password="secret",
			hostname="127.0.0.1",
			port=9390,
			socket_path=str(socket_file),
			scanner_id="scanner-1",
			scan_config_id="config-1",
			report_format_id="format-1",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=1,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)
		mocked_access.side_effect = [False, False, True, True]
		mocked_which.side_effect = lambda name: f"/usr/bin/{name}" if name in {"sudo", "setfacl"} else None
		mocked_run.return_value = CompletedProcess(args=[], returncode=0, stdout="", stderr="")

		executor = GreenboneScanExecutor(self.session, triggered_by=self.owner, targets_data={"hosts": []}, auto_finalize=False)
		executor.config = config
		executor._attempt_autostart_greenbone = Mock()

		with self.settings(TESTING=False):
			executor._ensure_service_available()
		self.assertTrue(mocked_run.called)

	@patch("arpia_vuln.services._load_greenbone_config")
	@patch("arpia_vuln.services.subprocess.run")
	@patch("arpia_vuln.services.shutil.which")
	def test_autostart_greenbone_with_sudo_password(self, mocked_which, mocked_run, mocked_load_config):
		mocked_which.side_effect = lambda name: f"/usr/bin/{name}" if name in {"sudo", "gvm-start"} else None
		config = GreenboneConfig(
			mode="tls",
			username=None,
			password=None,
			hostname="127.0.0.1",
			port=9390,
			socket_path=None,
			scanner_id="scanner",
			scan_config_id="config",
			report_format_id="format",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=1,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)
		mocked_load_config.side_effect = [config, config]
		mocked_run.side_effect = [
			CompletedProcess(
				args=["sudo", "-n", "gvm-start"],
				returncode=1,
				stdout="",
				stderr="sudo: a password is required",
			),
			CompletedProcess(
				args=["sudo", "-S", "gvm-start"],
				returncode=0,
				stdout="Greenbone started",
				stderr="",
			),
		]

		session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão retry",
			status=VulnScanSession.Status.FAILED,
		)
		with patch.dict(os.environ, {"ARPIA_GVM_AUTOSTART": "1"}, clear=False):
			with self.settings(TESTING=False, ARPIA_GVM_SUDO_PASSWORD="secr3t"):
				executor = GreenboneScanExecutor(session, triggered_by=self.owner, targets_data={"hosts": []}, auto_finalize=False)
				executor.config = config
				executor._attempt_autostart_greenbone()

		self.assertEqual(mocked_run.call_count, 2)
		self.assertEqual(mocked_run.call_args_list[1].kwargs.get("input"), "secr3t\n")
		self.assertGreaterEqual(mocked_load_config.call_count, 2)

	def test_plan_vulnerability_session_creates_default_playbook(self):
		planned = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão planejada",
			source_scan_session=self.scan_session,
		)
		planned.refresh_from_db()
		self.assertEqual(planned.status, VulnScanSession.Status.PLANNED)
		self.assertTrue(planned.macros_snapshot)
		self.assertIn("PROJECT_NAME", planned.macros_snapshot)
		pipeline = planned.config_snapshot.get("pipeline", [])
		actions = [step.get("action") for step in pipeline]
		self.assertEqual(actions, ["targeted", "greenbone"])
		tasks = list(planned.tasks.order_by("order"))
		self.assertEqual(len(tasks), 3)
		self.assertTrue(all(task.status == VulnTask.Status.PENDING for task in tasks))
		self.assertEqual(tasks[0].parameters.get("playbook_action"), "targeted")
		self.assertEqual(tasks[0].parameters.get("script"), "nmap-targeted-open-ports")
		self.assertEqual(tasks[1].parameters.get("script"), "nmap-targeted-nse")
		self.assertEqual(tasks[-1].parameters.get("playbook_action"), "greenbone")
		target_snapshot = planned.targets_snapshot or {}
		self.assertEqual(target_snapshot.get("unique_tcp_ports"), [22, 80])
		self.assertEqual(target_snapshot.get("stats", {}).get("total_hosts"), 1)

	@patch("arpia_vuln.services.subprocess.run")
	def test_playbook_planned_tasks_are_reused(self, mocked_run):
		mocked_run.side_effect = [
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap targeted scan para 192.168.0.10 (22,80)",
				stderr="",
			),
			CompletedProcess(
				args=["/bin/bash"],
				returncode=0,
				stdout="[INFO] Nmap NSE (default,safe,vuln) para 192.168.0.10 (22,80)",
				stderr="",
			),
		]
		planned = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão planejada",
		)
		task_ids = list(planned.tasks.values_list("id", flat=True))
		self.assertEqual(len(task_ids), 3)
		targeted_ids = list(
			planned.tasks.filter(parameters__playbook_action="targeted").values_list("id", flat=True)
		)
		self.assertEqual(len(targeted_ids), 2)
		self.assertTrue(planned.macros_snapshot)
		tasks = run_targeted_nmap_scans(planned, triggered_by=self.owner)
		planned.refresh_from_db()
		self.assertEqual(mocked_run.call_count, 2)
		self.assertEqual(len(tasks), 2)
		self.assertSetEqual({task.id for task in tasks}, set(targeted_ids))
		self.assertTrue(all(task.status == VulnTask.Status.COMPLETED for task in tasks))
		remaining_pending = list(planned.tasks.filter(status=VulnTask.Status.PENDING))
		self.assertEqual(len(remaining_pending), 1)
		self.assertEqual(
			remaining_pending[0].parameters.get("playbook_action"),
			"greenbone",
		)

	def test_plan_session_without_nse_creates_single_targeted_task(self):
		planned = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão targeted",
			pipeline=[{"action": "targeted", "include_nse": False}],
		)
		tasks = list(planned.tasks.order_by("order"))
		self.assertEqual(len(tasks), 1)
		task = tasks[0]
		self.assertEqual(task.parameters.get("playbook_action"), "targeted")
		self.assertEqual(task.parameters.get("script"), "nmap-targeted-open-ports")
		self.assertEqual(task.kind, VulnTask.Kind.SERVICE_ENUMERATION)


class GreenboneTests(TestCase):
	def setUp(self):
		self.temp_dir = Path(tempfile.mkdtemp())
		self.addCleanup(shutil.rmtree, self.temp_dir, True)
		self.config = GreenboneConfig(
			mode="tls",
			username="admin",
			password="secret",
			hostname="127.0.0.1",
			port=9390,
			socket_path=None,
			scanner_id="scanner-1",
			scan_config_id="config-1",
			report_format_id="format-1",
			report_directory=self.temp_dir,
			poll_interval=0.0,
			max_attempts=3,
			task_timeout=None,
			tool_slug="gvm",
			tool_path="gvm-cli",
		)

	@patch("gvm.protocols.gmp.Gmp")
	@patch("gvm.connections.TLSConnection")
	def test_runner_auth_success(self, mocked_tls, mocked_gmp):
		gmp_mock = Mock()
		gmp_mock.authenticate.return_value = ET.Element("authenticate_response", status="200")
		gmp_mock.is_authenticated.return_value = True
		gmp_mock.send_command.return_value = "<ok/>"
		mocked_gmp.return_value.__enter__.return_value = gmp_mock

		runner = GreenboneCliRunner(self.config)
		result = runner.run("<ping/>", description="ping")

		self.assertEqual(result, "<ok/>")
		gmp_mock.authenticate.assert_called_once_with("admin", "secret")
		gmp_mock.send_command.assert_called_once_with("<ping/>")

	@patch("gvm.protocols.gmp.Gmp")
	@patch("gvm.connections.TLSConnection")
	def test_runner_auth_failure_raises_error(self, mocked_tls, mocked_gmp):
		gmp_mock = Mock()
		gmp_mock.authenticate.return_value = ET.Element(
			"authenticate_response",
			status="401",
			status_text="Invalid credential",
		)
		gmp_mock.is_authenticated.return_value = False
		gmp_mock.send_command.return_value = "<should-not-run/>"
		mocked_gmp.return_value.__enter__.return_value = gmp_mock

		runner = GreenboneCliRunner(self.config)

		with self.assertRaises(GreenboneCliError) as ctx:
			runner.run("<ping/>", description="ping")
		self.assertIn("Falha na autenticação", str(ctx.exception))
		self.assertIn("Invalid credential", str(ctx.exception))
		gmp_mock.send_command.assert_not_called()


class VulnReportingIntegrationTests(TestCase):
	def setUp(self):
		user_model = get_user_model()
		self.owner = user_model.objects.create_user("reporter", password="test1234")
		self.project = Project.objects.create(
			owner=self.owner,
			name="Projeto Relatório Vuln",
			slug="projeto-relatorio-vuln",
		)
		self.session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão consolidada",
			status=VulnScanSession.Status.COMPLETED,
		)
		self.task = VulnTask.objects.create(
			session=self.session,
			order=1,
			kind=VulnTask.Kind.SCRIPT,
			status=VulnTask.Status.COMPLETED,
			name="Nmap NSE",
		)
		self.finding = VulnerabilityFinding.objects.create(
			session=self.session,
			source_task=self.task,
			cve="CVE-2025-0001",
			title="Execução remota",
			summary="Falha crítica permitindo execução remota de código",
			severity=VulnerabilityFinding.Severity.CRITICAL,
			status=VulnerabilityFinding.Status.OPEN,
			host="10.10.10.5",
			service="https",
			port=443,
			protocol="tcp",
			cvss_score=9.8,
			cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			data={
				"file_path": "recon/projeto-relatorio-vuln/vuln/report.xml",
				"source_kind": "nmap_targeted_nse",
				"scanner": "nmap",
				"references": ["https://example.com/vuln"],
				"raw_output": "<xml>" + "x" * (MAX_EVIDENCE_LENGTH + 50) + "</xml>",
				"collected_at": timezone.now().isoformat(),
			},
		)

	def test_upsert_creates_entry_with_sanitized_payload(self):
		summary = {
			"total": 1,
			"open_total": 1,
			"by_severity": {
				"critical": 1,
				"high": 0,
				"medium": 0,
				"low": 0,
				"info": 0,
				"unknown": 0,
			},
			"cves": ["CVE-2025-0001"],
			"sources": ["nmap_targeted_nse"],
			"hosts_impacted": 1,
			"max_cvss": 9.8,
			"artifacts": [
				{
					"path": "recon/projeto-relatorio-vuln/vuln/report.xml",
					"source": "nmap_targeted_nse",
				},
			],
			"last_collected_at": timezone.now().isoformat(),
		}

		result = upsert_vulnerability_report_entry(self.session, summary)
		entry = result.entry
		self.assertEqual(entry.project, self.project)
		self.assertEqual(entry.severity_distribution.get("critical"), 1)
		self.assertIn("vuln", entry.tags)
		self.assertIn(f"session:{self.session.reference}", entry.tags)
		payload = entry.payload
		self.assertEqual(payload["summary"]["totals"]["total"], 1)
		self.assertEqual(payload["artifacts"][0]["path"], "recon/projeto-relatorio-vuln/vuln/report.xml")
		serialized_finding = payload["findings"][0]
		self.assertEqual(serialized_finding["cve"], "CVE-2025-0001")
		self.assertEqual(serialized_finding["sources"]["primary"], "nmap_targeted_nse")
		evidence = serialized_finding.get("evidence_excerpt")
		self.assertIsNotNone(evidence)
		self.assertLessEqual(len(evidence), MAX_EVIDENCE_LENGTH + 1)
		self.assertTrue(evidence.endswith("…"))


class VulnApiTests(TestCase):
	def setUp(self):
		user_model = get_user_model()
		self.owner = user_model.objects.create_user("planner", password="test1234")
		self.member = user_model.objects.create_user("member", password="test1234")
		self.outsider = user_model.objects.create_user("outsider", password="test1234")
		self.project = Project.objects.create(owner=self.owner, name="Projeto API Vuln", slug="projeto-api-vuln")
		ProjectMembership.objects.create(project=self.project, user=self.member)
		self.scan_session = ScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão Scan",
			status=ScanSession.Status.COMPLETED,
		)
		self.scan_session.report_snapshot = {
			"targets": {
				"hosts": [
					{
						"host": "10.0.0.5",
						"ports": [
							{"port": 443, "protocol": "tcp", "status": "open"},
							{"port": 22, "protocol": "tcp", "status": "open"},
						],
					}
				],
				"open_ports": 2,
			},
		}
		self.scan_session.save(update_fields=["report_snapshot"])

		self.vuln_session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão consolidada",
			status=VulnScanSession.Status.COMPLETED,
		)
		task = VulnTask.objects.create(
			session=self.vuln_session,
			order=1,
			kind=VulnTask.Kind.SCRIPT,
			status=VulnTask.Status.COMPLETED,
			name="Nmap NSE",
		)
		VulnerabilityFinding.objects.create(
			session=self.vuln_session,
			source_task=task,
			cve="CVE-2025-0001",
			title="Execução remota",
			summary="Falha crítica permitindo execução remota de código",
			severity=VulnerabilityFinding.Severity.CRITICAL,
			status=VulnerabilityFinding.Status.OPEN,
			host="10.10.10.5",
			service="https",
			port=443,
			protocol="tcp",
			cvss_score=9.8,
			cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			data={
				"file_path": "recon/projeto-api-vuln/vuln/report.xml",
				"source_kind": "nmap_targeted_nse",
				"scanner": "nmap",
				"references": ["https://example.com/vuln"],
				"collected_at": timezone.now().isoformat(),
			},
		)
		summary = {
			"total": 1,
			"open_total": 1,
			"by_severity": {
				"critical": 1,
				"high": 0,
				"medium": 0,
				"low": 0,
				"info": 0,
				"unknown": 0,
			},
			"cves": ["CVE-2025-0001"],
			"sources": ["nmap_targeted_nse"],
			"hosts_impacted": 1,
			"max_cvss": 9.8,
			"artifacts": [
				{
					"path": "recon/projeto-api-vuln/vuln/report.xml",
					"source": "nmap_targeted_nse",
				},
			],
			"last_collected_at": timezone.now().isoformat(),
		}
		upsert_vulnerability_report_entry(self.vuln_session, summary)


	class VulnRetryApiTests(TestCase):
		def setUp(self):
			user_model = get_user_model()
			self.owner = user_model.objects.create_user("retry", password="test1234")
			self.project = Project.objects.create(owner=self.owner, name="Projeto Retry", slug="projeto-retry")
			self.session = VulnScanSession.objects.create(
				project=self.project,
				owner=self.owner,
				title="Sessão falha",
				status=VulnScanSession.Status.FAILED,
				last_error="Greenbone indisponível",
				finished_at=timezone.now(),
			)
			self.task = VulnTask.objects.create(
				session=self.session,
				order=1,
				kind=VulnTask.Kind.GREENBONE_SCAN,
				status=VulnTask.Status.FAILED,
				name="Greenbone Vulnerability Scan",
				progress=100.0,
			)

		@patch("arpia_vuln.views.run_greenbone_scan")
		def test_retry_greenbone_success(self, mocked_run_greenbone):
			def fake_run(session, *, triggered_by=None, auto_finalize=True):
				task = session.tasks.filter(kind=VulnTask.Kind.GREENBONE_SCAN).first()
				if task:
					task.status = VulnTask.Status.COMPLETED
					task.progress = 100.0
					task.finished_at = timezone.now()
					task.save(update_fields=["status", "progress", "finished_at", "updated_at"])
				session.status = VulnScanSession.Status.COMPLETED
				session.last_error = ""
				session.finished_at = timezone.now()
				session.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
				return task

			mocked_run_greenbone.side_effect = fake_run
			self.client.force_login(self.owner)
			url = reverse("arpia_vuln:api_session_retry", args=[self.session.pk])
			response = self.client.post(url, data=json.dumps({"step": "greenbone"}), content_type="application/json")
			self.assertEqual(response.status_code, 200)
			payload = response.json()
			self.session.refresh_from_db()
			self.task.refresh_from_db()
			self.assertEqual(self.session.status, VulnScanSession.Status.COMPLETED)
			self.assertEqual(payload["task"]["status"], VulnTask.Status.COMPLETED)
			mocked_run_greenbone.assert_called_once()
			self.assertTrue(mocked_run_greenbone.call_args.kwargs.get("auto_finalize"))

		@patch("arpia_vuln.views.run_greenbone_scan")
		def test_retry_greenbone_allows_when_last_error_cites_greenbone(self, mocked_run_greenbone):
			self.task.status = VulnTask.Status.PENDING
			self.task.save(update_fields=["status", "updated_at"])
			self.session.status = VulnScanSession.Status.FAILED
			self.session.last_error = "Falha ao iniciar o Greenbone automaticamente."
			self.session.save(update_fields=["status", "last_error", "updated_at"])

			def fake_run(session, *, triggered_by=None, auto_finalize=True):
				task = session.tasks.filter(kind=VulnTask.Kind.GREENBONE_SCAN).first()
				if task:
					task.status = VulnTask.Status.COMPLETED
					task.progress = 100.0
					task.finished_at = timezone.now()
					task.save(update_fields=["status", "progress", "finished_at", "updated_at"])
				session.status = VulnScanSession.Status.COMPLETED
				session.last_error = ""
				session.finished_at = timezone.now()
				session.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
				return task

			mocked_run_greenbone.side_effect = fake_run
			self.client.force_login(self.owner)
			url = reverse("arpia_vuln:api_session_retry", args=[self.session.pk])
			response = self.client.post(url, data=json.dumps({}), content_type="application/json")
			self.assertEqual(response.status_code, 200)
			self.session.refresh_from_db()
			self.task.refresh_from_db()
			self.assertEqual(self.session.status, VulnScanSession.Status.COMPLETED)
			self.assertEqual(self.task.status, VulnTask.Status.COMPLETED)
			mocked_run_greenbone.assert_called_once()

		@patch("arpia_vuln.views.run_greenbone_scan")
		def test_retry_greenbone_failure_propagates_error(self, mocked_run_greenbone):
			mocked_run_greenbone.side_effect = VulnGreenboneExecutionError("falha ao conectar")
			self.client.force_login(self.owner)
			url = reverse("arpia_vuln:api_session_retry", args=[self.session.pk])
			response = self.client.post(url, data=json.dumps({}), content_type="application/json")
			self.assertEqual(response.status_code, 502)
			self.assertIn("falha ao conectar", response.json().get("error", ""))
			self.session.refresh_from_db()
			self.assertEqual(self.session.status, VulnScanSession.Status.FAILED)

	def test_api_session_plan_creates_session(self):
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_session_plan")
		payload = {
			"project_id": str(self.project.pk),
			"title": "Sessão via API",
			"include_greenbone": False,
			"source_scan_session": str(self.scan_session.pk),
		}
		response = self.client.post(url, data=json.dumps(payload), content_type="application/json")
		self.assertEqual(response.status_code, 201)
		data = response.json()
		self.assertEqual(data["title"], "Sessão via API")
		self.assertEqual(data["project_id"], str(self.project.pk))
		self.assertTrue(data.get("tasks"))
		self.assertFalse(any(task["kind"] == VulnTask.Kind.GREENBONE_SCAN for task in data["tasks"]))
		session = VulnScanSession.objects.get(pk=data["id"])
		self.assertEqual(session.status, VulnScanSession.Status.PLANNED)
		self.assertTrue(session.macros_snapshot)
		self.assertEqual(session.source_scan_session, self.scan_session)

	def test_api_session_plan_rejects_without_access(self):
		self.client.force_login(self.outsider)
		url = reverse("arpia_vuln:api_session_plan")
		payload = {"project_id": str(self.project.pk)}
		response = self.client.post(url, data=json.dumps(payload), content_type="application/json")
		self.assertEqual(response.status_code, 403)
		self.assertIn("error", response.json())

	def test_api_session_plan_requires_project(self):
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_session_plan")
		response = self.client.post(url, data=json.dumps({}), content_type="application/json")
		self.assertEqual(response.status_code, 400)
		self.assertIn("project_id", response.json().get("error", ""))

		aggregator = ReportAggregator(project=self.project)
		sections = aggregator.build_sections()
		self.assertIn("vuln", sections)
		vuln_section = sections["vuln"]
		self.assertGreaterEqual(len(vuln_section.items), 1)
		metadata = vuln_section.items[0].metadata
		self.assertEqual(metadata["severity_distribution"].get("critical"), 1)
		self.assertIn("CVE-2025-0001", metadata["cves"])

	@patch("arpia_vuln.views.run_vulnerability_pipeline")
	def test_api_session_start_runs_pipeline(self, mocked_runner):
		planned = plan_vulnerability_session(
			owner=self.owner,
			project=self.project,
			title="Sessão planejada",
			source_scan_session=self.scan_session,
		)
		mocked_runner.return_value = planned
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_session_start", args=[planned.pk])
		response = self.client.post(url, data="{}", content_type="application/json")
		self.assertEqual(response.status_code, 200)
		mocked_runner.assert_called_once_with(planned, triggered_by=self.owner)
		payload = response.json()
		self.assertEqual(payload["id"], str(planned.pk))

	def test_api_session_start_requires_access(self):
		session = plan_vulnerability_session(owner=self.owner, project=self.project, title="Sessão privada")
		self.client.force_login(self.outsider)
		url = reverse("arpia_vuln:api_session_start", args=[session.pk])
		response = self.client.post(url, data="{}", content_type="application/json")
		self.assertEqual(response.status_code, 403)

	def test_api_session_start_conflict_when_terminal(self):
		session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.owner,
			title="Sessão finalizada",
			status=VulnScanSession.Status.COMPLETED,
		)
		self.client.force_login(self.owner)
		url = reverse("arpia_vuln:api_session_start", args=[session.pk])
		response = self.client.post(url, data="{}", content_type="application/json")
		self.assertEqual(response.status_code, 409)
