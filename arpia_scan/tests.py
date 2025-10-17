import json
from datetime import timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from arpia_core.models import Project
from arpia_log.models import LogEntry

from .models import ScanSession, ScanTask, ScanFinding
from .parsers import merge_observations, parse_nmap_xml, parse_rustscan_payload


FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures" / "scan_samples"


class ObservationParsersTests(SimpleTestCase):
    def test_merge_observations_from_samples(self):
        nmap_payload = (FIXTURES_DIR / "nmap_sample.xml").read_text(encoding="utf-8")
        rustscan_payload = (FIXTURES_DIR / "rustscan_sample.json").read_text(encoding="utf-8")

        endpoints = [*parse_nmap_xml(nmap_payload), *parse_rustscan_payload(rustscan_payload)]
        self.assertGreater(len(endpoints), 0)

        observations = merge_observations(endpoints)

        targets = observations.get("targets", {})
        services = observations.get("services", {})

        self.assertEqual(targets.get("hosts_count"), 2)
        self.assertEqual(targets.get("open_ports"), 3)
        host_ips = {host.get("host") for host in targets.get("hosts", [])}
        self.assertIn("10.0.0.5", host_ips)
        self.assertIn("10.0.0.8", host_ips)

        service_names = {item.get("service") for item in services.get("items", [])}
        self.assertIn("ssh", service_names)
        self.assertIn("http", service_names)


class ScanDashboardViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="tester",
            email="tester@example.com",
            password="pass1234",
        )

    def test_redirects_when_not_authenticated(self):
        response = self.client.get(reverse("arpia_scan:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_lists_projects_for_authenticated_user(self):
        Project.objects.create(owner=self.user, name="Projeto Alpha", slug="projeto-alpha")

        self.client.login(username="tester", password="pass1234")
        response = self.client.get(reverse("arpia_scan:dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scan/dashboard.html")
        self.assertContains(response, "Projeto Alpha")

    def test_dashboard_shows_sessions_and_macros_for_selected_project(self):
        project = Project.objects.create(owner=self.user, name="Projeto Gamma", slug="projeto-gamma")
        ScanSession.objects.create(project=project, owner=self.user, title="Descoberta inicial")

        self.client.login(username="tester", password="pass1234")
        response = self.client.get(reverse("arpia_scan:dashboard"))

        self.assertContains(response, "Descoberta inicial")
        self.assertContains(response, "PROJECT_NAME")
        self.assertContains(response, "Teste de conectividade")
        self.assertContains(response, "Executar agora")


class ScanModelTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="modeler",
            email="modeler@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(owner=self.user, name="Projeto Beta", slug="projeto-beta")

    def test_create_session_task_and_finding(self):
        session = ScanSession.objects.create(
            project=self.project,
            owner=self.user,
            title="Varredura inicial",
        )
        self.assertEqual(session.status, ScanSession.Status.PLANNED)
        self.assertTrue(session.reference)

        task = ScanTask.objects.create(
            session=session,
            order=1,
            kind=ScanTask.Kind.CONNECTIVITY,
            name="Teste de rede",
        )
        self.assertEqual(task.status, ScanTask.Status.PENDING)
        self.assertEqual(session.tasks.count(), 1)

        finding = ScanFinding.objects.create(
            session=session,
            source_task=task,
            kind=ScanFinding.Kind.SUMMARY,
            title="Resumo provisório",
            data={"hosts": 3},
        )
        self.assertEqual(finding.kind, ScanFinding.Kind.SUMMARY)
        self.assertEqual(session.findings.count(), 1)


class ScanSessionDetailViewTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="owner",
            email="owner@example.com",
            password="pass1234",
        )
        self.other = get_user_model().objects.create_user(
            username="guest",
            email="guest@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(owner=self.owner, name="Projeto Detalhe", slug="projeto-detalhe")
        self.session = ScanSession.objects.create(
            project=self.project,
            owner=self.owner,
            title="Sessão detalhada",
            macros_snapshot={"PROJECT_NAME": "Projeto Detalhe"},
        )
        self.task = ScanTask.objects.create(
            session=self.session,
            order=1,
            kind=ScanTask.Kind.CONNECTIVITY,
            name="Ping inicial",
        )
        self.finding = ScanFinding.objects.create(
            session=self.session,
            source_task=self.task,
            kind=ScanFinding.Kind.SUMMARY,
            title="Resumo",
            data={"hosts": ["10.0.0.1"]},
        )

    def test_owner_can_view_session_detail(self):
        self.client.login(username="owner", password="pass1234")
        response = self.client.get(reverse("arpia_scan:session_detail", args=[self.session.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "scan/session_detail.html")
        self.assertContains(response, "Sessão detalhada")
        self.assertContains(response, "Ping inicial")
        self.assertContains(response, "hosts")

    def test_non_member_receives_404(self):
        self.client.login(username="guest", password="pass1234")
        response = self.client.get(reverse("arpia_scan:session_detail", args=[self.session.pk]))
        self.assertEqual(response.status_code, 404)


class ScanApiTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="api_owner",
            email="api_owner@example.com",
            password="pass1234",
        )
        self.other = get_user_model().objects.create_user(
            username="api_guest",
            email="api_guest@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(owner=self.owner, name="Projeto API", slug="projeto-api")

    def test_requires_authentication(self):
        url = reverse("arpia_scan:api_session_create")
        response = self.client.post(url, data=json.dumps({"project_id": str(self.project.pk)}), content_type="application/json")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_owner_can_create_session(self):
        self.client.login(username="api_owner", password="pass1234")
        url = reverse("arpia_scan:api_session_create")
        response = self.client.post(
            url,
            data=json.dumps({"project_id": str(self.project.pk), "notes": "Executar em modo rápido"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertEqual(payload["status"], ScanSession.Status.PLANNED)
        self.assertGreaterEqual(len(payload["tasks"]), 1)
        self.assertIn("detail_url", payload)
        self.assertIn("progress_percent", payload["tasks"][0])
        self.assertIn("stdout", payload["tasks"][0])
        self.assertEqual(LogEntry.objects.filter(event_type="scan.session.created").count(), 1)

        session = ScanSession.objects.get(pk=payload["id"])
        self.assertEqual(session.owner, self.owner)
        self.assertIn("notes", session.config_snapshot)

    def test_non_owner_cannot_create_session(self):
        self.client.login(username="api_guest", password="pass1234")
        url = reverse("arpia_scan:api_session_create")
        response = self.client.post(
            url,
            data=json.dumps({"project_id": str(self.project.pk)}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "Usuário não possui acesso a este projeto.")

    def test_can_start_and_fetch_status(self):
        self.client.login(username="api_owner", password="pass1234")
        create_url = reverse("arpia_scan:api_session_create")
        create_response = self.client.post(
            create_url,
            data=json.dumps({"project_id": str(self.project.pk)}),
            content_type="application/json",
        )
        session_id = create_response.json()["id"]

        start_url = reverse("arpia_scan:api_session_start", args=[session_id])
        start_response = self.client.post(start_url)
        self.assertEqual(start_response.status_code, 200)
        start_payload = start_response.json()
        self.assertEqual(start_payload["status"], ScanSession.Status.COMPLETED)
        self.assertTrue(LogEntry.objects.filter(event_type="scan.session.started").exists())
        self.assertTrue(LogEntry.objects.filter(event_type="scan.session.completed").exists())
        self.assertGreaterEqual(
            LogEntry.objects.filter(event_type="scan.task.completed").count(),
            len(start_payload["tasks"])
        )

        status_url = reverse("arpia_scan:api_session_status", args=[session_id])
        status_response = self.client.get(status_url)
        self.assertEqual(status_response.status_code, 200)
        status_payload = status_response.json()
        self.assertEqual(status_payload["status_display"], "Concluído")
        self.assertGreaterEqual(len(status_payload["findings"]), 1)
        self.assertIn("summary", status_payload["findings"][0])
        self.assertIn("stdout", status_payload["tasks"][0])
        snapshot = status_payload.get("report_snapshot", {})
        targets = snapshot.get("targets", {})
        self.assertGreaterEqual(targets.get("hosts_count", 0), 1)
        self.assertIn("configured_hosts", snapshot.get("targets", {}))


class ScanExportTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="exporter",
            email="exporter@example.com",
            password="pass1234",
        )
        self.other = get_user_model().objects.create_user(
            username="outsider",
            email="outsider@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(owner=self.owner, name="Projeto Export", slug="projeto-export")
        self.session = ScanSession.objects.create(project=self.project, owner=self.owner, title="Sessão export")
        self.session.report_snapshot = {
            "targets": {
                "hosts_count": 1,
                "open_ports": 2,
                "hosts": [
                    {
                        "host": "10.0.0.5",
                        "severity": "medium",
                        "ports": [
                            {"port": 22, "protocol": "tcp", "service": "ssh", "severity": "medium"},
                            {"port": 80, "protocol": "tcp", "service": "http", "severity": "medium"},
                        ],
                    }
                ],
            }
        }
        self.session.save(update_fields=["report_snapshot"])

    def test_csv_export_requires_login(self):
        url = reverse("arpia_scan:session_targets_export_csv", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_csv_export_returns_data(self):
        self.client.login(username="exporter", password="pass1234")
        url = reverse("arpia_scan:session_targets_export_csv", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv")
        content = response.content.decode()
        self.assertIn("10.0.0.5", content)
        self.assertIn("22", content)

    def test_json_export_blocks_unauthorized_access(self):
        self.client.login(username="outsider", password="pass1234")
        url = reverse("arpia_scan:session_targets_export_json", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)

    def test_json_export_returns_payload(self):
        self.client.login(username="exporter", password="pass1234")
        url = reverse("arpia_scan:session_targets_export_json", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload.get("hosts_count"), 1)


class ScanLogApiTests(TestCase):
    def setUp(self):
        self.owner = get_user_model().objects.create_user(
            username="logger",
            email="logger@example.com",
            password="pass1234",
        )
        self.other = get_user_model().objects.create_user(
            username="outsider2",
            email="outsider2@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(owner=self.owner, name="Projeto Logs", slug="projeto-logs")
        self.session = ScanSession.objects.create(project=self.project, owner=self.owner, title="Sessão logs")

    def _create_log(self, severity="INFO", message="Mensagem", timestamp=None):
        return LogEntry.objects.create(
            timestamp=timestamp or timezone.now(),
            source_app="arpia_scan",
            event_type="scan.session.test",
            severity=severity,
            message=message,
            correlation={"scan_session_id": str(self.session.pk), "project_id": str(self.project.pk)},
        )

    def test_logs_endpoint_requires_auth(self):
        url = reverse("arpia_scan:api_session_logs", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_owner_receives_logs(self):
        self._create_log()
        self.client.login(username="logger", password="pass1234")
        url = reverse("arpia_scan:api_session_logs", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["severity"], "INFO")

    def test_non_member_cannot_access(self):
        self._create_log()
        self.client.login(username="outsider2", password="pass1234")
        url = reverse("arpia_scan:api_session_logs", args=[self.session.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def test_filters_by_cursor(self):
        first = self._create_log(timestamp=timezone.now() - timedelta(minutes=5), message="Primeiro")
        self._create_log(timestamp=timezone.now(), message="Segundo")
        self.client.login(username="logger", password="pass1234")
        url = reverse("arpia_scan:api_session_logs", args=[self.session.pk])
        response = self.client.get(url, {"cursor": first.timestamp.isoformat()})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["message"], "Segundo")
