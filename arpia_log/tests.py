from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from .models import LogEntry
from .serializers import LogEntrySerializer
from .services import log_event


class LogEntrySerializerTests(TestCase):
	def test_serializer_creates_entry_with_defaults(self):
		data = {
			"source_app": "arpia_core",
			"event_type": "TEST_EVENT",
			"message": "Teste",
		}
		serializer = LogEntrySerializer(data=data)
		self.assertTrue(serializer.is_valid(), serializer.errors)
		entry = serializer.save()
		self.assertEqual(entry.source_app, "arpia_core")
		self.assertEqual(entry.severity, LogEntry.Severity.INFO)
		self.assertEqual(entry.project_ref, "")
		self.assertEqual(entry.ingestion_channel, LogEntry.Channel.INTERNAL)


class LogEventServiceTests(TestCase):
	def test_log_event_populates_actor_from_request(self):
		from django.contrib.auth import get_user_model

		user_model = get_user_model()
		user = user_model.objects.create_user(username="tester", password="secret")

		request = type("Req", (), {"user": user})
		entry = log_event(
			source_app="arpia_core",
			event_type="SERVICE_CHECK",
			severity=LogEntry.Severity.NOTICE,
			message="Serviço testado",
			correlation={"project_id": 10},
			request=request,
		)
		self.assertEqual(entry.user_ref, str(user.pk))
		self.assertEqual(entry.project_ref, "10")


@override_settings(ARPIA_LOG_INGEST_TOKEN="apitoken")
class LogIngestApiTests(TestCase):
	def setUp(self) -> None:
		self.client = APIClient()
		self.url = reverse("logs_ingest")

	def test_rejects_without_token(self):
		response = self.client.post(self.url, data={}, format="json")
		self.assertEqual(response.status_code, 403)

	def test_accepts_valid_payload(self):
		payload = {
			"source_app": "arpia_scan",
			"event_type": "SCAN_DONE",
			"message": "Scan executado",
			"severity": "WARN",
			"timestamp": timezone.now().isoformat(),
			"correlation": {"project_id": 77},
		}
		response = self.client.post(
			self.url,
			data=payload,
			format="json",
			HTTP_AUTHORIZATION="Token apitoken",
		)
		self.assertEqual(response.status_code, 201, response.content)
		entry = LogEntry.objects.last()
		self.assertIsNotNone(entry)
		self.assertEqual(entry.project_ref, "77")


@override_settings(ARPIA_LOG_INGEST_TOKEN="apitoken")
class LogBulkApiTests(TestCase):
	def setUp(self) -> None:
		self.client = APIClient()
		self.url = reverse("logs_bulk_ingest")

	def test_bulk_creates_multiple_entries(self):
		payload = [
			{
				"source_app": "arpia_vuln",
				"event_type": "VULN_OPENED",
				"message": "Nova vulnerabilidade",
			},
			{
				"source_app": "arpia_vuln",
				"event_type": "VULN_CLOSED",
				"message": "Remediada",
				"severity": "NOTICE",
			},
		]
		response = self.client.post(
			self.url,
			data=payload,
			format="json",
			HTTP_AUTHORIZATION="Token apitoken",
		)
		self.assertIn(response.status_code, {201, 207}, response.content)
		self.assertEqual(LogEntry.objects.count(), 2)
