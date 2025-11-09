from django.contrib.auth import get_user_model
from django.test import TestCase

from arpia_core.models import Project, Script
from arpia_scan.models import ScanSession
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession

from .models import ChatMessage, ChatSession, Provider, ProviderCredential
from .services import build_project_context


class ProviderModelTests(TestCase):
	def test_slug_autofill(self):
		provider = Provider.objects.create(name="OpenAI", description="LLM provider")
		self.assertEqual(provider.slug, "openai")


class ProviderCredentialTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(
			username="ai-user",
			email="ai@example.com",
			password="pass1234",
		)
		self.provider = Provider.objects.create(name="OpenAI")

	def test_masked_api_key(self):
		credential = ProviderCredential.objects.create(
			provider=self.provider,
			owner=self.user,
			api_key="sk-demo-123456789",
		)
		self.assertTrue(credential.masked_api_key.endswith("6789"))
		self.assertTrue(credential.masked_api_key.startswith("****"))


class ChatSessionTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(
			username="agent",
			email="agent@example.com",
			password="pass1234",
		)
		self.provider = Provider.objects.create(name="OpenAI")
		self.project = Project.objects.create(name="Projeto IA", slug="projeto-ia", owner=self.user)

	def test_create_session_and_message(self):
		session = ChatSession.objects.create(
			owner=self.user,
			provider=self.provider,
			project=self.project,
			title="Revisão de CVE",
		)
		message = ChatMessage.objects.create(
			session=session,
			role=ChatMessage.Role.USER,
			content="Qual mitigação?",
		)
		self.assertEqual(session.messages.count(), 1)
		self.assertIn("Qual mitigação", str(message))


class ProjectContextBuilderTests(TestCase):
	def setUp(self):
		self.user = get_user_model().objects.create_user(
			username="contextor",
			email="ctx@example.com",
			password="pass1234",
		)
		self.project = Project.objects.create(name="Projeto Demo", slug="projeto-demo", owner=self.user)

		self.scan_session = ScanSession.objects.create(
			project=self.project,
			owner=self.user,
			title="Scan de Rede",
			status=ScanSession.Status.COMPLETED,
		)

		self.vuln_session = VulnScanSession.objects.create(
			project=self.project,
			owner=self.user,
			title="Vulnerabilidades",
		)

		VulnerabilityFinding.objects.create(
			session=self.vuln_session,
			title="CVE-2024-1234",
			summary="Detalhes extensos sobre mitigação" * 5,
			severity=VulnerabilityFinding.Severity.HIGH,
			cve="CVE-2024-1234",
		)

		Script.objects.create(
			owner=None,
			name="Script Demo",
			slug="script-demo",
			filename="demo.sh",
			content="#!/bin/sh\necho demo",
			description="Script de exemplo para exploração",
			kind=Script.Kind.DEFAULT,
		)

	def test_build_project_context_returns_expected_sections(self):
		context = build_project_context(project=self.project, user=self.user)

		self.assertIn("project", context)
		self.assertIn("macros", context)
		self.assertIn("vulnerability_findings", context)
		self.assertTrue(context["vulnerability_findings"])
		self.assertIn("recent_scan_sessions", context)
		self.assertIn("available_scripts", context)

		macro_keys = context["macros"].keys()
		self.assertNotIn("CREDENTIALS_JSON", macro_keys)
