from django.contrib.auth import get_user_model
from django.test import TestCase

from arpia_core.models import Project

from .models import ChatMessage, ChatSession, Provider, ProviderCredential


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
