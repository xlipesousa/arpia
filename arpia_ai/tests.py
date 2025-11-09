from django.contrib.auth import get_user_model
from django.test import TestCase

from arpia_core.models import Project, Script
from arpia_scan.models import ScanSession
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession

from .models import ChatMessage, ChatSession, Provider, ProviderCredential
from .services import (
    AdvisorResponse,
    build_project_context,
    generate_advisor_response,
    record_interaction,
)


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
            title="Revisao de CVE",
        )
        message = ChatMessage.objects.create(
            session=session,
            role=ChatMessage.Role.USER,
            content="Qual mitigacao?",
        )
        self.assertEqual(session.messages.count(), 1)
        self.assertIn("Qual mitigacao", str(message))


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
            summary="Detalhes extensos sobre mitigacao" * 5,
            severity=VulnerabilityFinding.Severity.HIGH,
            cve="CVE-2024-1234",
        )

        Script.objects.create(
            owner=None,
            name="Script Demo",
            slug="script-demo",
            filename="demo.sh",
            content="#!/bin/sh\necho demo",
            description="Script de exemplo para exploracao",
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


class AdvisorResponseTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="advisor",
            email="advisor@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(name="Projeto Advisor", slug="projeto-advisor", owner=self.user)
        vuln_session = VulnScanSession.objects.create(project=self.project, owner=self.user, title="Sessao Vuln")
        VulnerabilityFinding.objects.create(
            session=vuln_session,
            title="CVE-2024-9999",
            summary="Resumo breve",
            severity=VulnerabilityFinding.Severity.CRITICAL,
            cve="CVE-2024-9999",
        )

    def test_generate_advisor_response_returns_summary(self):
        result: AdvisorResponse = generate_advisor_response(
            user=self.user,
            project=self.project,
            question="Como mitigar?",
        )

        self.assertIn("Projeto:", result.answer)
        self.assertIn("CVE-2024-9999", result.answer)
        self.assertTrue(result.context)


class AssistViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="viewer",
            email="viewer@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(name="Projeto Assist", slug="projeto-assist", owner=self.user)
        vuln_session = VulnScanSession.objects.create(project=self.project, owner=self.user, title="Sessao Vuln")
        VulnerabilityFinding.objects.create(
            session=vuln_session,
            title="CVE-2024-5555",
            summary="Mitigar atualizando o pacote",
            severity=VulnerabilityFinding.Severity.HIGH,
            cve="CVE-2024-5555",
        )

    def test_assist_endpoint_requires_login(self):
        response = self.client.post("/ai/assist/", data={})
        self.assertEqual(response.status_code, 302)

    def test_assist_endpoint_returns_answer(self):
        self.client.login(username="viewer", password="pass1234")
        response = self.client.post(
            "/ai/assist/",
            data={"question": "Resumo", "project_id": self.project.pk},
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("answer", payload)
        self.assertIn("CVE-2024-5555", payload["answer"])
        self.assertEqual(ChatSession.objects.count(), 1)
        self.assertEqual(ChatMessage.objects.filter(role=ChatMessage.Role.USER).count(), 1)
        self.assertEqual(ChatMessage.objects.filter(role=ChatMessage.Role.ASSISTANT).count(), 1)


class HistoryServiceTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="logger",
            email="logger@example.com",
            password="pass1234",
        )
        self.project = Project.objects.create(name="Projeto Log", slug="projeto-log", owner=self.user)

    def test_record_interaction_persists_session_and_messages(self):
        session = record_interaction(
            user=self.user,
            project=self.project,
            question="Qual e o status?",
            answer="Tudo mitigado.",
            context={"key": "value"},
        )

        self.assertEqual(ChatSession.objects.count(), 1)
        self.assertEqual(session.project, self.project)
        self.assertEqual(session.context_snapshot, {"key": "value"})
        self.assertEqual(ChatMessage.objects.filter(session=session).count(), 2)

    def test_record_interaction_without_project_raises(self):
        with self.assertRaises(ValueError):
            record_interaction(
                user=self.user,
                project=None,
                question="Pergunta",
                answer="Resposta",
            )
