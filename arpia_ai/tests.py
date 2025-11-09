from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from arpia_core.models import Project, Script
from arpia_scan.models import ScanSession
from arpia_vuln.models import VulnerabilityFinding, VulnScanSession

from .models import ChatMessage, ChatSession, Provider, ProviderCredential
from .services import (
    AdvisorResponse,
    build_project_context,
    ensure_demo_provider,
    ensure_openai_provider,
    generate_advisor_response,
    record_interaction,
    resolve_provider_for_user,
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
        self.assertEqual(result.provider.slug, "demo-advisor")
        self.assertIsNone(result.credential)
        self.assertEqual(result.metadata.get("mode"), "demo")

    def test_generate_advisor_response_prefers_openai_with_credential(self):
        provider = ensure_openai_provider()
        credential = ProviderCredential.objects.create(
            provider=provider,
            owner=self.user,
            label="default",
            api_key="sk-demo-openai",
        )

        result: AdvisorResponse = generate_advisor_response(
            user=self.user,
            project=self.project,
            question="Qual mitigacao devemos adotar?",
        )

        self.assertEqual(result.provider.slug, "openai")
        self.assertEqual(result.credential, credential)
        self.assertEqual(result.metadata.get("mode"), "openai")
        self.assertIn(result.metadata.get("status"), {"sdk-missing", "ok", "error", "empty-response"})


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
        self.assertIn("provider", payload)
        self.assertEqual(payload["provider"]["slug"], "demo-advisor")
        self.assertIn("metadata", payload)
        self.assertEqual(ChatSession.objects.count(), 1)
        self.assertEqual(ChatMessage.objects.filter(role=ChatMessage.Role.USER).count(), 1)
        self.assertEqual(ChatMessage.objects.filter(role=ChatMessage.Role.ASSISTANT).count(), 1)
        session = ChatSession.objects.first()
        self.assertEqual(session.provider.slug, "demo-advisor")
        assistant_msg = ChatMessage.objects.filter(role=ChatMessage.Role.ASSISTANT).first()
        self.assertEqual(assistant_msg.metadata.get("provider"), "demo-advisor")
        self.assertEqual(assistant_msg.metadata.get("provider_metadata", {}).get("mode"), "demo")


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
        assistant = ChatMessage.objects.filter(session=session, role=ChatMessage.Role.ASSISTANT).first()
        self.assertEqual(assistant.metadata.get("provider"), "demo-advisor")
        self.assertEqual(assistant.metadata.get("provider_metadata"), {})
        user_message = ChatMessage.objects.filter(session=session, role=ChatMessage.Role.USER).first()
        self.assertEqual(user_message.metadata.get("provider"), "demo-advisor")

    def test_record_interaction_without_project_raises(self):
        with self.assertRaises(ValueError):
            record_interaction(
                user=self.user,
                project=None,
                question="Pergunta",
                answer="Resposta",
            )

    def test_record_interaction_with_explicit_provider_and_credential(self):
        provider = ensure_demo_provider()
        credential = ProviderCredential.objects.create(
            provider=provider,
            owner=self.user,
            label="demo",
            api_key="sk-demo-abcdef",
        )

        session = record_interaction(
            user=self.user,
            project=self.project,
            question="Status?",
            answer="Tudo ok.",
            context={"foo": "bar"},
            provider=provider,
            credential=credential,
            metadata={"mode": "demo"},
        )

        self.assertEqual(session.credential, credential)
        credential.refresh_from_db()
        self.assertIsNotNone(credential.last_used_at)
        assistant = ChatMessage.objects.filter(session=session, role=ChatMessage.Role.ASSISTANT).first()
        self.assertEqual(assistant.metadata.get("provider"), provider.slug)
        self.assertEqual(assistant.metadata.get("provider_metadata", {}).get("mode"), "demo")


class ProviderRegistryTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="registry",
            email="registry@example.com",
            password="pass1234",
        )

    def test_resolve_provider_for_user_returns_demo(self):
        provider, credential = resolve_provider_for_user(user=self.user, project=None)
        self.assertEqual(provider.slug, "demo-advisor")
        self.assertIsNone(credential)

    def test_resolve_provider_for_user_prefers_openai_with_credential(self):
        provider = ensure_openai_provider()
        credential = ProviderCredential.objects.create(
            provider=provider,
            owner=self.user,
            label="default",
            api_key="sk-existing",
        )

        resolved_provider, resolved_credential = resolve_provider_for_user(user=self.user, project=None)
        self.assertEqual(resolved_provider.slug, "openai")
        self.assertEqual(resolved_credential, credential)


class ProviderListViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="provviewer",
            email="provviewer@example.com",
            password="pass1234",
        )

    def test_list_providers_requires_login(self):
        url = reverse("arpia_ai:providers")
        response = self.client.get(url)
        self.assertEqual(response.status_code, 302)

    def test_list_providers_returns_demo_provider(self):
        self.client.force_login(self.user)
        url = reverse("arpia_ai:providers")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        providers = payload.get("providers", [])
        self.assertTrue(providers)
        slugs = {item["slug"] for item in providers}
        self.assertIn("demo-advisor", slugs)
        self.assertIn("openai", slugs)
        demo = next(item for item in providers if item["slug"] == "demo-advisor")
        self.assertFalse(demo["has_credentials"])

    def test_list_providers_includes_masked_credential(self):
        self.client.force_login(self.user)
        provider = ensure_openai_provider()
        ProviderCredential.objects.create(
            provider=provider,
            owner=self.user,
            label="default",
            api_key="sk-demo-xyz123",
        )

        url = reverse("arpia_ai:providers")
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        providers = payload.get("providers", [])
        openai = next(p for p in providers if p["slug"] == "openai")
        self.assertTrue(openai["has_credentials"])
        credential = openai.get("credential")
        self.assertIsNotNone(credential)
        self.assertTrue(credential["masked_api_key"].startswith("****"))
        self.assertIn("validation", credential)


class OpenAICredentialRegistrationTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="creduser",
            email="creduser@example.com",
            password="pass1234",
        )
        self.url = reverse("arpia_ai:provider_openai_credential")

    def test_registration_requires_login(self):
        response = self.client.post(self.url, data={"api_key": "sk-test"})
        self.assertEqual(response.status_code, 302)

    def test_registration_validates_api_key(self):
        self.client.force_login(self.user)
        response = self.client.post(self.url, data={"api_key": ""})
        self.assertEqual(response.status_code, 400)
        payload = response.json()
        self.assertIn("error", payload)

    def test_registration_creates_credential(self):
        self.client.force_login(self.user)
        response = self.client.post(self.url, data={"api_key": "sk-test-value"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["provider"], "openai")
        credential = ProviderCredential.objects.get(provider__slug="openai", owner=self.user)
        self.assertEqual(credential.api_key, "sk-test-value")
        self.assertIsInstance(credential.metadata, dict)
        validation = credential.metadata.get("validation")
        self.assertIsNotNone(validation)
        self.assertEqual(validation.get("status"), "skipped")
        response_validation = payload["credential"].get("validation")
        self.assertEqual(response_validation.get("status"), "skipped")

    def test_registration_updates_existing_credential(self):
        self.client.force_login(self.user)
        provider = ensure_openai_provider()
        ProviderCredential.objects.create(
            provider=provider,
            owner=self.user,
            label="default",
            api_key="sk-inicial",
        )

        response = self.client.post(self.url, data={"api_key": "sk-atualizado"})
        self.assertEqual(response.status_code, 200)
        credential = ProviderCredential.objects.get(provider=provider, owner=self.user)
        self.assertEqual(credential.api_key, "sk-atualizado")
        self.assertEqual(credential.metadata.get("validation", {}).get("status"), "skipped")
