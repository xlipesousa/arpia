from __future__ import annotations

from typing import Any

from django.db import transaction

from ..models import ChatMessage, ChatSession, Provider, ProviderCredential
from .provider_registry import ensure_demo_provider


@transaction.atomic
def record_interaction(
    *,
    user,
    project,
    question: str,
    answer: str,
    context: dict[str, Any] | None = None,
    provider: Provider | None = None,
    credential: ProviderCredential | None = None,
    metadata: dict[str, Any] | None = None,
) -> ChatSession:
    if project is None:
        raise ValueError("Projeto obrigatorio para registrar a interacao.")

    provider = provider or ensure_demo_provider()

    session = ChatSession.objects.create(
        owner=user,
        provider=provider,
        credential=credential,
        project=project,
        title=f"Assistente IA - {project.name}",
        context_snapshot=context or {},
    )

    if credential:
        credential.touch_last_used()

    ChatMessage.objects.create(
        session=session,
        role=ChatMessage.Role.USER,
        content=question or "(sem pergunta)",
        metadata={
            "provider": provider.slug,
            "provider_name": provider.name,
        },
    )
    ChatMessage.objects.create(
        session=session,
        role=ChatMessage.Role.ASSISTANT,
        content=answer,
        metadata={
            "context_keys": sorted((context or {}).keys()),
            "provider": provider.slug,
            "provider_name": provider.name,
            "provider_metadata": metadata or {},
        },
    )

    return session
