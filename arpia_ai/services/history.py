from __future__ import annotations

from typing import Any

from django.db import transaction

from ..models import ChatMessage, ChatSession, Provider


def _get_internal_provider() -> Provider:
    provider, _ = Provider.objects.get_or_create(
        slug="demo-advisor",
        defaults={
            "name": "Demo Advisor",
            "description": "Assistente interno usado na demonstracao do modulo IA.",
        },
    )
    return provider


@transaction.atomic
def record_interaction(
    *,
    user,
    project,
    question: str,
    answer: str,
    context: dict[str, Any] | None = None,
) -> ChatSession:
    if project is None:
        raise ValueError("Projeto obrigatorio para registrar a interacao.")

    provider = _get_internal_provider()

    session = ChatSession.objects.create(
        owner=user,
        provider=provider,
        project=project,
        title=f"Assistente IA - {project.name}",
        context_snapshot=context or {},
    )

    ChatMessage.objects.create(
        session=session,
        role=ChatMessage.Role.USER,
        content=question or "(sem pergunta)",
    )
    ChatMessage.objects.create(
        session=session,
        role=ChatMessage.Role.ASSISTANT,
        content=answer,
        metadata={"context_keys": sorted((context or {}).keys())},
    )

    return session
