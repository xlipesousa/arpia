from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from arpia_core.models import Project

from .context import build_project_context
from .provider_registry import (
    ProviderAnswer,
    ensure_demo_provider,
    registry,
    resolve_provider_for_user,
)
from .renderers import render_internal_summary
from ..models import Provider, ProviderCredential


@dataclass(frozen=True)
class AdvisorResponse:
    answer: str
    context: dict[str, Any]
    provider: Provider
    credential: ProviderCredential | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def generate_advisor_response(
    *,
    user,
    project: Project | None,
    question: str,
) -> AdvisorResponse:
    context = build_project_context(project=project, user=user)
    if not project or not context:
        demo_provider = ensure_demo_provider()
        return AdvisorResponse(
            answer="Selecione um projeto valido para que eu possa analisar os dados coletados.",
            context={},
            provider=demo_provider,
        )

    provider, credential = resolve_provider_for_user(user=user, project=project)
    adapter = registry.get_adapter(provider.slug)
    provider_answer: ProviderAnswer | None = None
    if adapter:
        provider_answer = adapter.generate_answer(
            user=user,
            project=project,
            question=question,
            context=context,
            credential=credential,
        )

    if provider_answer is None:
        fallback_answer = render_internal_summary(context=context, question=question)
        provider_answer = ProviderAnswer(
            answer=fallback_answer,
            metadata={"mode": "internal-fallback"},
        )

    return AdvisorResponse(
        answer=provider_answer.answer,
        context=context,
        provider=provider,
        credential=credential,
        metadata=provider_answer.metadata,
    )
