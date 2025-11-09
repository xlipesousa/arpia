from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from django.conf import settings
from django.utils import timezone

from ..models import Provider, ProviderCredential
from .renderers import render_internal_summary


try:  # pragma: no cover - opcional durante a demo
    from openai import (  # type: ignore
        APIStatusError,
        AuthenticationError,
        NotFoundError,
        OpenAI,
        PermissionDeniedError,
        RateLimitError,
    )
except ImportError:  # pragma: no cover - fallback quando SDK nao instalado
    OpenAI = None  # type: ignore
    APIStatusError = AuthenticationError = NotFoundError = PermissionDeniedError = RateLimitError = Exception  # type: ignore


logger = logging.getLogger(__name__)

DEMO_PROVIDER_SLUG = "demo-advisor"
OPENAI_PROVIDER_SLUG = "openai"


@dataclass(frozen=True)
class ProviderAnswer:
    answer: str
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseProviderAdapter(ABC):
    slug: str
    display_name: str

    @abstractmethod
    def generate_answer(
        self,
        *,
        user,
        project,
        question: str,
        context: dict[str, Any],
        credential: Optional[ProviderCredential],
    ) -> ProviderAnswer | None:
        raise NotImplementedError


class ProviderRegistry:
    def __init__(self) -> None:
        self._adapters: Dict[str, BaseProviderAdapter] = {}

    def register(self, adapter: BaseProviderAdapter) -> None:
        self._adapters[adapter.slug] = adapter

    def get_adapter(self, provider_slug: str) -> BaseProviderAdapter | None:
        return self._adapters.get(provider_slug)

    def all_slugs(self) -> list[str]:
        return sorted(self._adapters.keys())


registry = ProviderRegistry()


class DemoProviderAdapter(BaseProviderAdapter):
    slug = DEMO_PROVIDER_SLUG
    display_name = "Demo Advisor"

    def generate_answer(
        self,
        *,
        user,
        project,
        question: str,
        context: dict[str, Any],
        credential: Optional[ProviderCredential],
    ) -> ProviderAnswer | None:
        answer = render_internal_summary(context=context, question=question)
        return ProviderAnswer(answer=answer, metadata={"mode": "demo"})


registry.register(DemoProviderAdapter())


class OpenAIProviderAdapter(BaseProviderAdapter):
    slug = OPENAI_PROVIDER_SLUG
    display_name = "OpenAI"

    _FALLBACK_MESSAGE = (
        "Resumo interno gerado porque a chamada ao modelo OpenAI nao foi concluida."
    )

    def generate_answer(
        self,
        *,
        user,
        project,
        question: str,
        context: dict[str, Any],
        credential: Optional[ProviderCredential],
    ) -> ProviderAnswer | None:
        provider = Provider.objects.filter(slug=self.slug).first()
        model_name = provider.default_model if provider else "gpt-4o-mini"

        if credential is None or not credential.api_key:
            answer = render_internal_summary(context=context, question=question)
            return ProviderAnswer(
                answer=answer,
                metadata={"mode": "openai", "status": "missing-credential"},
            )

        if OpenAI is None:
            logger.info("OpenAI SDK nao instalado. Usando resumo interno como fallback.")
            answer = render_internal_summary(context=context, question=question)
            return ProviderAnswer(
                answer=answer,
                metadata={"mode": "openai", "status": "sdk-missing"},
            )

        summary = render_internal_summary(context=context, question=question)

        client = OpenAI(api_key=credential.api_key)
        messages = [
            {
                "role": "system",
                "content": (
                    "Voce e um assistente de seguranca ofensiva/defensiva do ARPIA. "
                    "Responda em portugues, focando em acoes praticas, mitigacao e proximos passos."  # noqa: E501
                ),
            },
            {
                "role": "user",
                "content": (
                    "Contexto fornecido pelo ARPIA (sanitizado):\n" + summary + "\n\nPergunta: " + question
                ),
            },
        ]

        try:
            completion = client.chat.completions.create(  # pragma: no cover - integracao externa
                model=model_name,
                messages=messages,
                temperature=0.2,
                max_tokens=600,
            )
        except RateLimitError as exc:  # pragma: no cover - integracao externa
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-quota-exceeded",
                user_message=(
                    "Quota do OpenAI esgotada ou bloqueada. Revise o plano de faturamento."
                ),
                exc=exc,
                log_level=logging.WARNING,
                log_exception=False,
            )
        except AuthenticationError as exc:  # pragma: no cover - integracao externa
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-authentication-failed",
                user_message="Chave OpenAI rejeitada. Confirme o valor informado.",
                exc=exc,
                log_level=logging.WARNING,
                log_exception=False,
            )
        except PermissionDeniedError as exc:  # pragma: no cover - integracao externa
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-permission-denied",
                user_message=(
                    "A chave nao possui permissao para acessar o modelo solicitado."
                ),
                exc=exc,
                log_level=logging.WARNING,
                log_exception=False,
            )
        except NotFoundError as exc:  # pragma: no cover - integracao externa
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-model-unavailable",
                user_message=(
                    f"Modelo {model_name} nao esta habilitado para a chave informada."
                ),
                exc=exc,
                log_level=logging.WARNING,
                log_exception=False,
            )
        except APIStatusError as exc:  # pragma: no cover - integracao externa
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-api-error",
                user_message="OpenAI retornou erro temporario. Tente novamente em instantes.",
                exc=exc,
            )
        except Exception as exc:  # pragma: no cover - falhas externas
            logger.exception("Falha inesperada ao consultar OpenAI: %s", exc)
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-unknown-error",
                user_message="Falha inesperada ao consultar o OpenAI.",
                exc=exc,
                log_exception=False,
            )

        choice = completion.choices[0] if completion.choices else None
        content = (choice.message.content if choice and choice.message else "").strip() if choice else ""
        if not content:
            return self._handle_openai_error(
                credential=credential,
                context=context,
                question=question,
                code="openai-empty-response",
                user_message="Resposta vazia recebida do OpenAI.",
                exc=None,
                log_level=logging.INFO,
                include_exception=False,
            )

        usage = getattr(completion, "usage", None)
        metadata: dict[str, Any] = {
            "mode": "openai",
            "status": "ok",
        }
        if usage:
            metadata["usage"] = {
                "prompt_tokens": getattr(usage, "prompt_tokens", None),
                "completion_tokens": getattr(usage, "completion_tokens", None),
                "total_tokens": getattr(usage, "total_tokens", None),
            }

        return ProviderAnswer(answer=content, metadata=metadata)

    def _handle_openai_error(
        self,
        *,
        credential: Optional[ProviderCredential],
        context: dict[str, Any],
        question: str,
        code: str,
        user_message: str,
        exc: Exception | None,
        log_level: int = logging.ERROR,
        log_exception: bool = True,
        include_exception: bool = True,
    ) -> ProviderAnswer:
        if exc:
            if log_exception:
                logger.log(log_level, "Falha ao consultar OpenAI (%s): %s", code, exc, exc_info=True)
            else:
                logger.log(log_level, "Falha ao consultar OpenAI (%s): %s", code, exc)
        elif log_exception:
            logger.log(log_level, "Falha ao consultar OpenAI (%s)", code)

        if credential is not None:
            self._store_error_on_credential(
                credential=credential,
                code=code,
                provider_message=str(exc) if exc else user_message,
            )

        metadata: dict[str, Any] = {
            "mode": "openai",
            "status": "error",
            "detail": code,
            "message": user_message,
            "fallback": True,
        }

        if include_exception and exc is not None:
            metadata.update(
                {
                    "error_type": exc.__class__.__name__,
                    "error_message": str(exc),
                    "error_code": getattr(exc, "code", None),
                    "status_code": getattr(exc, "status_code", None),
                }
            )

        answer = render_internal_summary(context=context, question=question)
        metadata.setdefault("note", self._FALLBACK_MESSAGE)
        return ProviderAnswer(answer=answer, metadata=metadata)

    def _store_error_on_credential(
        self,
        *,
        credential: ProviderCredential,
        code: str,
        provider_message: str,
    ) -> None:
        metadata = credential.metadata if isinstance(credential.metadata, dict) else {}
        metadata.update(
            {
                "last_error": {
                    "code": code,
                    "message": provider_message,
                    "timestamp": timezone.now().isoformat(),
                }
            }
        )
        credential.metadata = metadata
        credential.save(update_fields=["metadata", "updated_at"])


def validate_openai_api_key(
    *,
    api_key: str,
    model_name: str = "gpt-4o-mini",
    force_remote: bool | None = None,
) -> dict[str, Any]:
    """Valida acesso basico ao modelo solicitado.

    Quando ``force_remote`` nao for informado, respeita a configuracao
    ``ARPIA_AI_VALIDATE_PROVIDER_KEYS`` (default: desativado) para evitar
    chamadas externas em ambientes de teste.
    """

    timestamp = timezone.now().isoformat()

    if not api_key:
        return {
            "status": "error",
            "code": "missing-key",
            "checked_at": timestamp,
            "message": "Nenhuma chave informada.",
        }

    if OpenAI is None:
        return {
            "status": "error",
            "code": "sdk-missing",
            "checked_at": timestamp,
            "message": "SDK OpenAI nao instalado no servidor.",
        }

    if force_remote is None:
        should_validate = getattr(settings, "ARPIA_AI_VALIDATE_PROVIDER_KEYS", False)
    else:
        should_validate = force_remote

    if not should_validate:
        return {
            "status": "skipped",
            "code": "validation-disabled",
            "checked_at": timestamp,
            "message": "Validacao externa desativada.",
        }

    client = OpenAI(api_key=api_key)

    try:
        model = client.models.retrieve(model_name)  # pragma: no cover - integracao externa
    except AuthenticationError as exc:  # pragma: no cover - integracao externa
        return {
            "status": "error",
            "code": "authentication-failed",
            "checked_at": timestamp,
            "message": "Chave rejeitada pelo OpenAI.",
            "detail": str(exc),
        }
    except PermissionDeniedError as exc:  # pragma: no cover - integracao externa
        return {
            "status": "error",
            "code": "permission-denied",
            "checked_at": timestamp,
            "message": "Permissao negada para acessar o modelo informado.",
            "detail": str(exc),
        }
    except NotFoundError as exc:  # pragma: no cover - integracao externa
        return {
            "status": "error",
            "code": "model-not-found",
            "checked_at": timestamp,
            "message": f"Modelo {model_name} nao encontrado ou nao autorizado.",
            "detail": str(exc),
        }
    except RateLimitError as exc:  # pragma: no cover - integracao externa
        return {
            "status": "error",
            "code": "quota",
            "checked_at": timestamp,
            "message": "Quota insuficiente para validar a chave.",
            "detail": str(exc),
        }
    except APIStatusError as exc:  # pragma: no cover - integracao externa
        return {
            "status": "error",
            "code": "api-error",
            "checked_at": timestamp,
            "message": "Erro ao consultar API de modelos.",
            "detail": str(exc),
        }
    except Exception as exc:  # pragma: no cover - integracao externa
        logger.exception("Falha inesperada ao validar chave OpenAI: %s", exc)
        return {
            "status": "error",
            "code": "unknown",
            "checked_at": timestamp,
            "message": "Falha inesperada ao validar a chave.",
            "detail": str(exc),
        }

    model_id = getattr(model, "id", model_name)
    return {
        "status": "ok",
        "code": "model-access",
        "checked_at": timestamp,
        "message": f"Acesso confirmado ao modelo {model_id}.",
        "model": model_id,
    }


registry.register(OpenAIProviderAdapter())


def ensure_demo_provider() -> Provider:
    provider, _ = Provider.objects.get_or_create(
        slug=DEMO_PROVIDER_SLUG,
        defaults={
            "name": "Demo Advisor",
            "description": "Assistente interno usado na demonstracao do modulo IA.",
        },
    )
    return provider


def ensure_openai_provider() -> Provider:
    provider, _ = Provider.objects.get_or_create(
        slug=OPENAI_PROVIDER_SLUG,
        defaults={
            "name": "OpenAI",
            "description": "Integracao com os modelos OpenAI para recomendacoes contextuais.",
            "metadata": {"default_model": "gpt-4o-mini"},
        },
    )
    return provider


def resolve_provider_for_user(
    *, user, project
) -> tuple[Provider, Optional[ProviderCredential]]:
    openai_provider = ensure_openai_provider()
    credential: Optional[ProviderCredential] = None
    if user is not None:
        credential = (
            ProviderCredential.objects.filter(provider=openai_provider, owner=user)
            .order_by("created_at")
            .first()
        )
        if credential is not None:
            return openai_provider, credential

    provider = ensure_demo_provider()
    return provider, None


__all__ = [
    "BaseProviderAdapter",
    "DemoProviderAdapter",
    "OpenAIProviderAdapter",
    "ProviderAnswer",
    "ProviderRegistry",
    "ensure_demo_provider",
    "ensure_openai_provider",
    "registry",
    "resolve_provider_for_user",
]
