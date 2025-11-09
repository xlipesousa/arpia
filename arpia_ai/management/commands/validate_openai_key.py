from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from arpia_ai.models import ProviderCredential
from arpia_ai.services import ensure_openai_provider, validate_openai_api_key


class Command(BaseCommand):
    help = (
        "Valida se uma chave OpenAI possui acesso ao modelo configurado (padrao: gpt-4o-mini)."
        " E possivel usar --api-key ou --user para reutilizar a credencial cadastrada."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--api-key",
            dest="api_key",
            help="Chave OpenAI que sera validada.",
        )
        parser.add_argument(
            "--model",
            dest="model_name",
            help="Modelo que deve estar disponivel (default: modelo padrao do provedor OpenAI).",
        )
        parser.add_argument(
            "--user",
            dest="username",
            help="Usuario cujo cadastro de credencial sera reutilizado (exige --label opcional).",
        )
        parser.add_argument(
            "--label",
            dest="label",
            default="default",
            help="Label da credencial quando usado com --user (default: default).",
        )
        parser.add_argument(
            "--force",
            dest="force_remote",
            action="store_true",
            help="Forca a chamada remota mesmo que a validacao esteja desativada nas settings.",
        )

    def handle(self, *args, **options):
        provider = ensure_openai_provider()
        model_name = options.get("model_name") or provider.default_model or "gpt-4o-mini"
        api_key = options.get("api_key") or ""
        username = options.get("username")
        label = options.get("label") or "default"

        if not api_key and username:
            user_model = get_user_model()
            try:
                user = user_model.objects.get(username=username)
            except user_model.DoesNotExist as exc:  # pragma: no cover - erro informativo
                raise CommandError(f"Usuario '{username}' nao encontrado.") from exc

            credential = (
                ProviderCredential.objects.filter(provider=provider, owner=user, label=label)
                .order_by("created_at")
                .first()
            )
            if credential is None:  # pragma: no cover - erro informativo
                raise CommandError(
                    f"Nenhuma credencial do OpenAI encontrada para o usuario '{username}' com label '{label}'."
                )
            api_key = credential.api_key

        if not api_key:
            raise CommandError("Informe --api-key ou utilize --user para reutilizar uma credencial armazenada.")

        force_flag = options.get("force_remote")
        result = validate_openai_api_key(
            api_key=api_key,
            model_name=model_name,
            force_remote=True if force_flag else None,
        )

        status = result.get("status")
        code = result.get("code")
        message = result.get("message") or ""

        if status == "ok":
            model_id = result.get("model") or model_name
            checked_at = result.get("checked_at")
            self.stdout.write(
                self.style.SUCCESS(
                    f"Acesso confirmado ao modelo {model_id}. (status={status}, checked_at={checked_at})"
                )
            )
            return

        if status == "skipped":
            warn_message = (
                message
                or "Validacao nao executada. Habilite ARPIA_AI_VALIDATE_PROVIDER_KEYS para forcar a checagem."
            )
            self.stdout.write(self.style.WARNING(warn_message))
            return

        detail = result.get("detail")
        pieces = [message or "Falha na validacao da chave OpenAI."]
        if code:
            pieces.append(f"code={code}")
        if detail:
            pieces.append(f"detail={detail}")
        raise CommandError(" | ".join(pieces))
