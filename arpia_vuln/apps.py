from contextlib import suppress

from django.apps import AppConfig


class ArpiaVulnConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "arpia_vuln"

    def ready(self) -> None:  # pragma: no cover - inicialização defensiva
        with suppress(Exception):
            from .script_registry import sync_vuln_default_scripts

            sync_vuln_default_scripts()
