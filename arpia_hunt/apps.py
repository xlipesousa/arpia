from django.apps import AppConfig


class ArpiaHuntConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "arpia_hunt"

    def ready(self) -> None:  # pragma: no cover - side effects de registro de signals
        from . import signals  # noqa: F401
