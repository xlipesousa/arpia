import logging
from django.apps import AppConfig
from importlib import import_module


class ArpiaCoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "arpia_core"
    verbose_name = "ARPIA Core"

    def ready(self):
        # tenta registrar signals/seeds se o módulo existir
        logger = logging.getLogger(__name__)
        try:
            import_module("arpia_core.signals")
            logger.debug("arpia_core: signals carregados")
        except ModuleNotFoundError:
            logger.debug("arpia_core: signals não encontrados (ok)")
        except Exception as exc:  # pragma: no cover - debug helper
            logger.exception("arpia_core: erro ao carregar signals: %s", exc)
