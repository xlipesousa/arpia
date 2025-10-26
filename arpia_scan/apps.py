import logging

from django.apps import AppConfig
from django.conf import settings
from django.db.backends.signals import connection_created


logger = logging.getLogger(__name__)


def _configure_sqlite_connection(sender, connection, **kwargs):
    if connection.vendor != "sqlite":  # pragma: no cover - apenas para sqlite
        return

    timeout_seconds = settings.DATABASES.get("default", {}).get("OPTIONS", {}).get("timeout", 20)
    try:
        timeout_seconds = int(timeout_seconds)
    except (TypeError, ValueError):  # pragma: no cover - defesa
        timeout_seconds = 20

    busy_timeout_ms = max(1000, timeout_seconds * 1000)

    try:
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms};")
        cursor.close()
    except Exception:  # pragma: no cover - loga mas não interrompe
        logger.exception("Falha ao configurar conexão SQLite para execução simultânea")


class ArpiaScanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'arpia_scan'

    def ready(self):  # pragma: no cover - inicialização
        if settings.DATABASES.get("default", {}).get("ENGINE") == "django.db.backends.sqlite3":
            connection_created.connect(
                _configure_sqlite_connection,
                dispatch_uid="arpia_scan.configure_sqlite_connection",
            )
