from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List

from django.conf import settings
from django.core.management.base import BaseCommand, CommandParser

from arpia_hunt.log_events import emit_hunt_log


def _build_entries(python_path: str, manage_path: Path, *, limit: int) -> List[str]:
    base_dir = manage_path.parent
    env_vars = os.getenv("ARPIA_HUNT_CRON_ENV", "").strip()
    exports = []
    if env_vars:
        exports = [line.strip() for line in env_vars.splitlines() if line.strip()]
    cron_prefix = " && ".join(exports) + " && " if exports else ""
    return [
        f"*/30 * * * * {cron_prefix}{python_path} {manage_path} hunt_sync",
        f"0 * * * * {cron_prefix}{python_path} {manage_path} hunt_enrich --limit {limit}",
    ]


def _merge_crontab(existing: str, entries: Iterable[str]) -> str:
    lines = [line.rstrip() for line in existing.splitlines() if line.strip() and "hunt_" not in line]
    lines.extend(entries)
    return "\n".join(lines) + "\n"


class Command(BaseCommand):
    help = "Exibe ou instala entries de agendamento para hunt_sync e hunt_enrich."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--install",
            action="store_true",
            help="Aplica as entradas diretamente via crontab.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=100,
            help="Limite padrão para o job hunt_enrich (default: 100).",
        )
        parser.add_argument(
            "--python",
            dest="python_path",
            help="Caminho explícito para o interpretador Python a ser usado no cron.",
        )

    def handle(self, *args, **options):
        limit = max(1, options.get("limit") or 100)
        python_path = options.get("python_path") or sys.executable
        manage_path = Path(settings.BASE_DIR) / "manage.py"
        entries = _build_entries(python_path, manage_path, limit=limit)

        if options.get("install"):
            self._install(entries)
            emit_hunt_log(
                event_type="hunt.scheduler.installed",
                message="Cron do Hunt configurado/atualizado.",
                component="hunt.scheduler",
                details={
                    "python_path": python_path,
                    "limit": limit,
                },
                tags=["pipeline:hunt-schedule", "action:install"],
            )
        else:
            emit_hunt_log(
                event_type="hunt.scheduler.preview",
                message="Pré-visualização das entradas de cron do Hunt.",
                component="hunt.scheduler",
                details={
                    "python_path": python_path,
                    "limit": limit,
                },
                tags=["pipeline:hunt-schedule", "action:preview"],
            )

        for line in entries:
            self.stdout.write(line)

    def _install(self, entries: Iterable[str]) -> None:
        current = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
        )
        existing = ""
        if current.returncode == 0:
            existing = current.stdout
        merged = _merge_crontab(existing, entries)
        subprocess.run([
            "crontab",
            "-",
        ], input=merged, text=True, check=True)

