from __future__ import annotations

from django.core.management.base import BaseCommand, CommandParser

from arpia_hunt.services import SyncResult, synchronize_findings


class Command(BaseCommand):
    help = "Sincroniza achados do módulo de vulnerabilidades para o Hunt."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--project",
            dest="project_ids",
            nargs="*",
            help="Filtra sincronização para um ou mais projetos (UUID).",
        )
        parser.add_argument(
            "--limit",
            dest="limit",
            type=int,
            help="Limita a quantidade de findings processados nesta execução.",
        )
        parser.add_argument(
            "--no-log",
            dest="no_log",
            action="store_true",
            help="Não persiste HuntSyncLog (útil para execuções temporárias).",
        )

    def handle(self, *args, **options):
        project_ids = options.get("project_ids")
        limit = options.get("limit")
        create_log = not options.get("no_log")

        result: SyncResult = synchronize_findings(
            project_ids=project_ids,
            limit=limit,
            create_log=create_log,
            audit_logs=create_log,
        )

        self.stdout.write(self.style.SUCCESS(
            f"Sincronização concluída — total={result.total} criados={result.created} "
            f"atualizados={result.updated} ignorados={result.skipped}"
        ))
