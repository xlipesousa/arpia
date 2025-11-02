from __future__ import annotations

import os
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandParser
from django.db.models import QuerySet
from django.utils import timezone

from arpia_hunt.enrichment import enrich_finding
from arpia_hunt.models import HuntFinding
from arpia_hunt.log_events import emit_hunt_log


class Command(BaseCommand):
    help = "Executa enriquecimento de metadados externos para findings do Hunt."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--project",
            dest="project_ids",
            nargs="*",
            help="Processa apenas findings de projetos específicos (UUID).",
        )
        parser.add_argument(
            "--limit",
            dest="limit",
            type=int,
            help="Limita o número de findings processados nesta execução.",
        )
        parser.add_argument(
            "--force",
            dest="force",
            action="store_true",
            help="Força reprocessamento mesmo que os perfis estejam dentro do TTL.",
        )
        parser.add_argument(
            "--remote",
            dest="remote",
            action="store_true",
            help="Força enriquecimento remoto, ignorando variável de ambiente.",
        )
        parser.add_argument(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            help="Apenas lista os findings elegíveis sem executar enriquecimento.",
        )

    def handle(self, *args, **options):
        project_ids = options.get("project_ids") or []
        limit = options.get("limit")
        force = options.get("force", False)
        remote = options.get("remote", False)
        dry_run = options.get("dry_run", False)

        queryset = self._build_queryset(project_ids)
        if limit:
            queryset = queryset[:limit]

        ttl_hours = int(os.getenv("ARPIA_HUNT_PROFILE_TTL_HOURS", "6"))
        reprofile_before = timezone.now() - timedelta(hours=max(1, ttl_hours))

        total = 0
        updated = 0
        skipped = 0

        for finding in queryset:
            total += 1
            if not force and finding.last_profiled_at and finding.last_profiled_at >= reprofile_before:
                skipped += 1
                continue

            if dry_run:
                self.stdout.write(f"[dry-run] Finding {finding.pk} seria enriquecido")
                skipped += 1
                continue

            records, changed = enrich_finding(
                finding,
                enable_remote=True if remote else None,
                force_refresh=force,
            )
            if changed:
                updated += 1
            else:
                skipped += 1

        emit_hunt_log(
            event_type="hunt.enrichment.batch",
            message="Execução batch de enriquecimento concluída.",
            component="hunt.enrichment",
            details={
                "total": total,
                "updated": updated,
                "skipped": skipped,
                "force": force,
                "remote": remote,
            },
            tags=["pipeline:hunt-enrichment", "batch"],
        )

        self.stdout.write(
            self.style.SUCCESS(
                f"Enriquecimento concluído — total={total} atualizados={updated} ignorados={skipped}"
            )
        )

    def _build_queryset(self, project_ids: list[str]) -> QuerySet[HuntFinding]:
        queryset = HuntFinding.objects.filter(is_active=True).order_by("-detected_at")
        if project_ids:
            queryset = queryset.filter(project_id__in=project_ids)
        return queryset
