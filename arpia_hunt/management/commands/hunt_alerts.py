from __future__ import annotations

from typing import Iterable

from django.core.management.base import BaseCommand

from ...models import HuntFinding
from ...services.alerts import evaluate_alerts_for_finding, evaluate_all_findings


class Command(BaseCommand):
    help = "Avalia os thresholds do Hunt e ativa alertas operacionais."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--finding",
            dest="finding",
            help="UUID do HuntFinding a ser avaliado",
        )
        parser.add_argument(
            "--project",
            dest="project",
            help="Filtra findings por projeto (UUID)",
        )
        parser.add_argument(
            "--limit",
            dest="limit",
            type=int,
            help="Limita a quantidade de findings avaliados (ordenados por atualização recente)",
        )

    def handle(self, *args, **options) -> None:  # noqa: D401 assinatura obrigatória
        finding_id = options.get("finding")
        if finding_id:
            result = evaluate_alerts_for_finding(finding_id)
            triggered = len(result["triggered"])
            resolved = len(result["resolved"])
            self.stdout.write(
                self.style.SUCCESS(
                    f"Alerts avaliados para {finding_id}: {triggered} ativados, {resolved} resolvidos."
                )
            )
            return

        queryset: Iterable[HuntFinding] = HuntFinding.objects.select_related("project", "vulnerability").order_by(
            "-updated_at"
        )
        project_id = options.get("project")
        if project_id:
            queryset = queryset.filter(project_id=project_id)

        limit = options.get("limit")
        if limit is not None and limit > 0:
            queryset = queryset[:limit]

        summary = evaluate_all_findings(queryset)
        self.stdout.write(
            self.style.SUCCESS(
                f"Alerts avaliados: {summary['triggered']} ativados, {summary['resolved']} resolvidos."
            )
        )
