from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from ...models import AttackTactic
from ...services.attack_catalog import (
    CatalogImportError,
    load_catalog_from_fixture,
    load_from_pyattck,
    sync_attack_catalog,
)


DEFAULT_FIXTURE = Path(__file__).resolve().parent.parent.parent / "fixtures" / "attack_catalog.json"


class Command(BaseCommand):
    help = "Importa o catálogo MITRE ATT&CK para os modelos do Hunt."

    def add_arguments(self, parser):
        parser.add_argument(
            "--from-file",
            dest="from_file",
            help="Caminho para fixture JSON no formato Django (lista de objetos)",
        )
        parser.add_argument(
            "--matrix",
            dest="matrix",
            choices=[choice for choice, _label in AttackTactic.Matrix.choices],
            default=AttackTactic.Matrix.ENTERPRISE,
            help="Matriz ATT&CK a importar quando utilizar pyattck (default: enterprise).",
        )
        parser.add_argument(
            "--pyattck",
            dest="use_pyattck",
            action="store_true",
            help="Importa dados diretamente da biblioteca pyattck (requer dependência instalada).",
        )

    def handle(self, *args, **options):  # noqa: D401 - assinatura obrigatória
        try:
            dataset = self._load_dataset(options)
            result = sync_attack_catalog(
                tactics=dataset["tactics"],
                techniques=dataset["techniques"],
            )
        except CatalogImportError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(
            self.style.SUCCESS(
                f"Catálogo ATT&CK sincronizado: {result.tactics} táticas, {result.techniques} técnicas.",
            )
        )

    def _load_dataset(self, options):
        if options.get("use_pyattck"):
            return load_from_pyattck(matrix=options["matrix"])

        if options.get("from_file"):
            path = Path(options["from_file"]).expanduser().resolve()
        else:
            path = DEFAULT_FIXTURE

        return load_catalog_from_fixture(path)
