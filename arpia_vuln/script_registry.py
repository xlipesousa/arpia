from __future__ import annotations

from typing import Iterable, List, Optional

from arpia_core.models import Script
from arpia_core.script_registry import ScriptDefinition




VULN_DEFAULT_SCRIPTS: List[ScriptDefinition] = [
	ScriptDefinition(
		slug="nmap-targeted-open-ports",
		name="Nmap — Portas abertas focadas",
		filename="nmap_targeted_ports.sh",
		description="Executa Nmap (-sS -sV) apenas nas portas previamente descobertas para cada host do projeto.",
		tags=["nmap", "ports", "focused"],
		category="vuln",
		requires_hosts=True,
		required_tool_slug="nmap",
	),
	ScriptDefinition(
		slug="nmap-targeted-nse",
		name="Nmap — NSE focado",
		filename="nmap_targeted_nse.sh",
		description="Aplica scripts NSE (default,vuln,safe) apenas nas portas abertas previamente descobertas.",
		tags=["nmap", "nse", "focused"],
		category="vuln",
		requires_hosts=True,
		required_tool_slug="nmap",
	),
]


def iter_vuln_scripts() -> Iterable[ScriptDefinition]:
	return list(VULN_DEFAULT_SCRIPTS)


def get_vuln_script_by_slug(slug: str) -> Optional[ScriptDefinition]:
	for entry in VULN_DEFAULT_SCRIPTS:
		if entry.slug == slug:
			return entry
	return None


def sync_vuln_default_scripts() -> None:
	for entry in VULN_DEFAULT_SCRIPTS:
		try:
			content = entry.read_content()
		except FileNotFoundError:
			content = ""

		defaults = {
			"name": entry.name,
			"description": entry.description,
			"filename": entry.filename,
			"content": content,
			"kind": Script.Kind.DEFAULT,
			"tags": entry.tags,
			"source_path": str(entry.source_path),
			"required_tool_slug": entry.required_tool_slug or "",
		}

		Script.objects.update_or_create(
			owner=None,
			slug=entry.slug,
			defaults=defaults,
		)
