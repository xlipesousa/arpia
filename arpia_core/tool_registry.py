from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional

@dataclass(frozen=True)
class ToolDefinition:
    slug: str
    name: str
    path: str
    description: str
    category: str = "scanner"


DEFAULT_TOOLS: List[ToolDefinition] = [
    ToolDefinition(
        slug="rustscan",
        name="Rustscan",
        path="/home/kali/.cargo/bin/rustscan",
        description="Scanner TCP assíncrono focado em agilidade e evasão.",
        category="scanner",
    ),
    ToolDefinition(
        slug="nmap",
        name="Nmap",
        path="/usr/bin/nmap",
        description="Scanner de rede clássico amplamente utilizado.",
        category="scanner",
    ),
    ToolDefinition(
        slug="gvm",
        name="Greenbone Vulnerability Manager (gvm-cli)",
        path="/usr/bin/gvm-cli",
        description="Cliente GMP para controle do Greenbone/OpenVAS via linha de comando.",
        category="vulnerability",
    ),
    ToolDefinition(
        slug="searchsploit",
        name="Searchsploit",
        path="/usr/bin/searchsploit",
        description="Cliente Exploit-DB offline para consulta de exploits e PoCs.",
        category="research",
    ),
]


def get_default_tools() -> List[ToolDefinition]:
    return list(DEFAULT_TOOLS)


def get_default_by_slug(slug: str) -> Optional[ToolDefinition]:
    for entry in DEFAULT_TOOLS:
        if entry.slug == slug:
            return entry
    return None


def sync_default_tools_for_user(user) -> None:
    """Garantir que o usuário possua o kit básico de ferramentas."""
    if not user or not getattr(user, "is_authenticated", False):
        return

    from .models import Tool  # import tardio para evitar import circular

    for definition in DEFAULT_TOOLS:
        Tool.objects.get_or_create(
            owner=user,
            slug=definition.slug,
            defaults={
                "name": definition.name,
                "description": definition.description,
                "path": definition.path,
                "category": definition.category,
            },
        )


__all__ = [
    "ToolDefinition",
    "DEFAULT_TOOLS",
    "get_default_tools",
    "get_default_by_slug",
    "sync_default_tools_for_user",
]
