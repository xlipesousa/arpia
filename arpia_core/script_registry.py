from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SCRIPTS_DIR = BASE_DIR / "scripts" / "default"


@dataclass(frozen=True)
class ScriptDefinition:
    slug: str
    name: str
    filename: str
    description: str
    tags: List[str]
    category: str = "nmap"
    requires_hosts: bool = True
    requires_networks: bool = False
    requires_credentials: bool = False
    required_tool_slug: str | None = None

    @property
    def source_path(self) -> Path:
        return DEFAULT_SCRIPTS_DIR / self.filename

    def read_content(self) -> str:
        return self.source_path.read_text(encoding="utf-8")


DEFAULT_SCRIPTS: List[ScriptDefinition] = [
    ScriptDefinition(
        slug="rustscan-top-ports",
        name="Rustscan — Top 1000 TCP + UDP",
        filename="rustscan_top_ports.sh",
        description="Executa Rustscan nos hosts alvo usando top 1000 portas TCP e varredura UDP completa.",
        tags=["rustscan", "tcp", "udp", "recon"],
        requires_hosts=True,
        required_tool_slug="rustscan",
    ),
    ScriptDefinition(
        slug="nmap-quick-top1000",
        name="Nmap — Top 1000 TCP",
        filename="example_reset.sh",
        description=(
            "Varredura rápida com as 1000 portas TCP mais comuns usando SYN scan e fingerprint de serviços."
        ),
        tags=["nmap", "tcp", "top1000", "recon"],
        requires_hosts=True,
        required_tool_slug="nmap",
    ),
    ScriptDefinition(
        slug="nmap-discovery",
        name="Nmap — Descoberta de Redes",
        filename="nmap_discovery.sh",
        description="Ping sweep (-sn) em todas as redes cadastradas no projeto.",
        tags=["nmap", "discovery", "ping"],
        requires_hosts=False,
        requires_networks=True,
        required_tool_slug="nmap",
    ),
    ScriptDefinition(
        slug="nmap-full-tcp",
        name="Nmap — Full TCP",
        filename="nmap_full_tcp.sh",
        description="Varredura completa TCP com detecção de versões e sistema operacional.",
        tags=["nmap", "tcp", "service-detection"],
        requires_hosts=True,
        required_tool_slug="nmap",
    ),
    ScriptDefinition(
        slug="nmap-udp-top100",
        name="Nmap — Top 100 UDP",
        filename="nmap_udp_top100.sh",
        description="Varredura UDP nas 100 portas mais comuns utilizando --top-ports 100.",
        tags=["nmap", "udp", "recon"],
        requires_hosts=True,
        required_tool_slug="nmap",
    ),
]


def get_default_catalog() -> List[ScriptDefinition]:
    return DEFAULT_SCRIPTS


def get_default_by_slug(slug: str) -> Optional[ScriptDefinition]:
    for entry in DEFAULT_SCRIPTS:
        if entry.slug == slug:
            return entry
    return None


def get_default_by_filename(filename: str) -> Optional[ScriptDefinition]:
    for entry in DEFAULT_SCRIPTS:
        if entry.filename == filename:
            return entry
    return None


def catalog_map_by_filename() -> Dict[str, ScriptDefinition]:
    return {entry.filename: entry for entry in DEFAULT_SCRIPTS}


def iter_default_scripts() -> Iterable[ScriptDefinition]:
    return list(DEFAULT_SCRIPTS)
