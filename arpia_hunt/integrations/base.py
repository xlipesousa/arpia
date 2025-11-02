from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module
from types import ModuleType


@dataclass(slots=True)
class IntegrationError(RuntimeError):
    message: str
    retriable: bool = True

    def __str__(self) -> str:  # pragma: no cover - representação simples
        return self.message


def load_requests() -> ModuleType:
    try:
        return import_module("requests")
    except ModuleNotFoundError as exc:  # pragma: no cover - dependência opcional
        raise IntegrationError("Biblioteca requests não está disponível para integrações remotas.", retriable=False) from exc


__all__ = ["IntegrationError", "load_requests"]
