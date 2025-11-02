"""Compat layer for legacy imports (arpia_hunt.services)."""

from .services.sync import SyncResult, synchronize_findings  # noqa: F401

__all__ = ["SyncResult", "synchronize_findings"]
