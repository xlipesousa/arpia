from __future__ import annotations

import os
from typing import Mapping

from .base import IntegrationError, load_requests

DEFAULT_ENDPOINT = "https://vulners.com/api/v3/search/id/"


def fetch_cve(cve: str) -> Mapping[str, object]:
    requests = load_requests()
    endpoint = os.getenv("ARPIA_HUNT_VULNERS_URL", DEFAULT_ENDPOINT)
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv("ARPIA_HUNT_VULNERS_API_KEY") or os.getenv("VULNERS_API_KEY")
    if api_key:
        headers["X-ApiKey"] = api_key

    timeout_value = os.getenv("ARPIA_HUNT_VULNERS_TIMEOUT", "10")
    try:
        timeout = float(timeout_value)
    except ValueError:
        timeout = 10.0

    try:
        response = requests.get(
            endpoint,
            params={"id": cve},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except Exception as exc:  # pragma: no cover - tratado como falha de integração
        raise IntegrationError(f"Falha ao consultar Vulners para {cve}: {exc}") from exc


__all__ = ["fetch_cve", "DEFAULT_ENDPOINT"]
