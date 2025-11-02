from __future__ import annotations

import os
from typing import Mapping

from .base import IntegrationError, load_requests

DEFAULT_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve: str) -> Mapping[str, object]:
    requests = load_requests()
    endpoint = os.getenv("ARPIA_HUNT_NVD_URL", DEFAULT_ENDPOINT)
    headers: dict[str, str] = {}
    api_key = os.getenv("ARPIA_HUNT_NVD_API_KEY") or os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    timeout_value = os.getenv("ARPIA_HUNT_NVD_TIMEOUT", "12")
    try:
        timeout = float(timeout_value)
    except ValueError:
        timeout = 12.0

    try:
        response = requests.get(
            endpoint,
            params={"cveId": cve},
            headers=headers,
            timeout=timeout,
        )
        response.raise_for_status()
        return response.json()
    except Exception as exc:  # pragma: no cover - tratamos via IntegrationError
        raise IntegrationError(f"Falha ao consultar NVD para {cve}: {exc}") from exc


__all__ = ["fetch_cve", "DEFAULT_ENDPOINT"]
