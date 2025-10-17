from __future__ import annotations

import json
from typing import Iterable, List

from .observations import ObservedEndpoint, ObservedPort


def parse_rustscan_payload(payload: str | dict | Iterable[dict]) -> List[ObservedEndpoint]:
    if isinstance(payload, str):
        try:
            data = json.loads(payload or "[]")
        except json.JSONDecodeError:
            return []
    else:
        data = payload

    if isinstance(data, dict):
        data = [data]

    endpoints: list[ObservedEndpoint] = []

    for entry in data or []:
        host = entry.get("host") or entry.get("address") or entry.get("ip")
        if not host:
            continue

        endpoint = ObservedEndpoint(host=host)
        for port_info in entry.get("ports", []):
            try:
                port_number = int(port_info.get("port"))
            except (TypeError, ValueError):
                continue
            state = port_info.get("status", "open")
            if state != "open":
                continue

            observed_port = ObservedPort(
                port=port_number,
                protocol=port_info.get("protocol", "tcp"),
                state=state,
                service=port_info.get("service"),
                source="rustscan",
            )
            endpoint.add_port(observed_port)

        if endpoint.ports:
            endpoints.append(endpoint)

    return endpoints
