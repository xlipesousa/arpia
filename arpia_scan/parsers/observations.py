from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

SEVERITY_PORT_MAP: Dict[int, str] = {
    22: "medium",
    80: "medium",
    443: "medium",
    445: "high",
    3389: "high",
    5900: "medium",
}
DEFAULT_SEVERITY = "low"


@dataclass
class ObservedPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    source: str = "nmap"

    @property
    def severity(self) -> str:
        return SEVERITY_PORT_MAP.get(self.port, DEFAULT_SEVERITY)


@dataclass
class ObservedEndpoint:
    host: str
    hostname: Optional[str] = None
    ports: List[ObservedPort] = field(default_factory=list)

    def add_port(self, observed_port: ObservedPort) -> None:
        key = (observed_port.port, observed_port.protocol)
        for existing in self.ports:
            if (existing.port, existing.protocol) == key:
                _merge_port(existing, observed_port)
                return
        self.ports.append(observed_port)
        self.ports.sort(key=lambda p: (p.port, p.protocol))

    @property
    def severity(self) -> str:
        severities = [port.severity for port in self.ports if port.state == "open"]
        if not severities:
            return DEFAULT_SEVERITY
        if "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        return DEFAULT_SEVERITY


@dataclass
class ObservedService:
    name: str
    endpoints: List[Tuple[str, ObservedPort]] = field(default_factory=list)

    def add_endpoint(self, host: str, port: ObservedPort) -> None:
        self.endpoints.append((host, port))


def _merge_port(original: ObservedPort, new: ObservedPort) -> None:
    original.state = original.state or new.state
    original.service = original.service or new.service
    original.product = original.product or new.product
    original.version = original.version or new.version
    if new.source == "nmap":
        original.source = new.source


def merge_observations(endpoints: Iterable[ObservedEndpoint]) -> Dict[str, object]:
    endpoint_map: Dict[str, ObservedEndpoint] = {}
    service_map: Dict[str, ObservedService] = {}

    for endpoint in endpoints:
        combined = endpoint_map.setdefault(endpoint.host, ObservedEndpoint(host=endpoint.host, hostname=endpoint.hostname))
        for port in endpoint.ports:
            combined.add_port(port)
            service_name = port.service or "desconhecido"
            service_entry = service_map.setdefault(service_name, ObservedService(name=service_name))
            service_entry.add_endpoint(endpoint.host, port)

    hosts_payload = [
        {
            "host": endpoint.host,
            "hostname": endpoint.hostname,
            "severity": endpoint.severity,
            "ports": [
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "state": port.state,
                    "service": port.service,
                    "product": port.product,
                    "version": port.version,
                    "severity": port.severity,
                }
                for port in endpoint.ports
                if port.state == "open"
            ],
        }
        for endpoint in sorted(endpoint_map.values(), key=lambda e: e.host)
    ]

    services_payload = [
        {
            "service": service.name,
            "occurrences": [
                {
                    "host": host,
                    "port": port.port,
                    "protocol": port.protocol,
                    "severity": port.severity,
                }
                for host, port in sorted(service.endpoints, key=lambda item: (item[0], item[1].port))
            ],
        }
        for service in sorted(service_map.values(), key=lambda s: s.name or "")
    ]

    open_ports = sum(len(host["ports"]) for host in hosts_payload)

    return {
        "targets": {
            "hosts_count": len(hosts_payload),
            "open_ports": open_ports,
            "hosts": hosts_payload,
        },
        "services": {
            "count": len(services_payload),
            "items": services_payload,
        },
    }
