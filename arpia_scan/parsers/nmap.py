from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import List

from .observations import ObservedEndpoint, ObservedPort


def parse_nmap_xml(xml_payload: str) -> List[ObservedEndpoint]:
    if not xml_payload:
        return []

    try:
        root = ET.fromstring(xml_payload)
    except ET.ParseError:
        return []

    endpoints: list[ObservedEndpoint] = []

    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        if status_node is not None and status_node.get("state") == "down":
            continue

        address_node = host_node.find("address[@addrtype='ipv4']") or host_node.find("address")
        if address_node is None:
            continue
        host_addr = address_node.get("addr", "unknown")
        hostname = None
        hostname_node = host_node.find("hostnames/hostname")
        if hostname_node is not None:
            hostname = hostname_node.get("name")

        os_match = None
        os_node = host_node.find("os/osmatch")
        if os_node is not None:
            os_match = os_node.get("name")

        endpoint = ObservedEndpoint(host=host_addr, hostname=hostname, os_name=os_match)

        for port_node in host_node.findall("ports/port"):
            port_state = port_node.find("state")
            state = port_state.get("state") if port_state is not None else "unknown"
            if state != "open":
                continue

            protocol = port_node.get("protocol", "tcp")
            try:
                port_number = int(port_node.get("portid", "0"))
            except ValueError:
                continue

            service_node = port_node.find("service")
            service_name = service_node.get("name") if service_node is not None else None
            product = service_node.get("product") if service_node is not None else None
            version = service_node.get("version") if service_node is not None else None

            observed_port = ObservedPort(
                port=port_number,
                protocol=protocol,
                state=state,
                service=service_name,
                product=product,
                version=version,
                source="nmap",
            )
            endpoint.add_port(observed_port)

        if endpoint.ports:
            endpoints.append(endpoint)

    return endpoints
