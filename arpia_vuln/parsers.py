from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
FLOAT_PATTERN = re.compile(r"\d+(?:\.\d+)?")


@dataclass(slots=True)
class ParsedFinding:
	source: str
	scanner: str
	title: str
	summary: str
	severity: str
	host: str
	service: str
	port: Optional[int]
	protocol: str
	cves: List[str]
	cvss_score: Optional[float]
	cvss_vector: str
	data: Dict[str, Any]
	references: List[str]

	def fingerprint(self) -> tuple:
		return (
			self.source,
			self.host.lower(),
			self.port or 0,
			tuple(sorted({cve.upper() for cve in self.cves})),
			self.title.strip().lower(),
		)


def parse_nmap_vulnerabilities(
	xml_payload: str,
	*,
	source: str,
	file_path: Optional[str] = None,
) -> List[ParsedFinding]:
	if not xml_payload or not xml_payload.strip():
		return []

	try:
		root = ET.fromstring(xml_payload)
	except ET.ParseError:
		return []

	findings: List[ParsedFinding] = []

	for host_node in root.findall("host"):
		host_addr = _extract_host_address(host_node)
		if not host_addr:
			host_addr = "unknown"

		for port_node in host_node.findall("ports/port"):
			state_node = port_node.find("state")
			if state_node is not None and (state_node.get("state") or "").lower() != "open":
				continue

			port_number = _safe_int(port_node.get("portid"))
			protocol = (port_node.get("protocol") or "tcp").lower()
			service_node = port_node.find("service")
			service_name = (service_node.get("name") if service_node is not None else "") or ""

			for script_node in port_node.findall("script"):
				parsed = _parse_nmap_script(
					script_node,
					host_addr,
					port_number,
					protocol,
					service_name,
					source=source,
					file_path=file_path,
				)
				if parsed:
					findings.append(parsed)

	return findings


def parse_greenbone_vulnerabilities(
	xml_payload: str,
	*,
	file_path: Optional[str] = None,
) -> List[ParsedFinding]:
	if not xml_payload or not xml_payload.strip():
		return []

	try:
		root = ET.fromstring(xml_payload)
	except ET.ParseError:
		return []

	results: List[ParsedFinding] = []

	for result_elem in root.findall(".//result"):
		host = (result_elem.findtext("host") or result_elem.findtext("ip") or "").strip()
		if not host:
			continue

		port_text = (result_elem.findtext("port") or "").strip()
		port_number, protocol = _parse_port(port_text)

		nvt_elem = result_elem.find("nvt")
		title = _first_non_empty(
			result_elem.findtext("name"),
			nvt_elem.findtext("name") if nvt_elem is not None else None,
		)
		if not title:
			title = "Greenbone finding"

		description = _first_non_empty(
			result_elem.findtext("description"),
			nvt_elem.findtext("summary") if nvt_elem is not None else None,
			result_elem.findtext("original_severity"),
		)
		if not description:
			description = result_elem.findtext("details") or ""

		severity_label = (result_elem.findtext("threat") or "").strip()
		severity_score = _safe_float(result_elem.findtext("severity"))

		if nvt_elem is not None:
			if severity_score is None:
				severity_score = _safe_float(nvt_elem.findtext("cvss_base"))
			cvss_vector = (nvt_elem.findtext("cvss_vector") or nvt_elem.findtext("cvss_base_vector") or "").strip()
		else:
			cvss_vector = ""

		severity = _combine_severity(severity_label, severity_score)
		cves = _collect_cves(
			result_elem.findall("cve")
		)
		if nvt_elem is not None:
			cves.extend(_collect_cves(nvt_elem.findall("cve")))
		additional_texts = [description, severity_label, cvss_vector]
		cves.extend(_collect_cves(additional_texts))
		cves = sorted({cve.upper() for cve in cves})

		references = _collect_nvt_references(nvt_elem)
		cvss_final = severity_score if severity_score is not None else _guess_cvss_from_text(description)

		data = {
			"source": "greenbone",
			"file_path": file_path,
			"raw_description": description,
			"threat": severity_label,
			"nvt_oid": nvt_elem.findtext("oid") if nvt_elem is not None else None,
			"nvt_tags": _parse_nvt_tags(nvt_elem.findtext("tags")) if nvt_elem is not None else {},
		}

		finding = ParsedFinding(
			source="greenbone",
			scanner="greenbone",
			title=title.strip(),
			summary=description.strip(),
			severity=severity,
			host=host,
			service=(nvt_elem.findtext("family") if nvt_elem is not None else "") or "",
			port=port_number,
			protocol=protocol,
			cves=cves,
			cvss_score=cvss_final,
			cvss_vector=cvss_vector,
			data=data,
			references=references,
		)
		results.append(finding)

	return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_host_address(host_node: ET.Element) -> Optional[str]:
	address = host_node.find("address[@addrtype='ipv4']") or host_node.find("address[@addrtype='ipv6']")
	if address is None:
		address = host_node.find("address")
	return address.get("addr") if address is not None else None


def _parse_nmap_script(
	script_node: ET.Element,
	host: str,
	port: Optional[int],
	protocol: str,
	service_name: str,
	*,
	source: str,
	file_path: Optional[str] = None,
) -> Optional[ParsedFinding]:
	script_id = script_node.get("id") or "nmap-script"
	raw_output = script_node.get("output") or ""

	texts: List[str] = [raw_output]
	values_by_key: Dict[str, List[str]] = {}

	for elem in script_node.iter("elem"):
		key = (elem.get("key") or "").strip().lower()
		text = (elem.text or "").strip()
		if not text:
			continue
		texts.append(text)
		if key:
			values_by_key.setdefault(key, []).append(text)
		else:
			values_by_key.setdefault("_", []).append(text)

	for table in script_node.iter("table"):
		key = (table.get("key") or "").strip().lower()
		if key:
			values_by_key.setdefault(key, [])
		for elem in table.findall("elem"):
			text = (elem.text or "").strip()
			if not text:
				continue
			texts.append(text)
			sub_key = (elem.get("key") or "").strip().lower()
			if sub_key:
				values_by_key.setdefault(sub_key, []).append(text)
			if key:
				values_by_key.setdefault(key, []).append(text)

	cves = _collect_cves(texts)
	cvss_candidates = _collect_cvss_candidates(values_by_key.get("cvss", []))
	if not cvss_candidates and "cvss" in values_by_key:
		cvss_candidates = _collect_cvss_candidates(values_by_key["cvss"])
	if not cvss_candidates:
		cvss_candidates = _collect_cvss_candidates(texts)
	cvss_score = max(cvss_candidates) if cvss_candidates else None
	cvss_vector = _first_non_empty(
		values_by_key.get("cvss_vector", [None])[0] if values_by_key.get("cvss_vector") else None,
		values_by_key.get("vector", [None])[0] if values_by_key.get("vector") else None,
	)

	state_text = _first_non_empty(
		values_by_key.get("state", [None])[0] if values_by_key.get("state") else None,
		raw_output,
	)
	severity = _combine_severity(state_text, cvss_score)

	if not cves and (state_text or "").lower().find("vulnerable") == -1:
		return None

	title = _first_non_empty(
		values_by_key.get("title", [None])[0] if values_by_key.get("title") else None,
		script_id.replace("_", " ").title(),
	)
	description_parts = values_by_key.get("description") or []
	if not description_parts:
		description_parts = [raw_output]

	references = values_by_key.get("refs", []) or values_by_key.get("references", [])
	ids = values_by_key.get("ids", [])
	for entry in ids:
		if ":" in entry:
			_, value = entry.split(":", 1)
			cves.extend(_collect_cves([value]))

	cves = sorted({cve.upper() for cve in cves})
	data = {
		"source": "nmap",
		"script_id": script_id,
		"file_path": file_path,
		"raw_output": raw_output.strip(),
		"values": values_by_key,
	}

	return ParsedFinding(
		source=source,
		scanner="nmap",
		title=title.strip(),
		summary="\n".join(part for part in description_parts if part).strip(),
		severity=severity,
		host=host,
		service=service_name or script_id,
		port=port,
		protocol=protocol,
		cves=cves,
		cvss_score=cvss_score,
		cvss_vector=cvss_vector or "",
		data=data,
		references=references,
	)


def _collect_cves(entries: Iterable[Any]) -> List[str]:
	found: List[str] = []
	for entry in entries or []:
		if entry is None:
			continue
		text = str(entry)
		for match in CVE_PATTERN.findall(text):
			found.append(match.upper())
	return found


def _collect_cvss_candidates(entries: Iterable[str]) -> List[float]:
	candidates: List[float] = []
	for entry in entries or []:
		if entry is None:
			continue
		for match in FLOAT_PATTERN.findall(str(entry)):
			value = _safe_float(match)
			if value is not None:
				candidates.append(value)
	return candidates


def _combine_severity(label: Optional[str], score: Optional[float]) -> str:
	score_severity = _severity_from_score(score)
	label_severity = _severity_from_label(label)
	priorities = {
		"critical": 5,
		"high": 4,
		"medium": 3,
		"low": 2,
		"info": 1,
		"unknown": 0,
	}
	if priorities[label_severity] >= priorities[score_severity]:
		return label_severity
	return score_severity


def _severity_from_score(score: Optional[float]) -> str:
	if score is None:
		return "unknown"
	if score >= 9.0:
		return "critical"
	if score >= 7.0:
		return "high"
	if score >= 4.0:
		return "medium"
	if score > 0:
		return "low"
	return "info"


def _severity_from_label(label: Optional[str]) -> str:
	if not label:
		return "unknown"
	label_norm = label.strip().lower()
	if any(word in label_norm for word in ("critical", "grave")):
		return "critical"
	if any(word in label_norm for word in ("high", "alto", "exploitable")):
		return "high"
	if any(word in label_norm for word in ("medium", "médio", "medium")):
		return "medium"
	if any(word in label_norm for word in ("low", "baixo")):
		return "low"
	if any(word in label_norm for word in ("info", "informational", "log")):
		return "info"
	if "vulnerable" in label_norm:
		return "high"
	return "unknown"


def _safe_int(value: Any) -> Optional[int]:
	try:
		return int(str(value))
	except (TypeError, ValueError):
		return None


def _safe_float(value: Any) -> Optional[float]:
	try:
		return float(str(value))
	except (TypeError, ValueError):
		return None


def _first_non_empty(*values: Optional[str]) -> str:
	for value in values:
		if value:
			text = str(value).strip()
			if text:
				return text
	return ""


def _parse_port(port_text: str) -> tuple[Optional[int], str]:
	if not port_text:
		return None, ""
	port_text = port_text.strip()
	match = re.search(r"(\d+)/(tcp|udp)", port_text.lower())
	if match:
		return _safe_int(match.group(1)), match.group(2)
	if port_text.isdigit():
		return int(port_text), "tcp"
	return None, ""


def _collect_nvt_references(nvt_elem: Optional[ET.Element]) -> List[str]:
	if nvt_elem is None:
		return []
	references: List[str] = []
	for ref in nvt_elem.findall("refs/ref"):
		text = (ref.text or "").strip()
		if text:
			references.append(text)
	return references


def _parse_nvt_tags(tags: Optional[str]) -> Dict[str, str]:
	if not tags:
		return {}
	items = {}
	for part in str(tags).split("|"):
		if "=" not in part:
			continue
		key, value = part.split("=", 1)
		items[key.strip()] = value.strip()
	return items


def _guess_cvss_from_text(text: str) -> Optional[float]:
	if not text:
		return None
	candidates = _collect_cvss_candidates([text])
	return max(candidates) if candidates else None
