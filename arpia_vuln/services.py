from __future__ import annotations

import base64
import getpass
import html
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from xml.etree import ElementTree as ET

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.utils.text import slugify

from arpia_core.models import Project, Script, Tool
from arpia_core.tool_registry import sync_default_tools_for_user
from arpia_core.views import build_project_macros, render_script_with_macros
from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .models import VulnScanSession, VulnTask
from .script_registry import get_vuln_script_by_slug, sync_vuln_default_scripts

__all__ = [
    "GreenboneCliError",
    "GreenboneConfig",
    "VulnGreenboneExecutionError",
    "VulnScriptExecutionError",
    "VulnSessionCanceled",
    "plan_vulnerability_session",
    "cancel_vulnerability_session",
    "run_greenbone_scan",
    "run_targeted_nmap_scans",
    "run_vulnerability_pipeline",
    "run_vulnerability_pipeline_async",
    "ensure_session_is_active",
]


logger = logging.getLogger(__name__)


class VulnScriptExecutionError(Exception):
    """Erro durante execução de scripts da sessão de vulnerabilidades."""


class GreenboneCliError(Exception):
    """Erro ao interagir com gvm-cli."""


class VulnGreenboneExecutionError(VulnScriptExecutionError):
    """Erro fatal na execução do fluxo Greenbone."""


class VulnSessionCanceled(Exception):
    """Sessão de vulnerabilidades cancelada pelo usuário."""


TARGETED_ACTION = "targeted"
GREENBONE_ACTION = "greenbone"
TARGETED_STDOUT_RE = re.compile(r"Nmap .*? para\s+(?P<host>\S+)\s+\((?P<ports>[^)]+)\)", re.IGNORECASE)
TARGETED_SCRIPTS: Sequence[Tuple[str, str, str]] = (
    ("nmap-targeted-open-ports", "Nmap Targeted Ports", VulnTask.Kind.SERVICE_ENUMERATION),
    ("nmap-targeted-nse", "Nmap NSE focado", VulnTask.Kind.SCRIPT),
)

FALLBACK_SCRIPTS: Dict[str, Dict[str, str]] = {
    "nmap-targeted-open-ports": {
        "name": "Nmap — portas abertas",
        "filename": "nmap_targeted_open_ports.sh",
        "description": "Executa Nmap com foco nas portas previamente descobertas.",
        "content": textwrap.dedent(
            """
            #!/bin/bash
            set -euo pipefail
            TARGETS_WITH_PORTS=$(cat <<'EOF'
{{SCAN_TARGETS_WITH_PORTS}}
EOF
)
            AGGREGATED_PORTS="{{SCAN_OPEN_PORTS}}"

            echo "[ARPIA] Executando Nmap targeted ports"
            if [[ -n "${TARGETS_WITH_PORTS//[[:space:]]/}" ]]; then
                echo "Targets e portas recebidos:" >&2
                printf '%s\n' "${TARGETS_WITH_PORTS}" >&2
            elif [[ -n "${AGGREGATED_PORTS//[[:space:]]/}" ]]; then
                echo "Nenhum snapshot detalhado encontrado; utilizando portas agregadas: ${AGGREGATED_PORTS}" >&2
            else
                echo "Nenhum alvo ou porta disponível nas macros." >&2
            fi
            exit 0
            """
        ).strip(),
        "required_tool_slug": "nmap",
    },
}


def ensure_session_is_active(session: VulnScanSession) -> None:
    """Atualiza o estado da sessão e interrompe o fluxo se estiver cancelada."""
    if not isinstance(session, VulnScanSession) or session.pk is None:
        return
    session.refresh_from_db(fields=["status", "finished_at", "last_error", "updated_at"])
    if session.status == VulnScanSession.Status.CANCELED:
        raise VulnSessionCanceled("Sessão cancelada pelo usuário.")


def _ensure_project_access(user, project: Project) -> None:
    if project.owner_id == getattr(user, "id", None):
        return
    memberships = getattr(project, "memberships", None)
    if memberships is not None and memberships.filter(user=user).exists():
        return
    raise ValidationError("Usuário não possui acesso ao projeto informado.")


def _default_output_dir(project: Project) -> Path:
    safe_slug = project.slug or slugify(project.name) or "projeto"
    return Path("recon") / safe_slug / "vuln"


def _relative_to_base(path: Path) -> str:
    base_dir = Path(settings.BASE_DIR)
    try:
        return str(path.resolve().relative_to(base_dir))
    except (ValueError, RuntimeError):
        return str(path.resolve())


def _deepcopy_payload(payload: Any) -> Any:
    return json.loads(json.dumps(payload, ensure_ascii=False))


def _parse_macro_hosts(value: Any) -> List[str]:
    hosts: List[str] = []

    def _collect(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, str):
            stripped = item.strip()
            if not stripped:
                return
            if stripped.startswith("[") and stripped.endswith("]"):
                with suppress(json.JSONDecodeError):
                    parsed = json.loads(stripped)
                    if isinstance(parsed, (list, tuple)):
                        for sub in parsed:
                            _collect(sub)
                        return
            for line in stripped.splitlines():
                entry = line.strip()
                if entry:
                    hosts.append(entry)
            return
        if isinstance(item, (list, tuple, set)):
            for sub in item:
                _collect(sub)
            return
        if isinstance(item, dict):
            for key in ("host", "address", "target", "hostname"):
                if key in item:
                    _collect(item.get(key))
            if "hosts" in item:
                _collect(item.get("hosts"))
            return
        text = str(item).strip()
        if text:
            hosts.append(text)

    _collect(value)
    unique_hosts: List[str] = []
    seen: set[str] = set()
    for host in hosts:
        if host not in seen:
            seen.add(host)
            unique_hosts.append(host)
    return unique_hosts


def _parse_macro_ports(value: Any) -> List[int]:
    ports: set[int] = set()

    def _collect(item: Any) -> None:
        if item is None:
            return
        if isinstance(item, (list, tuple, set)):
            for sub in item:
                _collect(sub)
            return
        if isinstance(item, dict):
            for key in ("ports", "tcp_ports", "udp_ports", "open_ports", "port", "number", "value"):
                if key in item:
                    _collect(item.get(key))
            return
        text = str(item).strip()
        if not text:
            return
        if text.startswith("[") and text.endswith("]"):
            with suppress(json.JSONDecodeError):
                parsed = json.loads(text)
                if isinstance(parsed, (list, tuple)):
                    for sub in parsed:
                        _collect(sub)
                    return
        for token in re.split(r"[,\s]+", text):
            trimmed = token.strip()
            if not trimmed:
                continue
            match = re.match(r"^(\d{1,5})", trimmed)
            if not match:
                continue
            port = int(match.group(1))
            if 1 <= port <= 65535:
                ports.add(port)

    _collect(value)
    return sorted(ports)


def _collect_targets_from_scan(session: VulnScanSession) -> Dict[str, Any]:
    scan_session = session.source_scan_session
    hosts_payload: List[Dict[str, Any]] = []
    unique_ports: set[int] = set()

    if scan_session and scan_session.report_snapshot:
        snapshot = scan_session.report_snapshot or {}
        targets = snapshot.get("targets", {})
        for entry in targets.get("hosts", []):
            host_value = entry.get("host") or entry.get("address")
            if not host_value:
                continue
            tcp_ports: set[int] = set()
            for port_entry in entry.get("ports", []) or []:
                if str(port_entry.get("protocol", "tcp")).lower() != "tcp":
                    continue
                try:
                    port_number = int(port_entry.get("port"))
                except (TypeError, ValueError):
                    continue
                status = str(port_entry.get("status", "open")).lower()
                if status not in {"open", "unknown", "filtered", ""}:
                    continue
                tcp_ports.add(port_number)
                unique_ports.add(port_number)
            if tcp_ports:
                hosts_payload.append({"host": host_value, "tcp_ports": sorted(tcp_ports)})

    fallback_used = False
    if not hosts_payload:
        macros = session.macros_snapshot or {}
        aggregated_ports: List[int] = []
        for candidate in (
            macros.get("TARGET_PORTS"),
            macros.get("SCAN_OPEN_PORTS"),
            getattr(session.project, "ports", None),
        ):
            aggregated_ports = _parse_macro_ports(candidate)
            if aggregated_ports:
                break

        structured_entries: List[Dict[str, Any]] = []
        for key in ("TARGETS_TABLE", "TARGETS_JSON", "SCAN_TARGETS", "SCAN_TARGETS_TABLE"):
            raw_value = macros.get(key)
            if not raw_value:
                continue
            parsed_value = raw_value
            if isinstance(raw_value, str):
                with suppress(json.JSONDecodeError):
                    parsed_json = json.loads(raw_value)
                    parsed_value = parsed_json
            if isinstance(parsed_value, list):
                for item in parsed_value:
                    if isinstance(item, dict):
                        structured_entries.append(item)

        structured_hosts: List[Dict[str, Any]] = []
        for entry in structured_entries:
            host_value = entry.get("host") or entry.get("address") or entry.get("target")
            if not host_value:
                continue
            host_value = str(host_value).strip()
            if not host_value:
                continue
            entry_ports: List[int] = []
            for key in ("ports", "tcp_ports", "open_ports"):
                if entry.get(key):
                    entry_ports = _parse_macro_ports(entry.get(key))
                    break
            if not entry_ports and entry.get("port") is not None:
                entry_ports = _parse_macro_ports([entry.get("port")])
            if not entry_ports:
                entry_ports = aggregated_ports
            structured_hosts.append({"host": host_value, "tcp_ports": entry_ports})

        if structured_hosts:
            fallback_used = True
            for item in structured_hosts:
                ports = item.get("tcp_ports") or []
                hosts_payload.append({"host": item["host"], "tcp_ports": sorted(set(ports))})
                unique_ports.update(ports)

        if not hosts_payload:
            macro_hosts = _parse_macro_hosts(macros.get("TARGET_HOSTS"))
            if not macro_hosts:
                macro_hosts = _parse_macro_hosts(macros.get("TARGETS"))
            if macro_hosts:
                fallback_used = True
                for host in macro_hosts:
                    ports_list = aggregated_ports
                    hosts_payload.append({"host": host, "tcp_ports": list(ports_list)})
                    unique_ports.update(ports_list)

    return {
        "hosts": hosts_payload,
        "unique_tcp_ports": sorted(unique_ports),
        "generated_at": timezone.now().isoformat(),
        "stats": {
            "total_hosts": len(hosts_payload),
            "total_tcp_ports": len(unique_ports),
            "total_services": sum(len(host.get("tcp_ports", [])) for host in hosts_payload),
        },
        "fallback_used": fallback_used,
    }


def _should_update_targets_snapshot(current: Optional[Dict[str, Any]], new: Dict[str, Any]) -> bool:
    if not new:
        return False
    current = current or {}

    def _normalize_hosts(payload: Dict[str, Any]) -> List[Tuple[str, Tuple[int, ...]]]:
        normalized: List[Tuple[str, Tuple[int, ...]]] = []
        for item in payload.get("hosts", []) or []:
            host_value = str(item.get("host") or item.get("address") or "").strip()
            if not host_value:
                continue
            ports = tuple(sorted(int(port) for port in item.get("tcp_ports", []) or []))
            normalized.append((host_value, ports))
        return sorted(set(normalized))

    new_hosts = _normalize_hosts(new)
    current_hosts = _normalize_hosts(current)
    if new_hosts and new_hosts != current_hosts:
        return True

    new_ports = tuple(sorted(set(new.get("unique_tcp_ports", []) or [])))
    current_ports = tuple(sorted(set(current.get("unique_tcp_ports", []) or [])))
    if new_ports and new_ports != current_ports:
        return True

    if new.get("fallback_used") and not current.get("fallback_used"):
        return True

    return False


def _ensure_targets_snapshot(session: VulnScanSession) -> Dict[str, Any]:
    targets_data = _collect_targets_from_scan(session)
    if _should_update_targets_snapshot(session.targets_snapshot, targets_data):
        session.targets_snapshot = targets_data
        session.save(update_fields=["targets_snapshot", "updated_at"])
    return targets_data


def _format_targets_with_ports(hosts: List[Dict[str, Any]]) -> str:
    rows: List[str] = []
    for host in hosts:
        host_value = host.get("host")
        ports = host.get("tcp_ports") or []
        if not host_value or not ports:
            continue
        rows.append(f"{host_value};{','.join(str(port) for port in ports)}")
    return "\n".join(rows)


def _format_port_list(ports: Iterable[int]) -> str:
    unique = sorted({int(port) for port in ports})
    return ",".join(str(port) for port in unique)


def _parse_targeted_stdout(stdout: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not stdout:
        return findings
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = TARGETED_STDOUT_RE.search(line)
        if not match:
            continue
        host = match.group("host").strip()
        ports_raw = match.group("ports")
        ports: List[int] = []
        for token in ports_raw.split(","):
            token = token.strip()
            if not token:
                continue
            token = token.split("/")[0]
            try:
                ports.append(int(token))
            except ValueError:
                continue
        findings.append({"host": host, "ports": sorted({p for p in ports}), "line": line})
    return findings


def _strip_xml_tag(tag: Optional[str]) -> str:
    if not tag:
        return ""
    if "}" in tag:
        return tag.split("}", 1)[1]
    if ":" in tag:
        return tag.split(":", 1)[1]
    return tag


def _find_first_with_tag(element: Optional[ET.Element], tag: str) -> Optional[ET.Element]:
    if element is None:
        return None
    for node in element.iter():
        if _strip_xml_tag(node.tag) == tag:
            return node
    return None


def _summarize_gmp_response(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, bytes):
        payload = payload.decode(errors="ignore")
    if isinstance(payload, str):
        text = payload.strip()
        return " ".join(text.split())
    if isinstance(payload, ET.Element):
        status = payload.get("status")
        status_text = payload.get("status_text")
        detail_parts = [part for part in (status, status_text) if part]
        if not detail_parts:
            detail_parts.append(_strip_xml_tag(payload.tag) or "response")
        return " | ".join(detail_parts).strip()
    detail_parts: List[str] = []
    for attr in ("status", "status_text", "message", "detail"):
        value = getattr(payload, attr, None)
        if value:
            detail_parts.append(str(value))
    if detail_parts:
        return " | ".join(detail_parts)
    try:
        return str(payload)
    except Exception:  # pragma: no cover - conversão defensiva
        return ""


def _clone_macros(session: VulnScanSession, *, owner, project: Project) -> Dict[str, Any]:
    if session.macros_snapshot:
        return _deepcopy_payload(session.macros_snapshot)
    return build_project_macros(owner, project)


def _ensure_script(slug: str) -> Script:
    script = Script.objects.filter(owner=None, slug=slug).first()
    if script:
        return script
    fallback = FALLBACK_SCRIPTS.get(slug)
    if fallback:
        script, _ = Script.objects.update_or_create(
            owner=None,
            slug=slug,
            defaults={
                "name": fallback["name"],
                "filename": fallback["filename"],
                "content": fallback["content"],
                "description": fallback["description"],
                "kind": Script.Kind.DEFAULT,
                "tags": ["nmap", "targeted"],
                "required_tool_slug": fallback.get("required_tool_slug", ""),
            },
        )
        return script
    definition = get_vuln_script_by_slug(slug)
    if not definition:
        raise VulnScriptExecutionError(f"Script {slug} não está cadastrado.")
    content = ""
    with suppress(FileNotFoundError):
        content = definition.read_content()
    script, _ = Script.objects.update_or_create(
        owner=None,
        slug=slug,
        defaults={
            "name": definition.name,
            "filename": definition.filename,
            "description": definition.description,
            "content": content,
            "kind": Script.Kind.DEFAULT,
            "tags": definition.tags,
            "required_tool_slug": definition.required_tool_slug or "",
        },
    )
    return script


def _claim_pending_task(
    session: VulnScanSession,
    *,
    action: str,
    script_slug: Optional[str] = None,
    kind: Optional[str] = None,
    name: Optional[str] = None,
) -> Optional[VulnTask]:
    qs = session.tasks.filter(status=VulnTask.Status.PENDING, parameters__playbook_action=action)
    if script_slug:
        qs = qs.filter(parameters__script=script_slug)
    if kind:
        qs = qs.filter(kind=kind)
    if name:
        qs = qs.filter(name=name)
    return qs.order_by("order", "id").first()


def _record_log(
    *,
    session: VulnScanSession,
    component: str,
    event_type: str,
    message: str,
    severity: str,
    details: Optional[dict] = None,
) -> None:
    log_event(
        source_app="arpia_vuln",
        event_type=event_type,


        message=message,
        severity=severity,
        component=component,
        details=details,
        correlation={"session_id": str(session.pk), "project_id": str(session.project.pk)},
        tags=["vuln", component],
    )


def _normalize_pipeline(pipeline_input: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []
    if not pipeline_input:
        return normalized
    for step in pipeline_input:
        if isinstance(step, str):
            normalized.append({"action": step})
        elif isinstance(step, dict):
            action = step.get("action") or step.get("type")
            if not action:
                continue
            normalized.append({"action": str(action), **{k: v for k, v in step.items() if k != "action"}})
    return normalized


class _BaseTargetedExecutor:
    SCRIPT_SLUG: str = ""
    TASK_NAME: str = ""
    TASK_KIND: str = VulnTask.Kind.SCRIPT
    PLAYBOOK_ACTION: str = TARGETED_ACTION

    def __init__(
        self,
        session: VulnScanSession,
        *,
        triggered_by,
        targets_data: Optional[Dict[str, Any]] = None,
        auto_finalize: bool = True,
    ) -> None:
        if not self.SCRIPT_SLUG or not self.TASK_NAME:
            raise ValueError("Executor precisa definir SCRIPT_SLUG e TASK_NAME.")
        self.session = session
        self.project = session.project
        self.user = triggered_by or session.owner
        self.auto_finalize = bool(auto_finalize)
        origin_targets = targets_data or _collect_targets_from_scan(session)
        self.targets_data = _deepcopy_payload(origin_targets)
        self.output_dir = _default_output_dir(self.project)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.macros = _clone_macros(session, owner=self.user, project=self.project)
        self.macros.setdefault("OUTPUT_DIR", str(self.output_dir))
        self._sync_macro_targets()

    def run(self) -> VulnTask:
        sync_vuln_default_scripts()
        sync_default_tools_for_user(self.user)
        ensure_session_is_active(self.session)

        script = _ensure_script(self.SCRIPT_SLUG)
        tool_slug = script.required_tool_slug or "nmap"
        tool = Tool.objects.for_user(self.user).filter(slug=tool_slug).first()

        if self.session.status in {VulnScanSession.Status.PLANNED, VulnScanSession.Status.READY}:
            self.session.mark_started()

        task = self._claim_or_create_task(script=script, tool=tool)
        _record_log(
            session=self.session,
            component="nmap",
            event_type="vuln.targeted.start",
            message=f"Iniciando {self.TASK_NAME} ({script.slug}).",
            severity=LogEntry.Severity.INFO,
            details={"task_id": str(task.pk), "script": script.slug},
        )

        try:
            ensure_session_is_active(self.session)
            stdout, stderr, returncode = self._execute_script(script)
        except VulnSessionCanceled:
            self._mark_task_canceled(task)
            raise
        if returncode == 0:
            self._handle_success(task, stdout, stderr)
        else:
            self._handle_failure(task, stdout, stderr, returncode)
        return task

    def _sync_macro_targets(self) -> None:
        hosts = self.targets_data.get("hosts", [])
        self.macros["SCAN_TARGETS_WITH_PORTS"] = _format_targets_with_ports(hosts)
        self.macros["SCAN_OPEN_PORTS"] = _format_port_list(self.targets_data.get("unique_tcp_ports", []))

    def _claim_or_create_task(self, *, script: Script, tool: Optional[Tool]) -> VulnTask:
        task = _claim_pending_task(
            self.session,
            action=self.PLAYBOOK_ACTION,
            script_slug=script.slug,
            kind=self.TASK_KIND,
            name=self.TASK_NAME,
        )
        parameters = {
            "playbook_action": self.PLAYBOOK_ACTION,
            "script": script.slug,
            "targets": self.targets_data.get("hosts", []),
            "unique_ports": self.targets_data.get("unique_tcp_ports", []),
            "output_dir": _relative_to_base(self.output_dir),
        }
        if task:
            task.parameters = {**(task.parameters or {}), **parameters}
            task.parameters.setdefault("planned", False)
            task.script = script
            task.tool = tool
            task.status = VulnTask.Status.RUNNING
            task.started_at = timezone.now()
            task.finished_at = None
            task.progress = max(float(task.progress or 0.0), 5.0)
            task.save(
                update_fields=[
                    "parameters",
                    "script",
                    "tool",
                    "status",
                    "progress",
                    "started_at",
                    "finished_at",
                    "updated_at",
                ]
            )
            return task

        order = self.session.tasks.count() + 1
        return VulnTask.objects.create(
            session=self.session,
            order=order,
            kind=self.TASK_KIND,
            status=VulnTask.Status.RUNNING,
            name=self.TASK_NAME,
            script=script,
            tool=tool,
            parameters=parameters,
            started_at=timezone.now(),
            progress=5.0,
        )

    def _execute_script(self, script: Script) -> Tuple[str, str, int]:
        content = render_script_with_macros(script.content or "", self.macros)
        temp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=f"_{script.slug}.sh", delete=False) as handle:
                handle.write(content)
                handle.flush()
                temp_path = Path(handle.name)
            os.chmod(temp_path, 0o700)
            completed = subprocess.run(  # noqa: S603,S607
                ["/bin/bash", str(temp_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            returncode = completed.returncode if completed.returncode is not None else 0
            return stdout, stderr, returncode
        finally:
            if temp_path is not None:
                with suppress(FileNotFoundError):
                    temp_path.unlink()

    def _handle_success(self, task: VulnTask, stdout: str, stderr: str) -> None:
        parsed = _parse_targeted_stdout(stdout)
        updated_targets = self._update_targets_snapshot(parsed)
        task.parameters = {
            **(task.parameters or {}),
            "targets": updated_targets.get("hosts", []),
            "unique_ports": updated_targets.get("unique_tcp_ports", []),
            "stdout": stdout[:2000],
        }
        task.status = VulnTask.Status.COMPLETED
        task.progress = 100.0
        task.stdout = stdout
        task.stderr = stderr
        task.finished_at = timezone.now()
        task.save(update_fields=["parameters", "status", "progress", "stdout", "stderr", "finished_at", "updated_at"])

        _record_log(
            session=self.session,
            component="nmap",
            event_type="vuln.targeted.success",
            message=f"{self.TASK_NAME} concluída.",
            severity=LogEntry.Severity.NOTICE,
            details={"task_id": str(task.pk), "script": task.parameters.get("script")},
        )

    def _handle_failure(self, task: VulnTask, stdout: str, stderr: str, returncode: int) -> None:
        message = f"Execução retornou código {returncode}."
        task.status = VulnTask.Status.FAILED
        task.progress = 100.0
        task.stdout = stdout
        task.stderr = stderr or message
        task.finished_at = timezone.now()
        task.save(update_fields=["status", "progress", "stdout", "stderr", "finished_at", "updated_at"])

        self.session.last_error = message
        if self.auto_finalize:
            self.session.status = VulnScanSession.Status.FAILED
            self.session.finished_at = timezone.now()
            self.session.save(update_fields=["status", "last_error", "finished_at", "updated_at"])
        else:
            self.session.save(update_fields=["last_error", "updated_at"])

        _record_log(
            session=self.session,
            component="nmap",
            event_type="vuln.targeted.failure",
            message=f"{self.TASK_NAME} falhou.",
            severity=LogEntry.Severity.ERROR,
            details={"task_id": str(task.pk), "returncode": returncode, "stderr": stderr[:1000]},
        )
        raise VulnScriptExecutionError(message)

    def _mark_task_canceled(self, task: VulnTask) -> None:
        reason_text = (self.session.last_error or "").strip()
        addition = "Tarefa cancelada pelo usuário."
        if reason_text:
            addition = f"{addition} Motivo: {reason_text}"
        task.status = VulnTask.Status.CANCELED
        task.finished_at = timezone.now()
        if not task.started_at:
            task.started_at = task.finished_at
        task.stderr = self._merge_message(task.stderr, addition)
        task.save(update_fields=["status", "finished_at", "stderr", "started_at"])
        _record_log(
            session=self.session,
            component="nmap",
            event_type="vuln.targeted.canceled",
            message=f"{self.TASK_NAME} cancelada pelo usuário.",
            severity=LogEntry.Severity.WARN,
            details={"task_id": str(task.pk)},
        )

    @staticmethod
    def _merge_message(current: Optional[str], addition: str) -> str:
        addition_text = (addition or "").strip()
        current_text = (current or "").strip()
        if not addition_text:
            return current_text
        if not current_text:
            return addition_text
        if addition_text in current_text:
            return current_text
        return f"{current_text}\n{addition_text}"

    def _update_targets_snapshot(self, parsed: List[Dict[str, Any]]) -> Dict[str, Any]:
        data = _deepcopy_payload(self.targets_data)
        hosts_index: Dict[str, Dict[str, Any]] = {item.get("host"): item for item in data.get("hosts", []) if item.get("host")}
        for finding in parsed:
            host = finding.get("host")
            ports = finding.get("ports") or []
            if not host or not ports:
                continue
            entry = hosts_index.setdefault(host, {"host": host, "tcp_ports": []})
            entry_ports = set(entry.get("tcp_ports", []))
            entry_ports.update(int(port) for port in ports)
            entry["tcp_ports"] = sorted(entry_ports)
        data["hosts"] = list(hosts_index.values())
        unique_ports = sorted({port for host in data.get("hosts", []) for port in host.get("tcp_ports", [])})
        data["unique_tcp_ports"] = unique_ports
        data["last_run"] = timezone.now().isoformat()
        data["script"] = self.SCRIPT_SLUG
        data["parsed_stdout"] = parsed
        data["output_dir"] = _relative_to_base(self.output_dir)
        self.targets_data = data

        report_snapshot = _deepcopy_payload(self.session.report_snapshot or {})
        report_snapshot.setdefault("targeted_runs", []).append(
            {
                "timestamp": data["last_run"],
                "script": self.SCRIPT_SLUG,
                "unique_ports": unique_ports,
            }
        )
        report_snapshot["targets_from_scan"] = data
        self.session.targets_snapshot = data
        self.session.report_snapshot = report_snapshot
        self.session.last_error = ""
        self.session.save(update_fields=["targets_snapshot", "report_snapshot", "last_error", "updated_at"])
        self._sync_macro_targets()
        return data


class VulnTargetedPortsExecutor(_BaseTargetedExecutor):
    SCRIPT_SLUG = "nmap-targeted-open-ports"
    TASK_NAME = "Nmap Targeted Ports"
    TASK_KIND = VulnTask.Kind.SERVICE_ENUMERATION


class VulnTargetedNseExecutor(_BaseTargetedExecutor):
    SCRIPT_SLUG = "nmap-targeted-nse"
    TASK_NAME = "Nmap NSE focado"
    TASK_KIND = VulnTask.Kind.SCRIPT


@dataclass
class GreenboneConfig:
    mode: str
    username: Optional[str]
    password: Optional[str]
    hostname: str
    port: int
    socket_path: Optional[str]
    scanner_id: str
    scan_config_id: str
    report_format_id: str
    report_directory: Path
    poll_interval: float
    max_attempts: int
    task_timeout: Optional[float]
    tool_slug: str = "gvm"
    tool_path: Optional[str] = None

    def as_public_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "hostname": self.hostname,
            "port": self.port,
            "socket_path": self.socket_path,
            "scanner_id": self.scanner_id,
            "scan_config_id": self.scan_config_id,
            "report_format_id": self.report_format_id,
            "report_directory": str(self.report_directory),
            "poll_interval": self.poll_interval,
            "max_attempts": self.max_attempts,
            "task_timeout": self.task_timeout,
        }

    @classmethod
    def load(cls) -> "GreenboneConfig":
        cfg = settings
        socket_path = getattr(cfg, "ARPIA_GVM_SOCKET_PATH", None) or os.getenv("ARPIA_GVM_SOCKET_PATH")
        default_socket = Path("/run/gvmd/gvmd.sock")
        if not socket_path and default_socket.exists():
            socket_path = str(default_socket)
        mode = "socket" if socket_path else "tls"
        report_dir = getattr(cfg, "ARPIA_GVM_REPORT_DIR", None) or os.getenv("ARPIA_GVM_REPORT_DIR") or "./recon/greenbone"
        report_directory = Path(report_dir)
        report_directory.mkdir(parents=True, exist_ok=True)
        task_timeout_env = getattr(cfg, "ARPIA_GVM_TASK_TIMEOUT", None) or os.getenv("ARPIA_GVM_TASK_TIMEOUT")
        return cls(
            mode=mode,
            username=getattr(cfg, "ARPIA_GVM_USERNAME", None) or os.getenv("ARPIA_GVM_USERNAME"),
            password=getattr(cfg, "ARPIA_GVM_PASSWORD", None) or os.getenv("ARPIA_GVM_PASSWORD"),
            hostname=getattr(cfg, "ARPIA_GVM_HOST", None) or os.getenv("ARPIA_GVM_HOST", "127.0.0.1"),
            port=int(getattr(cfg, "ARPIA_GVM_PORT", None) or os.getenv("ARPIA_GVM_PORT", "9390")),
            socket_path=socket_path,
            scanner_id=getattr(cfg, "ARPIA_GVM_SCANNER_ID", None) or os.getenv(
                "ARPIA_GVM_SCANNER_ID",
                "08b69003-5fc2-4037-a479-93b440211c73",
            ),
            scan_config_id=getattr(cfg, "ARPIA_GVM_SCAN_CONFIG_ID", None) or os.getenv(
                "ARPIA_GVM_SCAN_CONFIG_ID",
                "daba56c8-73ec-11df-a475-002264764cea",
            ),
            report_format_id=getattr(cfg, "ARPIA_GVM_REPORT_FORMAT_ID", None) or os.getenv(
                "ARPIA_GVM_REPORT_FORMAT_ID",
                "a994b278-1f62-11e1-96ac-406186ea4fc5",
            ),
            report_directory=report_directory,
            poll_interval=float(getattr(cfg, "ARPIA_GVM_POLL_INTERVAL", None) or os.getenv("ARPIA_GVM_POLL_INTERVAL", "5")),
            max_attempts=int(getattr(cfg, "ARPIA_GVM_MAX_ATTEMPTS", None) or os.getenv("ARPIA_GVM_MAX_ATTEMPTS", "60")),
            task_timeout=float(task_timeout_env) if task_timeout_env else None,
            tool_slug=getattr(cfg, "ARPIA_GVM_TOOL_SLUG", None) or os.getenv("ARPIA_GVM_TOOL_SLUG", "gvm"),
            tool_path=getattr(cfg, "ARPIA_GVM_TOOL_PATH", None) or os.getenv("ARPIA_GVM_TOOL_PATH"),
        )


def _load_greenbone_config() -> GreenboneConfig:
    return GreenboneConfig.load()


def _get_sudo_password() -> str:
    return (
        getattr(settings, "ARPIA_GVM_SUDO_PASSWORD", None)
        or os.getenv("ARPIA_GVM_SUDO_PASSWORD")
        or "kali"
    )


def _greenbone_autostart_enabled() -> bool:
    env_value = os.getenv("ARPIA_GVM_AUTOSTART", "1").strip().lower()
    return env_value not in {"0", "false", "no"}


class GreenboneCliRunner:
    def __init__(self, config: GreenboneConfig, tool_path: Optional[str] = None) -> None:
        self.config = config
        self.tool_path = tool_path or config.tool_path or "gvm-cli"

    def run(self, xml_payload: str, *, description: str) -> str:
        try:
            from gvm.connections import TLSConnection, UnixSocketConnection
            from gvm.errors import GvmError
            from gvm.protocols.gmp import Gmp
        except ImportError as exc:  # pragma: no cover - dependência externa
            raise GreenboneCliError(
                "A biblioteca python-gvm não está instalada. Execute 'pip install python-gvm' e reinicie o ARPIA."
            ) from exc

        if self.config.mode == "socket":
            socket_path = self.config.socket_path
            if not socket_path:
                raise GreenboneCliError("Socket do Greenbone não configurado.")
            connection = UnixSocketConnection(path=socket_path)
        else:
            connection = TLSConnection(host=self.config.hostname, port=self.config.port)

        username = (self.config.username or "").strip()
        password = (self.config.password or "").strip()
        if not username or not password:
            raise GreenboneCliError(
                "Credenciais do Greenbone ausentes. Defina ARPIA_GVM_USERNAME e ARPIA_GVM_PASSWORD."
            )

        try:
            with Gmp(connection=connection) as gmp:
                auth_response = gmp.authenticate(username, password)
                auth_ok = True
                if hasattr(gmp, "is_authenticated"):
                    try:
                        auth_ok = bool(gmp.is_authenticated())
                    except Exception:  # pragma: no cover - comportamento defensivo
                        auth_ok = False
                if not auth_ok:
                    detail = _summarize_gmp_response(auth_response)
                    message = "Falha na autenticação com o Greenbone. Verifique ARPIA_GVM_USERNAME e ARPIA_GVM_PASSWORD."
                    if detail:
                        message = f"{message} Detalhes: {detail}"
                    raise GreenboneCliError(message)
                response = gmp.send_command(xml_payload)
        except PermissionError as exc:
            raise GreenboneCliError(f"Sem permissão para acessar o Greenbone: {exc}") from exc
        except GvmError as exc:
            raise GreenboneCliError(f"Erro ao executar '{description}' via GMP: {exc}") from exc
        except OSError as exc:
            raise GreenboneCliError(f"Falha de comunicação com o Greenbone ({description}): {exc}") from exc

        if isinstance(response, bytes):
            stdout = response.decode()
        elif isinstance(response, ET.Element):
            stdout = ET.tostring(response, encoding="unicode")
        else:
            stdout = str(response)

        if "status=" in stdout and "failed" in stdout.lower():
            raise GreenboneCliError(f"Greenbone reportou falha em '{description}'.")

        return stdout


class GreenboneScanExecutor:
    def __init__(
        self,
        session: VulnScanSession,
        *,
        triggered_by,
        targets_data: Optional[Dict[str, Any]] = None,
        auto_finalize: bool = True,
    ) -> None:
        self.session = session
        self.project = session.project
        self.user = triggered_by or session.owner
        self.auto_finalize = bool(auto_finalize)
        self.targets_data = _deepcopy_payload(targets_data or _collect_targets_from_scan(session))
        self.config = _load_greenbone_config()
        self.report_dir = self._build_report_dir()

    def _ensure_service_available(self) -> None:
        if getattr(settings, "TESTING", False):
            return
        if self.config.mode == "socket":
            socket_path = self.config.socket_path
            if not socket_path:
                self._attempt_autostart_greenbone()
                socket_path = self.config.socket_path
                if not socket_path:
                    raise VulnGreenboneExecutionError(
                        "Greenbone configurado para socket local, mas nenhum caminho foi informado. "
                        "Defina ARPIA_GVM_SOCKET_PATH ou configure host/porta."
                    )
            path = Path(socket_path)
            if not path.exists():
                self._attempt_autostart_greenbone()
                socket_path = self.config.socket_path or socket_path
                path = Path(socket_path)
                if not path.exists():
                    raise VulnGreenboneExecutionError(
                        "Socket do Greenbone Manager não encontrado em {path}. "
                        "Execute 'sudo gvm-start' para iniciar os serviços antes de continuar.".format(path=socket_path)
                    )
            if not os.access(path, os.R_OK | os.W_OK):
                if self._ensure_socket_access(path):
                    return
                raise VulnGreenboneExecutionError(
                    "Sem permissão para acessar o socket {path}. Ajuste as permissões do gvmd ou use conexão TLS.".format(path=socket_path)
                )
            return

        try:
            with socket.create_connection((self.config.hostname, self.config.port), timeout=3):
                return
        except OSError as exc:
            self._attempt_autostart_greenbone()
            try:
                with socket.create_connection((self.config.hostname, self.config.port), timeout=3):
                    return
            except OSError as second_exc:
                raise VulnGreenboneExecutionError(
                    (
                        "Não foi possível conectar ao Greenbone Manager em {host}:{port} ({error}). "
                        "Garanta que o serviço está em execução (sudo gvm-start) e que as credenciais ARPIA_GVM_* estão corretas."
                    ).format(host=self.config.hostname, port=self.config.port, error=second_exc)
                ) from second_exc

    def run(self) -> VulnTask:
        sync_default_tools_for_user(self.user)
        tool = Tool.objects.for_user(self.user).filter(slug=self.config.tool_slug).first()
        runner = GreenboneCliRunner(self.config, tool_path=tool.path if tool and tool.path else None)

        if self.session.status in {VulnScanSession.Status.PLANNED, VulnScanSession.Status.READY}:
            self.session.mark_started()

        task = self._claim_or_create_task(tool)
        _record_log(
            session=self.session,
            component="greenbone",
            event_type="vuln.greenbone.start",
            message="Iniciando execução Greenbone.",
            severity=LogEntry.Severity.INFO,
            details={"task_id": str(task.pk)},
        )

        try:
            ensure_session_is_active(self.session)
            self._ensure_service_available()
            ensure_session_is_active(self.session)
            if not self.targets_data.get("hosts"):
                raise VulnGreenboneExecutionError("Nenhum alvo disponível para Greenbone.")
            target_id = self._create_target(runner)
            ensure_session_is_active(self.session)
            task_id = self._create_task(runner, target_id)
            ensure_session_is_active(self.session)
            report_id = self._start_task(runner, task_id)
            ensure_session_is_active(self.session)
            status, summary = self._wait_for_completion(runner, task_id)
            ensure_session_is_active(self.session)
            report_path, severity_counts = self._download_report(runner, report_id)
        except VulnSessionCanceled:
            self._mark_task_canceled(task)
            raise
        except VulnGreenboneExecutionError as exc:
            self._handle_failure(task, exc)
            raise
        except Exception as exc:  # pragma: no cover - tratado como falha inesperada
            self._handle_failure(task, exc)
            raise VulnGreenboneExecutionError(str(exc)) from exc

        self._finalize_success(task, status, summary, report_id, report_path, severity_counts)
        return task

    def _build_report_dir(self) -> Path:
        safe_project = self.project.slug or slugify(self.project.name) or "projeto"
        directory = self.config.report_directory / safe_project / self.session.reference
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _collect_unique_ports(self) -> List[int]:
        ports = sorted({port for host in self.targets_data.get("hosts", []) for port in host.get("tcp_ports", [])})
        return ports

    def _port_range(self) -> str:
        ports = self._collect_unique_ports()
        if not ports:
            return "T:1-65535"
        return "T:" + ",".join(str(port) for port in ports)

    def _claim_or_create_task(self, tool: Optional[Tool]) -> VulnTask:
        defaults = {
            "playbook_action": GREENBONE_ACTION,
            "targets": [host.get("host") for host in self.targets_data.get("hosts", []) if host.get("host")],
            "unique_ports": self._collect_unique_ports(),
            "port_range": self._port_range(),
        }
        task = _claim_pending_task(
            self.session,
            action=GREENBONE_ACTION,
            kind=VulnTask.Kind.GREENBONE_SCAN,
            name="Greenbone Vulnerability Scan",
        )
        if task:
            task.parameters = {**(task.parameters or {}), **defaults}
            task.parameters.setdefault("planned", False)
            task.tool = tool
            task.status = VulnTask.Status.RUNNING
            task.started_at = timezone.now()
            task.finished_at = None
            task.progress = max(float(task.progress or 0.0), 5.0)
            task.save(
                update_fields=[
                    "parameters",
                    "tool",
                    "status",
                    "progress",
                    "started_at",
                    "finished_at",
                    "updated_at",
                ]
            )
            return task
        order = self.session.tasks.count() + 1
        return VulnTask.objects.create(
            session=self.session,
            order=order,
            kind=VulnTask.Kind.GREENBONE_SCAN,
            status=VulnTask.Status.RUNNING,
            name="Greenbone Vulnerability Scan",
            tool=tool,
            parameters=defaults,
            started_at=timezone.now(),
            progress=5.0,
        )

    def _create_target(self, runner: GreenboneCliRunner) -> str:
        hosts = ",".join(sorted(host.get("host") for host in self.targets_data.get("hosts", []) if host.get("host")))
        port_range = self._port_range()
        xml_payload = textwrap.dedent(
            f"""
            <create_target>
                <name>{html.escape(self.project.name)} ({html.escape(self.session.reference)})</name>
                <comment>Gerado automaticamente pelo ARPIA.</comment>
                <hosts>{html.escape(hosts)}</hosts>
                <port_list>
                    <name>ARPIA {html.escape(self.session.reference)} portas TCP</name>
                    <port_range>{html.escape(port_range)}</port_range>
                </port_list>
            </create_target>
            """
        ).strip()
        stdout = runner.run(xml_payload, description="create_target")
        root = ET.fromstring(stdout)
        response_node = root if _strip_xml_tag(root.tag) == "create_target_response" else _find_first_with_tag(root, "create_target_response")
        if response_node is None:
            snippet = stdout.strip().splitlines()[0:3]
            raise GreenboneCliError(
                "Resposta inesperada ao criar alvo. Conteúdo inicial: {snippet}".format(snippet=" | ".join(snippet))
            )
        target_id = response_node.get("id") or _find_first_with_tag(response_node, "id")
        if isinstance(target_id, ET.Element):
            target_id = (target_id.text or "").strip()
        if not target_id:
            raise GreenboneCliError("Greenbone não retornou ID do alvo.")
        return str(target_id)

    def _create_task(self, runner: GreenboneCliRunner, target_id: str) -> str:
        xml_payload = textwrap.dedent(
            f"""
            <create_task>
                <name>ARPIA {html.escape(self.session.reference)}</name>
                <comment>Tarefa automática para {html.escape(self.project.name)}</comment>
                <config id="{html.escape(self.config.scan_config_id)}"/>
                <target id="{html.escape(target_id)}"/>
                <scanner id="{html.escape(self.config.scanner_id)}"/>
            </create_task>
            """
        ).strip()
        stdout = runner.run(xml_payload, description="create_task")
        root = ET.fromstring(stdout)
        response_node = root if _strip_xml_tag(root.tag) == "create_task_response" else _find_first_with_tag(root, "create_task_response")
        if response_node is None:
            snippet = stdout.strip().splitlines()[0:3]
            raise GreenboneCliError(
                "Resposta inesperada ao criar tarefa. Conteúdo inicial: {snippet}".format(snippet=" | ".join(snippet))
            )
        task_id = response_node.get("id") or _find_first_with_tag(response_node, "id")
        if isinstance(task_id, ET.Element):
            task_id = (task_id.text or "").strip()
        if not task_id:
            raise GreenboneCliError("Greenbone não retornou ID da tarefa.")
        return str(task_id)

    def _start_task(self, runner: GreenboneCliRunner, task_id: str) -> str:
        xml_payload = f"<start_task task_id=\"{html.escape(task_id)}\"/>"
        stdout = runner.run(xml_payload, description="start_task")
        root = ET.fromstring(stdout)
        response_node = root if _strip_xml_tag(root.tag) == "start_task_response" else _find_first_with_tag(root, "start_task_response")
        if response_node is None:
            response_node = root
        report_elem = _find_first_with_tag(response_node, "report_id")
        if report_elem is None:
            raise GreenboneCliError("Resposta de start_task sem report_id.")
        report_id = report_elem.get("id") or (report_elem.text or "").strip()
        if not report_id:
            raise GreenboneCliError("ID do relatório não retornado pelo Greenbone.")
        return report_id

    def _wait_for_completion(self, runner: GreenboneCliRunner, task_id: str) -> Tuple[str, Dict[str, Any]]:
        attempts = 0
        deadline = time.time() + self.config.task_timeout if self.config.task_timeout else None
        while attempts < self.config.max_attempts:
            ensure_session_is_active(self.session)
            if deadline and time.time() >= deadline:
                raise GreenboneCliError("Tempo limite excedido aguardando tarefa Greenbone.")
            xml_payload = textwrap.dedent(
                f"""
                <get_tasks>
                    <filter>
                        <task_id>{html.escape(task_id)}</task_id>
                    </filter>
                </get_tasks>
                """
            ).strip()
            stdout = runner.run(xml_payload, description="get_tasks")
            root = ET.fromstring(stdout)
            task_elem = _find_first_with_tag(root, "task")
            if task_elem is None:
                raise GreenboneCliError("Resposta de get_tasks não contém tarefa.")
            status_elem = _find_first_with_tag(task_elem, "status")
            status = (status_elem.text if status_elem is not None else "").strip()
            progress_elem = _find_first_with_tag(task_elem, "progress")
            progress = progress_elem.text if progress_elem is not None else None
            if status.lower() in {"done", "finished", "completed"}:
                summary = {"status": status, "progress": progress}
                return status, summary
            if status.lower() in {"failed", "stopped", "interrupted"}:
                raise GreenboneCliError(f"Tarefa Greenbone finalizada com status {status}.")
            attempts += 1
            if self.config.poll_interval:
                time.sleep(self.config.poll_interval)
        raise GreenboneCliError("Número máximo de tentativas excedido aguardando tarefa Greenbone.")

    def _mark_task_canceled(self, task: VulnTask) -> None:
        reason_text = (self.session.last_error or "").strip()
        addition = "Execução Greenbone cancelada pelo usuário."
        if reason_text:
            addition = f"{addition} Motivo: {reason_text}"
        task.status = VulnTask.Status.CANCELED
        task.finished_at = timezone.now()
        if not task.started_at:
            task.started_at = task.finished_at
        task.stderr = _BaseTargetedExecutor._merge_message(task.stderr, addition)
        task.save(update_fields=["status", "finished_at", "stderr", "started_at"])
        _record_log(
            session=self.session,
            component="greenbone",
            event_type="vuln.greenbone.canceled",
            message="Execução Greenbone cancelada pelo usuário.",
            severity=LogEntry.Severity.WARN,
            details={"task_id": str(task.pk)},
        )

    def _download_report(self, runner: GreenboneCliRunner, report_id: str) -> Tuple[Path, Dict[str, Any]]:
        xml_payload = f"<get_reports report_id=\"{html.escape(report_id)}\" format_id=\"{html.escape(self.config.report_format_id)}\"/>"
        stdout = runner.run(xml_payload, description="get_reports")
        root = ET.fromstring(stdout)
        report_node = _find_first_with_tag(root, "report")
        content_node = _find_first_with_tag(report_node, "content") if report_node is not None else None
        if content_node is None:
            content_node = _find_first_with_tag(root, "content")
        if content_node is None and report_node is not None:
            content_node = report_node
        if content_node is not None:
            content_text = (content_node.text or "").strip()
            if not content_text:
                content_text = "".join(part for part in content_node.itertext()).strip()
        else:
            content_text = ""
        content_text = content_text.strip()
        if not content_text:
            raise GreenboneCliError("Conteúdo do relatório está vazio.")
        try:
            payload = base64.b64decode(content_text.encode(), validate=True)
        except Exception:
            payload = content_text.encode()
        report_path = self.report_dir / f"greenbone_report_{report_id}.xml"
        report_path.write_bytes(payload)
        severity_counts = self._extract_counts(payload.decode(errors="ignore"))
        return report_path, severity_counts

    def _extract_counts(self, report_content: str) -> Dict[str, Any]:
        try:
            root = ET.fromstring(report_content)
        except ET.ParseError:
            return {}
        counts: Dict[str, Any] = {}
        for node in root.iter():
            if _strip_xml_tag(node.tag) != "result_count":
                continue
            severity = node.get("severity") or node.get("type") or "unknown"
            try:
                counts[severity] = int(node.text or 0)
            except (TypeError, ValueError):
                continue
        return counts

    def _finalize_success(
        self,
        task: VulnTask,
        status: str,
        summary: Dict[str, Any],
        report_id: str,
        report_path: Path,
        severity_counts: Dict[str, Any],
    ) -> None:
        parameters = {**(task.parameters or {})}
        parameters.update(
            {
                "status": status,
                "summary": summary,
                "report_id": report_id,
                "report_path": _relative_to_base(report_path),
                "unique_ports": self._collect_unique_ports(),
                "port_range": self._port_range(),
            }
        )
        task.parameters = parameters
        task.status = VulnTask.Status.COMPLETED
        task.progress = 100.0
        task.stdout = json.dumps(summary)
        task.stderr = ""
        task.finished_at = timezone.now()
        task.save(update_fields=["parameters", "status", "progress", "stdout", "stderr", "finished_at", "updated_at"])

        last_report = {
            "report_id": report_id,
            "status": status,
            "summary": summary,
            "report_path": _relative_to_base(report_path),
            "severity_counts": severity_counts,
            "last_run": timezone.now().isoformat(),
        }
        snapshot = _deepcopy_payload(self.session.report_snapshot or {})
        snapshot.setdefault("greenbone_runs", []).append(last_report)
        snapshot["greenbone_last_report"] = last_report
        self.session.report_snapshot = snapshot
        self.session.last_error = ""
        self.session.save(update_fields=["report_snapshot", "last_error", "updated_at"])
        if self.auto_finalize:
            self.session.mark_finished(success=True)

        _record_log(
            session=self.session,
            component="greenbone",
            event_type="vuln.greenbone.success",


            message="Execução Greenbone concluída.",
            severity=LogEntry.Severity.NOTICE,
            details={"report_id": report_id, "status": status},
        )

    def _handle_failure(self, task: VulnTask, exc: Exception) -> None:
        message = str(exc)
        task.status = VulnTask.Status.FAILED
        task.progress = 100.0
        task.stderr = message
        task.finished_at = timezone.now()
        task.save(update_fields=["status", "progress", "stderr", "finished_at", "updated_at"])

        self.session.status = VulnScanSession.Status.FAILED
        self.session.last_error = message
        self.session.finished_at = timezone.now()
        self.session.save(update_fields=["status", "last_error", "finished_at", "updated_at"])

        _record_log(
            session=self.session,
            component="greenbone",
            event_type="vuln.greenbone.failure",
            message="Execução Greenbone falhou.",
            severity=LogEntry.Severity.ERROR,
            details={"error": message},
        )

    def _attempt_autostart_greenbone(self) -> None:
        if getattr(settings, "TESTING", False):
            return
        if not _greenbone_autostart_enabled():
            return
        if getattr(self, "_autostart_attempted", False):
            return
        self._autostart_attempted = True

        candidate_commands: List[List[str]] = []
        seen: set[tuple[str, ...]] = set()

        custom_command = getattr(settings, "ARPIA_GVM_AUTOSTART_COMMAND", None) or os.getenv("ARPIA_GVM_AUTOSTART_COMMAND")
        if custom_command:
            try:
                parsed = shlex.split(custom_command)
            except ValueError as exc:
                raise VulnGreenboneExecutionError(
                    "Valor inválido em ARPIA_GVM_AUTOSTART_COMMAND. Verifique a sintaxe do comando."
                ) from exc
            if parsed:
                candidate_commands.append(parsed)

        sudo_path = shutil.which("sudo")
        gvm_start_path = shutil.which("gvm-start")
        sudo_password = _get_sudo_password()

        if sudo_path and gvm_start_path:
            candidate_commands.append([sudo_path, "-n", gvm_start_path])
            if sudo_password:
                candidate_commands.append([sudo_path, "-S", gvm_start_path])
        if gvm_start_path:
            candidate_commands.append([gvm_start_path])

        if not candidate_commands:
            raise VulnGreenboneExecutionError(
                "Não foi possível localizar o comando 'gvm-start'. Instale e configure o GVM antes de executar o Greenbone."
            )

        last_error: Optional[str] = None
        for command in candidate_commands:
            key = tuple(command)
            if key in seen:
                continue
            seen.add(key)

            input_data: Optional[str] = None
            if sudo_password and "-S" in command:
                input_data = f"{sudo_password}\n"

            try:
                result = subprocess.run(  # noqa: S603,S607
                    command,
                    capture_output=True,
                    text=True,
                    input=input_data,
                )
            except FileNotFoundError as exc:
                last_error = str(exc)
                continue

            if result.returncode == 0:
                self.config = _load_greenbone_config()
                return

            stderr = (result.stderr or result.stdout or "").strip()
            if stderr:
                last_error = stderr

        raise VulnGreenboneExecutionError(
            "Falha ao iniciar o Greenbone automaticamente. "
            "Verifique as permissões do comando 'gvm-start' (sudoers) ou execute-o manualmente. "
            f"Detalhes: {last_error or 'sem saída disponível.'}"
        )

    def _ensure_socket_access(self, path: Path) -> bool:
        if os.access(path, os.R_OK | os.W_OK):
            return True

        sudo_path = shutil.which("sudo")
        if not sudo_path:
            return False

        password = _get_sudo_password()
        try:
            user = getpass.getuser()
        except Exception:  # pragma: no cover - ambientes sem usuário associado
            user = os.getenv("USER", "")
        commands: List[List[str]] = []
        setfacl_path = shutil.which("setfacl")
        if setfacl_path and user:
            commands.append([sudo_path, "-S", "setfacl", "-m", f"u:{user}:rw", str(path)])
        commands.append([sudo_path, "-S", "chmod", "666", str(path)])

        for command in commands:
            try:
                subprocess.run(  # noqa: S603,S607
                    command,
                    input=f"{password}\n" if password else None,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                continue
            if os.access(path, os.R_OK | os.W_OK):
                return True

        return os.access(path, os.R_OK | os.W_OK)


@transaction.atomic
def plan_vulnerability_session(
    *,
    owner,
    project: Project,
    title: str,
    source_scan_session=None,
    pipeline: Optional[Iterable[Any]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> VulnScanSession:
    _ensure_project_access(owner, project)
    sync_vuln_default_scripts()
    sync_default_tools_for_user(owner)

    macros = build_project_macros(owner, project)
    config = dict(config or {})
    pipeline_entries = _normalize_pipeline(pipeline or config.get("pipeline"))
    if not pipeline_entries:
        pipeline_entries = [
            {"action": TARGETED_ACTION, "include_nse": True},
            {"action": GREENBONE_ACTION},
        ]

    session = VulnScanSession.objects.create(
        project=project,
        owner=owner,
        title=title,
        source_scan_session=source_scan_session,
        status=VulnScanSession.Status.PLANNED,
        config_snapshot={},
        macros_snapshot=_deepcopy_payload(macros),
    )

    targets_snapshot = _collect_targets_from_scan(session)
    session.targets_snapshot = targets_snapshot
    session.config_snapshot = {
        "pipeline": _deepcopy_payload(pipeline_entries),
        "generated_at": timezone.now().isoformat(),
        "macros": macros,
    }
    session.save(update_fields=["targets_snapshot", "config_snapshot", "updated_at"])

    order = 1
    playbook_entries: List[Dict[str, Any]] = []
    for step in pipeline_entries:
        action = str(step.get("action") or "").strip().lower()
        if not action:
            continue
        if action == TARGETED_ACTION:
            include_open_ports = step.get("include_open_ports", True)
            include_nse = step.get("include_nse", True)
            if include_open_ports:
                VulnTask.objects.create(
                    session=session,
                    order=order,
                    kind=VulnTask.Kind.SERVICE_ENUMERATION,
                    status=VulnTask.Status.PENDING,
                    name="Nmap Targeted Ports",
                    parameters={
                        "playbook_action": TARGETED_ACTION,
                        "script": "nmap-targeted-open-ports",
                        "planned": True,
                    },
                )
                playbook_entries.append(
                    {
                        "order": order,
                        "action": TARGETED_ACTION,
                        "script": "nmap-targeted-open-ports",
                        "kind": VulnTask.Kind.SERVICE_ENUMERATION,
                    }
                )
                order += 1
            if include_nse:
                VulnTask.objects.create(
                    session=session,
                    order=order,
                    kind=VulnTask.Kind.SCRIPT,
                    status=VulnTask.Status.PENDING,
                    name="Nmap NSE focado",
                    parameters={
                        "playbook_action": TARGETED_ACTION,
                        "script": "nmap-targeted-nse",
                        "planned": True,
                    },
                )
                playbook_entries.append(
                    {
                        "order": order,
                        "action": TARGETED_ACTION,
                        "script": "nmap-targeted-nse",
                        "kind": VulnTask.Kind.SCRIPT,
                    }
                )
                order += 1
        elif action == GREENBONE_ACTION:
            VulnTask.objects.create(
                session=session,
                order=order,
                kind=VulnTask.Kind.GREENBONE_SCAN,
                status=VulnTask.Status.PENDING,
                name="Greenbone Vulnerability Scan",
                parameters={
                    "playbook_action": GREENBONE_ACTION,
                    "planned": True,
                },
            )
            playbook_entries.append(
                {
                    "order": order,
                    "action": GREENBONE_ACTION,
                    "kind": VulnTask.Kind.GREENBONE_SCAN,
                }
            )
            order += 1

    if playbook_entries:
        snapshot = _deepcopy_payload(session.config_snapshot)
        snapshot["playbook"] = playbook_entries
        session.config_snapshot = snapshot
        session.save(update_fields=["config_snapshot", "updated_at"])

    _record_log(
        session=session,
        component="planner",
        event_type="vuln.session.planned",
        message=f"Sessão {session.reference} planejada.",
        severity=LogEntry.Severity.INFO,
        details={"pipeline": pipeline_entries},
    )
    return session


@transaction.atomic
def cancel_vulnerability_session(
    session: VulnScanSession,
    *,
    triggered_by=None,
    reason: str | None = None,
) -> VulnScanSession:
    """Cancela uma sessão em execução, marcando tarefas pendentes como canceladas."""
    if session.pk is None:
        raise ValidationError("Sessão inválida.")
    locked_session = (
        VulnScanSession.objects.select_for_update()
        .select_related("project", "owner")
        .get(pk=session.pk)
    )
    if locked_session.status == VulnScanSession.Status.CANCELED:
        return locked_session
    if locked_session.is_terminal and locked_session.status != VulnScanSession.Status.RUNNING:
        raise ValidationError("Sessão já foi finalizada.")

    reason_text = (reason or "").strip()
    now = timezone.now()

    active_statuses = [
        VulnTask.Status.PENDING,
        VulnTask.Status.QUEUED,
        VulnTask.Status.RUNNING,
    ]
    canceled_tasks = []
    for task in locked_session.tasks.filter(status__in=active_statuses):
        task.status = VulnTask.Status.CANCELED
        task.finished_at = now
        if not task.started_at:
            task.started_at = now
        addition = "Tarefa cancelada pelo usuário."
        if reason_text:
            addition = f"{addition} Motivo: {reason_text}"
        existing = (task.stderr or "").strip()
        task.stderr = f"{existing}\n{addition}".strip() if existing else addition
        task.save(update_fields=["status", "finished_at", "stderr", "started_at"])
        canceled_tasks.append(task)

    locked_session.status = VulnScanSession.Status.CANCELED
    locked_session.finished_at = locked_session.finished_at or now
    if reason_text:
        locked_session.last_error = reason_text
    elif not (locked_session.last_error or "").strip():
        locked_session.last_error = "Sessão cancelada pelo usuário."
    locked_session.save(update_fields=["status", "finished_at", "last_error", "updated_at"])

    details = {
        "tasks_canceled": len(canceled_tasks),
        "reason": reason_text or None,
    }
    if triggered_by and getattr(triggered_by, "username", None):
        details["triggered_by"] = getattr(triggered_by, "username")

    _record_log(
        session=locked_session,
        component="session",
        event_type="vuln.session.canceled",
        message="Sessão cancelada pelo usuário.",
        severity=LogEntry.Severity.WARN,
        details=details,
    )

    with suppress(Exception):
        session.refresh_from_db(fields=["status", "finished_at", "last_error", "updated_at"])

    return locked_session


def run_targeted_nmap_scans(
    session: VulnScanSession,
    *,
    triggered_by=None,
    include_nse: bool = True,
    auto_finalize: bool = True,
) -> List[VulnTask]:
    ensure_session_is_active(session)
    targets_data = _ensure_targets_snapshot(session)
    tasks: List[VulnTask] = []
    ports_executor = VulnTargetedPortsExecutor(
        session,
        triggered_by=triggered_by,
        targets_data=targets_data,
        auto_finalize=auto_finalize,
    )
    first_task = ports_executor.run()
    tasks.append(first_task)
    ensure_session_is_active(session)

    if include_nse:
        ensure_session_is_active(session)
        nse_executor = VulnTargetedNseExecutor(
            session,
            triggered_by=triggered_by,
            targets_data=ports_executor.targets_data,
            auto_finalize=auto_finalize,
        )
        tasks.append(nse_executor.run())

    return tasks


def run_greenbone_scan(
    session: VulnScanSession,
    *,
    triggered_by=None,
    auto_finalize: bool = True,
) -> VulnTask:
    ensure_session_is_active(session)
    targets_data = _ensure_targets_snapshot(session)
    executor = GreenboneScanExecutor(
        session,
        triggered_by=triggered_by,
        targets_data=targets_data,
        auto_finalize=auto_finalize,
    )
    return executor.run()


def run_vulnerability_pipeline(
    session: VulnScanSession,
    *,
    triggered_by=None,
    pipeline: Optional[Sequence[Any]] = None,
    allow_prestarted: bool = False,
) -> VulnScanSession:
    from .orchestrator import VulnOrchestrator

    orchestrator = VulnOrchestrator(
        session,
        run_as_user=triggered_by,
        pipeline=pipeline,
        allow_prestarted=allow_prestarted,
    )
    return orchestrator.run()


def _pipeline_async_worker(
    *,
    session_id,
    triggered_by_id: Optional[int],
    pipeline: Optional[Sequence[Any]],
) -> None:
    from django.db import close_old_connections

    close_old_connections()
    try:
        session = (
            VulnScanSession.objects.select_related("project", "owner")
            .get(pk=session_id)
        )
    except VulnScanSession.DoesNotExist:
        logger.warning("Sessão de vulnerabilidade %s não encontrada para execução assíncrona.", session_id)
        close_old_connections()
        return

    triggered_by = None
    if triggered_by_id is not None:
        UserModel = get_user_model()
        triggered_by = UserModel.objects.filter(pk=triggered_by_id).first()

    try:
        run_vulnerability_pipeline(
            session,
            triggered_by=triggered_by,
            pipeline=pipeline,
            allow_prestarted=True,
        )
    except Exception:
        logger.exception("Falha ao executar pipeline da sessão %s em segundo plano.", session_id)
    finally:
        close_old_connections()


def run_vulnerability_pipeline_async(
    session: VulnScanSession,
    *,
    triggered_by=None,
    pipeline: Optional[Sequence[Any]] = None,
) -> threading.Thread:
    if session.pk is None:
        raise ValidationError("Sessão precisa estar persistida antes de iniciar o pipeline.")

    session.refresh_from_db(fields=["status", "finished_at", "updated_at"])
    if session.is_terminal:
        raise ValidationError("Sessão já foi finalizada.")
    if session.status == VulnScanSession.Status.RUNNING:
        raise ValidationError("Sessão já está em execução.")

    session.mark_started()

    pipeline_copy: Optional[Sequence[Any]]
    if pipeline is not None:
        pipeline_copy = list(pipeline)
    else:
        pipeline_copy = None

    thread = threading.Thread(
        target=_pipeline_async_worker,
        kwargs={
            "session_id": session.pk,
            "triggered_by_id": getattr(triggered_by, "pk", None),
            "pipeline": pipeline_copy,
        },
        name=f"vuln-session-{session.pk}",
        daemon=True,
    )
    thread.start()
    return thread
