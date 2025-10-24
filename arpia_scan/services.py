from __future__ import annotations

import json
import socket
import time
from contextlib import closing
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from arpia_core.models import Project, Script, Tool, Wordlist
from arpia_core.views import build_project_macros  # TODO mover p/ util compartilhado
from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .parsers import merge_observations, parse_nmap_xml, parse_rustscan_payload

from .models import ScanFinding, ScanSession, ScanTask


DEFAULT_TASK_DEFINITION = [
    {
        "kind": ScanTask.Kind.CONNECTIVITY,
        "name": "Teste de conectividade",
        "parameters": {},
    },
    {
        "kind": ScanTask.Kind.DISCOVERY_RUSTSCAN,
        "name": "Rustscan discovery",
        "parameters": {},
    },
    {
        "kind": ScanTask.Kind.DISCOVERY_NMAP,
        "name": "Varredura Nmap",
        "parameters": {},
    },
]


@dataclass(frozen=True)
class PortSpec:
    port: int
    protocol: str = "tcp"

    @classmethod
    def from_value(cls, value) -> "PortSpec | None":
        if isinstance(value, PortSpec):
            return value
        if isinstance(value, dict):
            port = value.get("port")
            protocol = (value.get("protocol") or "tcp").lower()
        elif isinstance(value, str):
            token = value.strip()
            if not token:
                return None
            if "/" in token:
                port_part, proto_part = token.split("/", 1)
                port = port_part.strip()
                protocol = proto_part.strip().lower() or "tcp"
            else:
                port = token
                protocol = "tcp"
        else:
            port = value
            protocol = "tcp"

        try:
            port_number = int(port)
        except (TypeError, ValueError):
            return None
        if not (0 < port_number < 65536):
            return None
        protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        return cls(port=port_number, protocol=protocol)


DEFAULT_CONNECTIVITY_PORTS: Sequence[PortSpec] = (
    PortSpec(22, "tcp"),
    PortSpec(80, "tcp"),
    PortSpec(443, "tcp"),
    PortSpec(53, "udp"),
    PortSpec(3389, "tcp"),
    PortSpec(445, "tcp"),
    PortSpec(25, "tcp"),
    PortSpec(161, "udp"),
)


@dataclass
class PlannedTask:
    order: int
    kind: str
    name: str
    parameters: dict
    tool: Optional[Tool] = None
    script: Optional[Script] = None
    wordlist: Optional[Wordlist] = None


def _ensure_membership(user, project: Project) -> None:
    if project.owner_id == user.id:
        return
    if project.memberships.filter(user=user).exists():
        return
    raise ValidationError("Usuário não possui acesso a este projeto.")


def _fetch_tool(owner, slug: Optional[str]) -> Optional[Tool]:
    if not slug:
        return None
    return Tool.objects.filter(owner=owner, slug=slug).first()


def _fetch_script(owner, slug: Optional[str]) -> Optional[Script]:
    if not slug:
        return None
    return Script.objects.for_user(owner).filter(slug=slug).first()


def _fetch_wordlist(owner, slug: Optional[str]) -> Optional[Wordlist]:
    if not slug:
        return None
    return Wordlist.objects.filter(owner=owner, slug=slug).first()


def _normalize_tasks(payload: Optional[Iterable[dict]], owner) -> List[PlannedTask]:
    tasks_payload = list(payload or DEFAULT_TASK_DEFINITION)
    planned: List[PlannedTask] = []

    for idx, task_def in enumerate(tasks_payload, start=1):
        kind = task_def.get("kind") or ScanTask.Kind.CUSTOM
        name = task_def.get("name") or dict(ScanTask.Kind.choices).get(kind, kind)
        parameters = task_def.get("parameters") or {}
        tool_slug = task_def.get("tool") or task_def.get("tool_slug")
        script_slug = task_def.get("script") or task_def.get("script_slug")
        wordlist_slug = task_def.get("wordlist") or task_def.get("wordlist_slug")

        planned.append(
            PlannedTask(
                order=idx,
                kind=kind,
                name=name,
                parameters=parameters,
                tool=_fetch_tool(owner, tool_slug),
                script=_fetch_script(owner, script_slug),
                wordlist=_fetch_wordlist(owner, wordlist_slug),
            )
        )

    return planned


@transaction.atomic
def create_planned_session(*, owner, project: Project, title: str, config: Optional[dict] = None) -> ScanSession:
    _ensure_membership(owner, project)

    config = config or {}
    tasks_payload = config.get("tasks")
    planned_tasks = _normalize_tasks(tasks_payload, owner)
    macros = build_project_macros(owner, project)

    session = ScanSession.objects.create(
        project=project,
        owner=owner,
        title=title or f"Scan {timezone.now():%Y-%m-%d %H:%M}",
        config_snapshot=config,
        macros_snapshot=macros,
        report_snapshot={},
        status=ScanSession.Status.PLANNED,
    )

    for task in planned_tasks:
        ScanTask.objects.create(
            session=session,
            order=task.order,
            kind=task.kind,
            name=task.name,
            tool=task.tool,
            script=task.script,
            wordlist=task.wordlist,
            parameters=task.parameters,
        )

    log_event(
        source_app="arpia_scan",
        event_type="scan.session.created",
        message=f"Sessão {session.reference} criada",
        context={
            "session_id": str(session.pk),
            "session_reference": session.reference,
            "project_id": str(project.pk),
            "project_name": project.name,
            "owner_id": owner.pk,
            "owner_username": getattr(owner, "username", ""),
        },
        correlation={
            "scan_session_id": str(session.pk),
            "project_id": str(project.pk),
        },
        tags=["scan", "session"],
    )

    return session


@dataclass
class ConnectivityProbeResult:
    host: str
    reachable: bool
    ports: List[dict]
    error: Optional[str] = None


class ConnectivityRunner:
    def __init__(self, hosts: List[str], ports: Sequence[PortSpec | int | dict | str], *, timeout: float = 1.5):
        self.hosts = hosts
        normalized = []
        for item in ports or []:
            spec = PortSpec.from_value(item)
            if spec:
                normalized.append(spec)
        if not normalized:
            normalized = list(DEFAULT_CONNECTIVITY_PORTS)
        self.ports = normalized
        self.timeout = timeout

    def run(self) -> List[ConnectivityProbeResult]:
        results: List[ConnectivityProbeResult] = []
        for host in self.hosts:
            results.append(self._probe_host(host))
        return results

    def _probe_host(self, host: str) -> ConnectivityProbeResult:
        reachable = False
        port_results: List[dict] = []
        last_error: Optional[str] = None

        for spec in self.ports:
            if spec.protocol == "udp":
                status, payload = self._probe_udp(host, spec.port)
            else:
                status, payload = self._probe_tcp(host, spec.port)

            payload.update({"port": spec.port, "protocol": spec.protocol})
            port_results.append(payload)

            if status == "open":
                reachable = True
            elif payload.get("error"):
                last_error = payload["error"]

        return ConnectivityProbeResult(host=host, reachable=reachable, ports=port_results, error=last_error)

    def _probe_tcp(self, host: str, port: int) -> tuple[str, dict]:
        started = time.perf_counter()
        try:
            with closing(socket.create_connection((host, int(port)), timeout=self.timeout)):
                latency_ms = (time.perf_counter() - started) * 1000
                return "open", {"status": "open", "latency_ms": round(latency_ms, 2)}
        except (OSError, socket.timeout) as exc:
            return "closed", {"status": "closed", "error": str(exc)}

    def _probe_udp(self, host: str, port: int) -> tuple[str, dict]:
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((host, int(port)))
            payload = b"\x00"
            sock.send(payload)
            try:
                sock.recv(1)
                latency_ms = (time.perf_counter() - started) * 1000
                return "open", {"status": "open", "latency_ms": round(latency_ms, 2)}
            except socket.timeout:
                latency_ms = (time.perf_counter() - started) * 1000
                return "open", {
                    "status": "open",
                    "latency_ms": round(latency_ms, 2),
                    "note": "Sem resposta UDP (best-effort)",
                }
        except (ConnectionRefusedError, OSError) as exc:
            return "closed", {"status": "closed", "error": str(exc)}
        finally:
            sock.close()


class ScanOrchestrator:
    def __init__(self, session: ScanSession, *, run_as_user=None):
        self.session = session
        self.user = run_as_user or session.owner
        self.macros = session.macros_snapshot or build_project_macros(self.user, session.project)

    def run(self) -> ScanSession:
        if self.session.status == ScanSession.Status.RUNNING:
            raise ValidationError("Sessão já está em execução.")
        if self.session.is_terminal:
            raise ValidationError("Sessão já foi finalizada.")

        self.session.mark_started()

        log_event(
            source_app="arpia_scan",
            event_type="scan.session.started",
            message=f"Sessão {self.session.reference} iniciada",
            context=self._log_context(),
            correlation=self._log_correlation(),
            tags=["scan", "session"],
        )

        summary_data = {
            "tasks": [],
            "project": self.session.project.name,
        }

        try:
            for task in self.session.tasks.order_by("order", "id"):
                self._run_task(task, summary_data)
        except Exception as exc:  # pragma: no cover - caminho de erro inesperado
            self.session.mark_finished(success=False, error=str(exc))
            log_event(
                source_app="arpia_scan",
                event_type="scan.session.failed",
                message=f"Sessão {self.session.reference} falhou",
                severity=LogEntry.Severity.ERROR,
                context=self._log_context(),
                correlation=self._log_correlation(),
                details={"error": str(exc)},
                tags=["scan", "session", "failure"],
            )
            raise
        else:
            self.session.mark_finished(success=True)
            self._persist_summary(summary_data)
            log_event(
                source_app="arpia_scan",
                event_type="scan.session.completed",
                message=f"Sessão {self.session.reference} concluída",
                context=self._log_context(),
                correlation=self._log_correlation(),
                details={"tasks_processed": len(summary_data.get("tasks", []))},
                tags=["scan", "session", "success"],
            )

        return self.session

    def _run_task(self, task: ScanTask, summary_data: dict) -> None:
        task.status = ScanTask.Status.RUNNING
        task.started_at = timezone.now()
        task.progress = 0.05
        task.stdout = ""
        task.stderr = ""
        task.save(update_fields=["status", "started_at", "progress", "stdout", "stderr", "updated_at"])

        stdout_lines: List[str] = []
        stdout_lines.append(f"[INFO] Iniciando '{task.name}' às {task.started_at:%H:%M:%S}")

        log_event(
            source_app="arpia_scan",
            event_type="scan.task.started",
            message=f"Tarefa {task.kind} iniciada",
            context=self._log_context(task=task),
            correlation=self._log_correlation(task=task),
            tags=["scan", "task", task.kind],
        )

        if task.kind == ScanTask.Kind.CONNECTIVITY:
            stdout_lines.extend(self._execute_connectivity(task, summary_data))
        elif task.kind == ScanTask.Kind.DISCOVERY_RUSTSCAN:
            stdout_lines.extend(self._simulate_rustscan(task, summary_data))
        elif task.kind == ScanTask.Kind.DISCOVERY_NMAP:
            stdout_lines.extend(self._simulate_nmap(task, summary_data))
        else:
            stdout_lines.append("[INFO] Etapa personalizada concluída (simulada).")

        stdout_lines.append("[INFO] Finalizando etapa.")

        task.stdout = "\n".join(stdout_lines)
        task.progress = 1.0
        task.finished_at = timezone.now()
        task.status = ScanTask.Status.COMPLETED
        task.save(update_fields=["status", "finished_at", "progress", "stdout", "updated_at"])

        log_event(
            source_app="arpia_scan",
            event_type="scan.task.completed",
            message=f"Tarefa {task.kind} concluída",
            context=self._log_context(task=task),
            correlation=self._log_correlation(task=task),
            details={
                "duration_seconds": (task.finished_at - task.started_at).total_seconds() if task.started_at else None,
                "tool": task.tool.slug if task.tool else None,
                "script": task.script.slug if task.script else None,
            },
            tags=["scan", "task", task.kind],
        )

        summary_data.setdefault("tasks", []).append(
            {
                "kind": task.kind,
                "name": task.name,
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "finished_at": task.finished_at.isoformat() if task.finished_at else None,
                "tool": task.tool.name if task.tool else None,
                "script": task.script.name if task.script else None,
            }
        )

    def _log_context(self, *, task: Optional[ScanTask] = None) -> dict:
        context = {
            "session_id": str(self.session.pk),
            "session_reference": self.session.reference,
            "project_id": str(self.session.project_id),
            "project_name": self.session.project.name,
            "owner_id": self.session.owner_id,
            "owner_username": getattr(self.session.owner, "username", ""),
        }
        if task:
            context.update(
                {
                    "task_id": task.id,
                    "task_kind": task.kind,
                    "task_name": task.name,
                }
            )
        return context

    def _log_correlation(self, *, task: Optional[ScanTask] = None) -> dict:
        correlation = {
            "scan_session_id": str(self.session.pk),
            "project_id": str(self.session.project_id),
        }
        if task:
            correlation.update({
                "scan_task_id": task.id,
                "scan_task_kind": task.kind,
            })
        return correlation

    def _execute_connectivity(self, task: ScanTask, summary_data: dict) -> List[str]:
        lines = ["[STEP] Validando conectividade básica"]
        hosts = self._configured_hosts()

        if not hosts:
            lines.append("[WARN] Nenhum host alvo configurado. Pulando etapa de conectividade.")
            summary_data.setdefault("artifacts", {})["connectivity"] = []
            return lines

        ports = self._configured_ports(task)
        timeout = float(task.parameters.get("timeout", 1.5)) if isinstance(task.parameters, dict) else 1.5
        runner = ConnectivityRunner(hosts, ports, timeout=timeout)
        results = runner.run()

        reachable = [result for result in results if result.reachable]
        unreachable = [result for result in results if not result.reachable]

        lines.append(f"[INFO] Hosts avaliados: {', '.join(hosts)}")
        lines.append(
            "[INFO] Portas verificadas: "
            + ", ".join(f"{port.port}/{port.protocol}" for port in ports)
        )

        for result in results:
            if result.reachable:
                best_latency = next((port.get("latency_ms") for port in result.ports if port.get("status") == "open"), None)
                latency_text = f" (latência {best_latency:.1f}ms)" if best_latency is not None else ""
                lines.append(f"[OK] {result.host} respondeu às conexões{latency_text}.")
            else:
                reason = result.error or "sem detalhes"
                lines.append(f"[WARN] {result.host} não respondeu ({reason}).")

        summary_data.setdefault("artifacts", {})["connectivity"] = [
            {
                "host": result.host,
                "reachable": result.reachable,
                "ports": result.ports,
                "error": result.error,
            }
            for result in results
        ]

        summary_data.setdefault("connectivity", {}).update(
            {
                "reachable_hosts": [item.host for item in reachable],
                "unreachable_hosts": [item.host for item in unreachable],
                "checked_ports": [
                    {"port": port.port, "protocol": port.protocol}
                    for port in ports
                ],
            }
        )

        self._store_connectivity_findings(results, task)

        if not reachable:
            lines.append("[WARN] Nenhum host respondeu durante o teste de conectividade.")
            summary_data.setdefault("insights", []).append(
                {
                    "level": "warning",
                    "message": "Nenhum host respondeu durante o teste de conectividade.",
                }
            )
        elif unreachable:
            lines.append(f"[INFO] {len(unreachable)} host(s) não responderam.")
            summary_data.setdefault("insights", []).append(
                {
                    "level": "info",
                    "message": f"{len(unreachable)} host(s) não responderam ao teste de conectividade.",
                }
            )
        else:
            lines.append("[INFO] Todos os hosts responderam com sucesso.")
            summary_data.setdefault("insights", []).append(
                {
                    "level": "success",
                    "message": "Todos os hosts configurados responderam ao teste de conectividade.",
                }
            )

        return lines

    def _simulate_rustscan(self, task: ScanTask, summary_data: dict) -> List[str]:
        lines = ["[STEP] Rustscan discovery (simulado)"]
        hosts = self._target_hosts()
        ports = (self.macros.get("TARGET_PORTS") or "22, 80, 443").split(",")
        clean_ports = [p.strip() for p in ports if p.strip()]
        lines.append(f"[INFO] Hosts analisados: {', '.join(hosts[:5])}")
        lines.append(f"[INFO] Portas alvo: {', '.join(clean_ports)}")
        if task.wordlist:
            lines.append(f"[INFO] Wordlist associada: {task.wordlist.name}")
        summary_data.setdefault("artifacts", {})["rustscan"] = self._generate_rustscan_payload(hosts)
        return lines

    def _simulate_nmap(self, task: ScanTask, summary_data: dict) -> List[str]:
        lines = ["[STEP] Nmap multi-perfil (simulado)"]
        if task.script:
            lines.append(f"[INFO] Script selecionado: {task.script.name}")
        lines.append("[INFO] Executando perfis de ruído crescente para hosts prioritários.")
        hosts = self._target_hosts()
        summary_data.setdefault("artifacts", {})["nmap"] = self._generate_nmap_payload(hosts)
        return lines

    def _target_hosts(self) -> List[str]:
        hosts = [host.strip() for host in (self.macros.get("TARGET_HOSTS") or "").splitlines() if host.strip()]
        if hosts:
            return hosts
        return ["10.0.0.5", "10.0.0.8"]

    def _configured_hosts(self) -> List[str]:
        return [host.strip() for host in (self.macros.get("TARGET_HOSTS") or "").splitlines() if host.strip()]

    def _configured_ports(self, task: ScanTask) -> List[PortSpec]:
        raw_ports = task.parameters.get("ports") if isinstance(task.parameters, dict) else None
        ports_source = raw_ports or self.macros.get("TARGET_PORTS") or []

        if isinstance(ports_source, str):
            sanitized = ports_source
            for sep in [";", "\n", "\r", "\t"]:
                sanitized = sanitized.replace(sep, ",")
            tokens = [token.strip() for token in sanitized.split(",") if token.strip()]
        elif isinstance(ports_source, (list, tuple)):
            tokens = [str(item).strip() for item in ports_source if str(item).strip()]
        else:
            tokens = []

        ports: List[PortSpec] = []
        for token in tokens:
            spec = PortSpec.from_value(token)
            if spec:
                ports.append(spec)

        if ports:
            return ports

        return list(DEFAULT_CONNECTIVITY_PORTS)

    def _store_connectivity_findings(self, results: List[ConnectivityProbeResult], task: ScanTask) -> None:
        if not results:
            return

        existing_count = self.session.findings.count()
        findings: List[ScanFinding] = []

        for index, result in enumerate(results, start=1):
            status = "alcançado" if result.reachable else "inalcançável"
            open_ports = [
                port_info
                for port_info in result.ports
                if port_info.get("status") == "open"
            ]
            summary = "Portas abertas: " + ", ".join(str(port.get("port")) for port in open_ports) if open_ports else "Nenhuma porta respondeu"
            severity = "low" if result.reachable else "medium"

            findings.append(
                ScanFinding(
                    session=self.session,
                    source_task=task,
                    kind=ScanFinding.Kind.TARGET,
                    title=f"Conectividade — {result.host}",
                    summary=f"Host {status}. {summary}.",
                    data={
                        "host": result.host,
                        "reachable": result.reachable,
                        "ports": result.ports,
                        "error": result.error,
                    },
                    severity=severity,
                    order=existing_count + index,
                )
            )

        ScanFinding.objects.bulk_create(findings)

    def _generate_rustscan_payload(self, hosts: List[str]) -> str:
        payload = []
        default_ports = [22, 80, 443]
        for idx, host in enumerate(hosts):
            host_ports = []
            for port in default_ports:
                if idx == 0 or port in (80, 443):
                    host_ports.append({"port": port, "status": "open", "protocol": "tcp"})
            if idx % 2 == 1:
                host_ports.append({"port": 445, "status": "closed", "protocol": "tcp"})
            payload.append({"host": host, "ports": host_ports})
        return json.dumps(payload)

    def _generate_nmap_payload(self, hosts: List[str]) -> str:
        ports_template = {
            22: {"service": "ssh", "product": "OpenSSH", "version": "8.2"},
            80: {"service": "http", "product": "Apache", "version": "2.4"},
            443: {"service": "https", "product": "nginx", "version": "1.20"},
        }
        snippets = []
        for host in hosts:
            port_entries = []
            for port, meta in ports_template.items():
                port_entries.append(
                    f"      <port protocol=\"tcp\" portid=\"{port}\">\n"
                    f"        <state state=\"open\" reason=\"syn-ack\"/>\n"
                    f"        <service name=\"{meta['service']}\" product=\"{meta['product']}\" version=\"{meta['version']}\"/>\n"
                    f"      </port>\n"
                )
            snippet = (
                "  <host>\n"
                "    <status state=\"up\" reason=\"syn-ack\"/>\n"
                f"    <address addr=\"{host}\" addrtype=\"ipv4\"/>\n"
                "    <ports>\n"
                + "".join(port_entries)
                + "    </ports>\n"
                "  </host>\n"
            )
            snippets.append(snippet)
        return "<?xml version=\"1.0\"?>\n<nmaprun>\n" + "".join(snippets) + "</nmaprun>"

    def _persist_summary(self, summary_data: dict) -> None:
        connectivity_artifact = summary_data.get("artifacts", {}).get("connectivity", [])
        hosts = [item.get("host") for item in connectivity_artifact if item.get("host")] or self._target_hosts()
        summary_data["hosts"] = hosts
        data = {
            "hosts": hosts,
            "tasks": summary_data.get("tasks", []),
        }
        if connectivity_artifact:
            data["connectivity"] = connectivity_artifact
        finding = ScanFinding.objects.create(
            session=self.session,
            kind=ScanFinding.Kind.SUMMARY,
            title=f"Resumo da sessão {self.session.title}",
            summary="Sessão concluída com sucesso.",
            data=json.loads(json.dumps(data)),
        )
        summary_data.setdefault("findings", []).append(
            {
                "id": finding.id,
                "kind": finding.kind,
                "title": finding.title,
                "summary": finding.summary,
            }
        )
        artifacts = summary_data.get("artifacts", {})
        rustscan_endpoints = parse_rustscan_payload(artifacts.get("rustscan"))
        nmap_endpoints = parse_nmap_xml(artifacts.get("nmap"))
        observations = merge_observations([*rustscan_endpoints, *nmap_endpoints])

        summary_data["observations"] = observations

        self._store_findings_from_observations(observations)
        summary_data.setdefault("insights", []).extend(self._build_observation_insights(observations))

        self._update_report_snapshot(summary_data)

    def _store_findings_from_observations(self, observations: dict) -> None:
        targets = observations.get("targets", {})
        services = observations.get("services", {})

        existing_count = self.session.findings.count()

        host_findings = []
        for index, host in enumerate(targets.get("hosts", []), start=1):
            ports = host.get("ports", [])
            port_list = ", ".join(str(port.get("port")) for port in ports) or "Nenhuma porta aberta"
            host_findings.append(
                ScanFinding(
                    session=self.session,
                    kind=ScanFinding.Kind.TARGET,
                    title=f"Host {host.get('host')}",
                    summary=f"Portas abertas: {port_list}",
                    data=host,
                    severity=host.get("severity", "low"),
                    order=existing_count + index,
                )
            )

        ScanFinding.objects.bulk_create(host_findings)

        if services.get("items"):
            ScanFinding.objects.create(
                session=self.session,
                kind=ScanFinding.Kind.SERVICE,
                title="Serviços detectados",
                summary=f"Foram identificados {services.get('count', 0)} serviço(s).",
                data=services,
                order=self.session.findings.count() + 1,
            )

    def _build_observation_insights(self, observations: dict) -> List[dict]:
        insights: List[dict] = []
        targets = observations.get("targets", {})
        services = observations.get("services", {})

        hosts = targets.get("hosts", [])
        open_ports = targets.get("open_ports", 0)
        if hosts:
            insights.append({
                "level": "info",
                "message": f"{len(hosts)} host(s) com {open_ports} porta(s) aberta(s) mapeadas.",
            })
            critical_hosts = [host for host in hosts if host.get("severity") == "high"]
            if critical_hosts:
                insights.append({
                    "level": "warning",
                    "message": f"{len(critical_hosts)} host(s) com portas de alto risco (ex.: SMB/RDP).",
                })
        if services.get("count"):
            https_services = [item for item in services.get("items", []) if item.get("service") in {"https", "http"}]
            if https_services:
                insights.append({
                    "level": "info",
                    "message": "Superfície web detectada — avaliar necessidade de scan de aplicação.",
                })
        return insights

    def _update_report_snapshot(self, summary_data: dict) -> None:
        tasks_qs = self.session.tasks.select_related("tool", "script", "wordlist").order_by("order", "id")
        findings_qs = self.session.findings.order_by("order", "id")

        def _iso(dt):
            return dt.isoformat() if dt else None

        def _truncate(text: Optional[str], limit: int = 1200) -> str:
            if not text:
                return ""
            if len(text) <= limit:
                return text
            return text[: limit - 3] + "..."

        tasks_payload: List[dict] = []
        timeline_payload: List[dict] = []
        status_counts = {choice[0]: 0 for choice in ScanTask.Status.choices}
        completed = 0
        failed = 0

        for task in tasks_qs:
            duration = None
            if task.started_at and task.finished_at:
                duration = (task.finished_at - task.started_at).total_seconds()

            status_counts[task.status] = status_counts.get(task.status, 0) + 1
            if task.status == ScanTask.Status.COMPLETED:
                completed += 1
            if task.status == ScanTask.Status.FAILED:
                failed += 1

            task_payload = {
                "id": task.id,
                "order": task.order,
                "name": task.name,
                "kind": task.kind,
                "status": task.status,
                "status_display": task.get_status_display(),
                "tool": {
                    "slug": task.tool.slug,
                    "name": task.tool.name,
                }
                if task.tool
                else None,
                "script": {
                    "slug": task.script.slug,
                    "name": task.script.name,
                }
                if task.script
                else None,
                "wordlist": {
                    "slug": task.wordlist.slug,
                    "name": task.wordlist.name,
                }
                if task.wordlist
                else None,
                "started_at": _iso(task.started_at),
                "finished_at": _iso(task.finished_at),
                "duration_seconds": duration,
                "progress": task.progress,
                "stdout_excerpt": _truncate(task.stdout, 1600),
            }
            tasks_payload.append(task_payload)

            timeline_payload.append(
                {
                    "label": task.name,
                    "kind": task.kind,
                    "status": task.status,
                    "started_at": _iso(task.started_at),
                    "finished_at": _iso(task.finished_at),
                    "duration_seconds": duration,
                }
            )

        findings_payload = [
            {
                "id": finding.id,
                "kind": finding.kind,
                "kind_display": finding.get_kind_display(),
                "title": finding.title,
                "severity": finding.severity,
                "summary": finding.summary,
                "data": finding.data,
                "created_at": _iso(finding.created_at),
                "source_task_id": finding.source_task_id,
            }
            for finding in findings_qs
        ]

        configured_hosts = [host.strip() for host in (summary_data.get("hosts") or []) if host.strip()]
        raw_ports = self.macros.get("TARGET_PORTS") if isinstance(self.macros, dict) else None
        configured_ports = [p.strip() for p in str(raw_ports).split(",") if p and str(p).strip()] if raw_ports else []

        observations = summary_data.get("observations", {})
        targets_observed = observations.get("targets", {})
        services_observed = observations.get("services", {})

        total_duration = None
        if self.session.started_at and self.session.finished_at:
            total_duration = (self.session.finished_at - self.session.started_at).total_seconds()

        insights = list(summary_data.get("insights", []))
        if not configured_hosts:
            insights.append({"level": "warning", "message": "Nenhum host alvo foi configurado para esta sessão."})
        if failed:
            insights.append({"level": "error", "message": f"{failed} etapa(s) falharam durante a execução."})
        if completed == len(tasks_payload) and completed:
            insights.append({"level": "success", "message": "Todas as etapas foram executadas com sucesso."})

        snapshot = {
            "version": 1,
            "generated_at": timezone.now().isoformat(),
            "session": {
                "id": str(self.session.pk),
                "reference": self.session.reference,
                "title": self.session.title,
                "status": self.session.status,
                "notes": self.session.notes,
            },
            "project": {
                "id": str(self.session.project.pk),
                "name": self.session.project.name,
                "slug": self.session.project.slug,
            },
            "timing": {
                "started_at": _iso(self.session.started_at),
                "finished_at": _iso(self.session.finished_at),
                "duration_seconds": total_duration,
            },
            "targets": {
                "configured_hosts": configured_hosts,
                "configured_ports": configured_ports,
                **targets_observed,
            },
            "services": services_observed,
            "macros": self.macros,
            "stats": {
                "total_tasks": len(tasks_payload),
                "completed_tasks": completed,
                "failed_tasks": failed,
                "status_counts": status_counts,
                "total_findings": len(findings_payload),
                "open_ports": targets_observed.get("open_ports", 0),
                "services_count": services_observed.get("count", 0),
            },
            "timeline": timeline_payload,
            "tasks": tasks_payload,
            "findings": findings_payload,
            "insights": insights,
            "summary": summary_data,
        }

        sanitized = json.loads(json.dumps(snapshot))
        self.session.report_snapshot = sanitized
        self.session.save(update_fields=["report_snapshot", "updated_at"])