from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from django.core.exceptions import ValidationError
from django.utils import timezone

from arpia_log.models import LogEntry
from arpia_log.services import log_event

from .finding_collector import VulnerabilityFindingCollector
from .models import VulnScanSession, VulnTask
from .reporting import upsert_vulnerability_report_entry
from .services import (
	VulnSessionCanceled,
	ensure_session_is_active,
	run_greenbone_scan,
	run_targeted_nmap_scans,
)


@dataclass(slots=True)
class PipelineStep:
	action: str
	label: str
	handler: Callable[[], List[VulnTask]]
	options: Dict[str, object]


DEFAULT_PIPELINE: Sequence[str] = ("targeted", "greenbone")



class VulnOrchestrator:
	"""Executa pipeline de vulnerabilidades para uma sessão."""

	def __init__(
		self,
		session: VulnScanSession,
		*,
		run_as_user=None,
		pipeline: Optional[Iterable[object]] = None,
		allow_prestarted: bool = False,
	) -> None:
		self.session = session
		self.user = run_as_user or session.owner
		self.allow_prestarted = bool(allow_prestarted)
		self.pipeline_steps = self._resolve_pipeline(pipeline)
		self.summary: Dict[str, object] = {
			"pipeline": [step.action for step in self.pipeline_steps],
			"steps": [],
		}

	def run(self) -> VulnScanSession:
		self._ensure_ready()
		prestarted = self.allow_prestarted and self.session.status == VulnScanSession.Status.RUNNING
		if not prestarted:
			self.session.mark_started()
		self._log_session_event(
			"vuln.session.started",
			f"Sessão {self.session.reference} iniciada",
		)

		try:
			for step in self.pipeline_steps:
				ensure_session_is_active(self.session)
				self._execute_step(step)
		except VulnSessionCanceled as exc:
			self._handle_cancellation(str(exc))
			return self.session
		except Exception as exc:  # pragma: no cover - caminhos de erro inesperados
			error_message = str(exc)
			self.session.mark_finished(success=False, error=error_message)
			self._log_session_event(
				"vuln.session.failed",
				f"Sessão {self.session.reference} falhou",
				severity=LogEntry.Severity.ERROR,
				details={"error": error_message},
			)
			raise
		else:
			try:
				collector = VulnerabilityFindingCollector(self.session)
				findings_summary = collector.collect(clean=True)
			except Exception as exc:  # pragma: no cover - erro inesperado de parsing
				error_message = f"Falha ao consolidar vulnerabilidades: {exc}"
				self._log_session_event(
					"vuln.session.failed",
					error_message,
					severity=LogEntry.Severity.ERROR,
					details={"error": str(exc)},
				)
				self.session.mark_finished(success=False, error=str(exc))
				raise
			else:
				self.summary["findings"] = findings_summary
				report_result = upsert_vulnerability_report_entry(self.session, findings_summary)
				self.summary["report_entry"] = {
					"id": str(report_result.entry.pk),
					"created": report_result.created,
				}
			self.summary["generated_at"] = timezone.now().isoformat()
			self._store_summary()
			self.session.mark_finished(success=True)
			self._log_session_event(
				"vuln.session.completed",
				f"Sessão {self.session.reference} concluída",
				details={"steps_processed": len(self.summary.get("steps", []))},
			)

		return self.session

	def _ensure_ready(self) -> None:
		if self.session.status == VulnScanSession.Status.RUNNING:
			if not self.allow_prestarted:
				raise ValidationError("Sessão já está em execução.")
			return
		if self.session.is_terminal:
			raise ValidationError("Sessão já foi finalizada.")

	def _resolve_pipeline(self, pipeline: Optional[Iterable[object]]) -> List[PipelineStep]:
		config = self.session.config_snapshot or {}
		definition: List[object]
		if pipeline is not None:
			definition = list(pipeline)
		else:
			definition = list(config.get("pipeline") or config.get("tasks") or [])

		steps: List[PipelineStep] = []
		for entry in definition:
			normalized = self._normalize_action(entry)
			if not normalized:
				continue
			action, options = normalized
			step = self._build_step(action, options)
			if step:
				steps.append(step)

		if not steps:
			steps = [self._build_step(action, {}) for action in DEFAULT_PIPELINE]
			steps = [step for step in steps if step is not None]
		if not steps:
			raise ValidationError("Nenhuma etapa válida configurada para o pipeline de vulnerabilidades.")
		return steps

	def _normalize_action(self, entry: object) -> Optional[tuple[str, Dict[str, object]]]:
		if isinstance(entry, str):
			action = entry.strip().lower()
			if not action:
				return None
			return action, {}
		if isinstance(entry, dict):
			action_raw = (
				entry.get("action")
				or entry.get("kind")
				or entry.get("name")
				or ""
			)
			action = str(action_raw).strip().lower()
			if not action:
				return None
			options = {
				key: value
				for key, value in entry.items()
				if key not in {"action", "kind", "name"}
			}
			return action, options
		return None

	def _build_step(self, action: str, options: Dict[str, object]) -> Optional[PipelineStep]:
		canonical = action
		step_options = dict(options)

		if action in {"targeted", "targeted_nmap", "targeted_ports", "targeted_nse"}:
			canonical = "targeted"
		elif action in {"greenbone", "gvm"}:
			canonical = "greenbone"
		else:
			return None

		if canonical == "targeted":
			label = "Nmap NSE focado"
			include_nse = bool(step_options.get("include_nse", True))

			def handler() -> List[VulnTask]:
				return run_targeted_nmap_scans(
					self.session,
					triggered_by=self.user,
					include_nse=include_nse,
					auto_finalize=False,
				)

			return PipelineStep(canonical, label, handler, step_options)

		if canonical == "greenbone":
			label = "Greenbone Vulnerability Scan"

			def handler() -> List[VulnTask]:
				task = run_greenbone_scan(
					self.session,
					triggered_by=self.user,
					auto_finalize=False,
				)
				return [task]

			return PipelineStep(canonical, label, handler, step_options)

		return None

	def _execute_step(self, step: PipelineStep) -> None:
		started_at = timezone.now()
		entry: Dict[str, object] = {
			"action": step.action,
			"label": step.label,
			"started_at": started_at.isoformat(),
		}
		self._record_step_event(
			step,
			"vuln.step.started",
			f"Etapa '{step.label}' iniciada.",
		)

		try:
			ensure_session_is_active(self.session)
			result = step.handler()
		except VulnSessionCanceled:
			entry["status"] = "canceled"
			entry["finished_at"] = timezone.now().isoformat()
			self.summary.setdefault("steps", []).append(entry)
			self._record_step_event(
				step,
				"vuln.step.canceled",
				f"Etapa '{step.label}' cancelada.",
				severity=LogEntry.Severity.WARN,
			)
			raise
		except Exception as exc:
			entry["status"] = "failed"
			entry["error"] = str(exc)
			entry["finished_at"] = timezone.now().isoformat()
			self.summary.setdefault("steps", []).append(entry)
			self._record_step_event(
				step,
				"vuln.step.failed",
				f"Etapa '{step.label}' falhou.",
				severity=LogEntry.Severity.ERROR,
				details={"error": str(exc)},
			)
			raise
		else:
			finished_at = timezone.now()
			tasks = self._normalize_tasks(result)
			entry.update(
				{
					"status": "completed",
					"finished_at": finished_at.isoformat(),
					"task_ids": [task.id for task in tasks],
					"task_kinds": [task.kind for task in tasks],
					"task_statuses": [task.status for task in tasks],
				}
			)
			self.summary.setdefault("steps", []).append(entry)
			self._record_step_event(
				step,
				"vuln.step.completed",
				f"Etapa '{step.label}' concluída.",
				details={
					"tasks": [
						{
							"id": task.id,
							"kind": task.kind,
							"status": task.status,
						}
						for task in tasks
					],
				},
			)

	def _normalize_tasks(self, result: Optional[Iterable[VulnTask]]) -> List[VulnTask]:
		if result is None:
			return []
		if isinstance(result, VulnTask):
			return [result]
		return [task for task in result if isinstance(task, VulnTask)]

	def _store_summary(self) -> None:
		snapshot = dict(self.session.report_snapshot or {})
		snapshot["orchestrator"] = self.summary
		self.session.report_snapshot = snapshot
		self.session.save(update_fields=["report_snapshot", "updated_at"])

	def _log_session_event(
		self,
		event_type: str,
		message: str,
		*,
		severity: str = LogEntry.Severity.INFO,
		details: Optional[Dict[str, object]] = None,
	) -> None:
		log_event(
			source_app="arpia_vuln",
			event_type=event_type,
			message=message,
			severity=severity,
			component="vuln.orchestrator",
			context=self._log_context(),
			correlation=self._log_correlation(),
			details=details,
			tags=["vuln", "session"],
		)

	def _record_step_event(
		self,
		step: PipelineStep,
		event_type: str,
		message: str,
		*,
		severity: str = LogEntry.Severity.INFO,
		details: Optional[Dict[str, object]] = None,
	) -> None:
		log_event(
			source_app="arpia_vuln",
			event_type=event_type,
			message=message,
			severity=severity,
			component="vuln.orchestrator",
			context=self._log_context(step=step),
			correlation=self._log_correlation(step=step),
			details=details,
			tags=["vuln", "step", step.action],
		)

	def _log_context(self, *, step: Optional[PipelineStep] = None) -> Dict[str, object]:
		context: Dict[str, object] = {
			"session_id": str(self.session.pk),
			"session_reference": self.session.reference,
			"project_id": str(self.session.project_id),
			"project_name": self.session.project.name,
			"owner_id": self.session.owner_id,
			"owner_username": getattr(self.session.owner, "username", ""),
		}
		if step is not None:
			context.update(
				{
					"pipeline_action": step.action,
					"pipeline_label": step.label,
				}
			)
		return context

	def _handle_cancellation(self, reason: Optional[str] = None) -> None:
		self.session.refresh_from_db(fields=["status", "finished_at", "last_error", "updated_at"])
		if self.session.status != VulnScanSession.Status.CANCELED:
			self.session.status = VulnScanSession.Status.CANCELED
			if not self.session.finished_at:
				self.session.finished_at = timezone.now()
			if reason and not (self.session.last_error or "").strip():
				self.session.last_error = reason
			self.session.save(update_fields=["status", "finished_at", "last_error", "updated_at"])
		self.summary.setdefault("status", "canceled")
		self.summary["generated_at"] = timezone.now().isoformat()
		self._store_summary()
		self._log_session_event(
			"vuln.session.canceled",
			f"Sessão {self.session.reference} cancelada",
			severity=LogEntry.Severity.WARN,
			details={"reason": reason} if reason else None,
		)

	def _log_correlation(self, *, step: Optional[PipelineStep] = None) -> Dict[str, object]:
		correlation: Dict[str, object] = {
			"vuln_session_id": str(self.session.pk),
			"project_id": str(self.session.project_id),
		}
		if step is not None:
			correlation.update(
				{
					"vuln_pipeline_action": step.action,
				}
			)
		return correlation
