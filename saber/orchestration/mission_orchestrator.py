"""Mission orchestrator for SABER."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from saber.agents.base_agent import AgentObservation, BaseAgent
from saber.core.sandbox import Sandbox
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.orchestration.chain_runner import ChainRunner
from saber.orchestration.execution_plan import (
    ExecutionPlan,
    ExecutionStep,
    ExecutionStepStatus,
    build_default_execution_plan,
)
from saber.orchestration.step_runner import StepRunRecord, StepRunner
from saber.tools.registry import ToolRegistry
from saber.reporting.finalizer import ReportFinalizer

if TYPE_CHECKING:
    from saber.orchestration.mission_loop import MissionLoop, MissionLoopResult


class MissionRunStatus(StrEnum):
    """Top-level mission run status."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED_FOR_APPROVAL = "paused_for_approval"
    STOPPED = "stopped"


@dataclass(frozen=True)
class MissionArtifact:
    """Artifact emitted during or after a mission."""

    path: str
    kind: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible artifact."""

        return {
            "path": self.path,
            "kind": self.kind,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class MissionRunResult:
    """Result of a mission orchestration run."""

    session: MissionSession
    plan: ExecutionPlan
    status: MissionRunStatus
    observations: list[AgentObservation] = field(default_factory=list)
    records: list[StepRunRecord] = field(default_factory=list)
    artifacts: list[MissionArtifact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible result."""

        return {
            "session_id": self.session.session_id,
            "mission_name": self.session.mission_name,
            "plan": self.plan.to_dict(),
            "status": self.status.value,
            "observations": [
                {
                    "summary": observation.summary,
                    "tool_name": observation.tool_name,
                    "action": observation.action,
                    "success": observation.success,
                    "metadata": observation.metadata,
                }
                for observation in self.observations
            ],
            "records": [record.to_dict() for record in self.records],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "metadata": self.metadata,
        }


class MissionOrchestrator:
    """Top-level SABER mission orchestrator."""

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: ToolRegistry,
        sandbox: Sandbox,
        step_runner: StepRunner | None = None,
        chain_runner: ChainRunner | None = None,
        result_processor: Any | None = None,
        report_finalizer: ReportFinalizer | None = None,
        reports_dir: Path | str | None = None,
        export_artifacts: bool = True,
        max_steps: int = 50,
        mission_loop: MissionLoop | None = None,
    ) -> None:
        """Initialize mission orchestrator."""

        if not agents:
            raise ValueError("MissionOrchestrator requires at least one agent.")
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1.")

        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox
        self.mission_loop = mission_loop
        self.step_runner = step_runner or StepRunner(
            agents=agents,
            tool_registry=tool_registry,
            sandbox=sandbox,
        )
        self.chain_runner = chain_runner or ChainRunner()
        self.result_processor = result_processor
        self.report_finalizer = report_finalizer
        self.reports_dir = Path(reports_dir or "runs/reports")
        self.export_artifacts = export_artifacts
        self.max_steps = max_steps

    def create_plan(
        self,
        mission_name: str,
        target: Target,
        objective: str,
        metadata: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Create an execution plan.

        Prefer PlannerAgent when present. Fall back to the static default plan.
        """

        planner = self.agents.get("planner_agent")
        if planner is not None and hasattr(planner, "build_execution_plan"):
            return planner.build_execution_plan(
                mission_name=mission_name,
                target=target,
                objective=objective,
                observations=[],
                available_agents=set(self.agents),
                metadata=metadata,
            )

        return build_default_execution_plan(
            mission_name=mission_name,
            target=target,
            objective=objective,
            metadata=metadata,
        )

    def run_mission(
        self,
        session: MissionSession,
        target: Target,
        objective: str,
        plan: ExecutionPlan | None = None,
        initial_observations: list[AgentObservation] | None = None,
        constraints: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MissionRunResult:
        """Run a mission. State-first via MissionLoop when available."""

        if self.mission_loop is not None:
            constraints = constraints or {}
            state = MissionState(
                session_id=session.session_id,
                target=target,
                objective=objective,
                scope=session.scope,
                autonomy_level=AutonomyLevel(
                    str(constraints.get("autonomy_level", AutonomyLevel.AUTONOMOUS.value))
                ),
                roe=constraints.get("roe", {}),
                metadata=metadata or {},
            )
            loop_result = self.mission_loop.run(state=state, session=session)
            return self._result_from_loop(loop_result)

        # Legacy plan-first path retained only as an explicit fallback (removed in P5).
        active_plan = plan or self.create_plan(
            mission_name=session.mission_name,
            target=target,
            objective=objective,
            metadata=metadata,
        )

        return self.run_until_pause_or_complete(
            plan=active_plan,
            session=session,
            target=target,
            observations=initial_observations or [],
            constraints=constraints,
            metadata=metadata,
        )

    def _result_from_loop(self, loop_result: MissionLoopResult) -> MissionRunResult:
        """Adapt a MissionLoopResult into the existing MissionRunResult shape.

        The loop is state-first and has no static ExecutionPlan, so we synthesize
        a single completed step to keep MissionRunResult's shape intact for
        existing consumers. ExecutionPlan/ExecutionStep both reject empty
        plan_id/steps/objective, so those fields are always populated.
        """

        plan = ExecutionPlan(
            plan_id="mission_loop",
            mission_name=loop_result.session.mission_name,
            steps=[
                ExecutionStep(
                    step_id="mission_loop",
                    agent_name="mission_loop",
                    objective=(loop_result.state.objective or "Agentic mission loop"),
                    phase=AssessmentPhase.RECON,
                    status=ExecutionStepStatus.COMPLETED,
                )
            ],
        )

        return MissionRunResult(
            session=loop_result.session,
            plan=plan,
            status=loop_result.status,
            observations=[],
            records=[],
            artifacts=[],
            metadata={
                "reason": loop_result.reason,
                "mission_state": loop_result.state.to_summary_dict(),
            },
        )

    def run_until_pause_or_complete(
        self,
        plan: ExecutionPlan,
        session: MissionSession,
        target: Target,
        observations: list[AgentObservation] | None = None,
        constraints: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MissionRunResult:
        """Run a plan until approval pause, failure, completion, or step limit."""

        active_plan = plan
        all_observations = list(observations or [])
        records: list[StepRunRecord] = []
        artifacts: list[MissionArtifact] = []

        for step_count in range(self.max_steps):
            if active_plan.has_blocking_approval():
                return self._finalize_result(
                    self._result(
                        session=session,
                        plan=active_plan,
                        status=MissionRunStatus.PAUSED_FOR_APPROVAL,
                        observations=all_observations,
                        records=records,
                        artifacts=artifacts,
                        metadata={"reason": "blocking_approval", "steps_run": step_count},
                    )
                )

            if active_plan.has_failed_step():
                return self._finalize_result(
                    self._result(
                        session=session,
                        plan=active_plan,
                        status=MissionRunStatus.FAILED,
                        observations=all_observations,
                        records=records,
                        artifacts=artifacts,
                        metadata={"reason": "step_failed", "steps_run": step_count},
                    )
                )

            runnable = self._next_runnable_step(active_plan)
            if runnable is None:
                status = MissionRunStatus.COMPLETED if active_plan.is_complete() else MissionRunStatus.STOPPED
                return self._finalize_result(
                    self._result(
                        session=session,
                        plan=active_plan,
                        status=status,
                        observations=all_observations,
                        records=records,
                        artifacts=artifacts,
                        metadata={"reason": "no_runnable_steps", "steps_run": step_count},
                    )
                )

            active_plan = active_plan.update_step(runnable.mark_running())

            record = self.step_runner.run_step(
                step=runnable,
                session=session,
                target=target,
                observations=all_observations,
                constraints=constraints,
                metadata=metadata,
            )
            records.append(record)
            all_observations.extend(record.new_observations)

            artifacts.extend(
                self._process_step_evidence(
                    record=record,
                    session=session,
                    target=target,
                )
            )

            active_plan = self.chain_runner.process_step_record(active_plan, record)

            if record.requires_approval:
                return self._finalize_result(
                    self._result(
                        session=session,
                        plan=active_plan,
                        status=MissionRunStatus.PAUSED_FOR_APPROVAL,
                        observations=all_observations,
                        records=records,
                        artifacts=artifacts,
                        metadata={"reason": "record_requires_approval", "steps_run": step_count + 1},
                    )
                )

            if self.chain_runner.should_stop(active_plan):
                if active_plan.has_blocking_approval():
                    status = MissionRunStatus.PAUSED_FOR_APPROVAL
                    reason = "blocking_approval"
                elif active_plan.has_failed_step():
                    status = MissionRunStatus.FAILED
                    reason = "step_failed"
                else:
                    status = MissionRunStatus.COMPLETED
                    reason = "plan_complete"

                return self._finalize_result(
                    self._result(
                        session=session,
                        plan=active_plan,
                        status=status,
                        observations=all_observations,
                        records=records,
                        artifacts=artifacts,
                        metadata={"reason": reason, "steps_run": step_count + 1},
                    )
                )

        return self._finalize_result(
            self._result(
                session=session,
                plan=active_plan,
                status=MissionRunStatus.STOPPED,
                observations=all_observations,
                records=records,
                artifacts=artifacts,
                metadata={"reason": "max_steps_reached", "max_steps": self.max_steps},
            )
        )

    def _process_step_evidence(
        self,
        *,
        record: StepRunRecord,
        session: MissionSession,
        target: Target,
    ) -> list[MissionArtifact]:
        """Process evidence paths emitted by a step record."""

        artifacts: list[MissionArtifact] = []

        if self.result_processor is None:
            return artifacts

        record_dict = self._to_dict(record)
        tool_name = self._first_string(record_dict, "tool_name", "tool")
        action = self._first_string(record_dict, "action", "tool_action")

        for observation in record.new_observations:
            tool_name = tool_name or observation.tool_name
            action = action or observation.action

        paths = self._collect_existing_paths(record_dict)

        for observation in record.new_observations:
            paths.extend(self._collect_existing_paths(self._to_dict(observation)))

        seen: set[Path] = set()

        for path in paths:
            if path in seen:
                continue

            seen.add(path)

            try:
                processed = self._call_result_processor(
                    path=path,
                    tool_name=tool_name,
                    action=action,
                    session=session,
                    target=target,
                )
                processed_safe = self._safe_json(processed)
                processed_errors = []
                if isinstance(processed_safe, dict):
                    processed_errors = processed_safe.get("errors") or []

                artifacts.append(
                    MissionArtifact(
                        path=str(path),
                        kind="evidence_processing_error" if processed_errors else "processed_evidence",
                        metadata={
                            "tool_name": tool_name,
                            "action": action,
                            "processor_result": processed_safe,
                            "errors": processed_errors,
                        },
                    )
                )
            except Exception as exc:  # noqa: BLE001 - mission should not die because one parser failed
                artifacts.append(
                    MissionArtifact(
                        path=str(path),
                        kind="evidence_processing_error",
                        metadata={
                            "tool_name": tool_name,
                            "action": action,
                            "error": str(exc),
                        },
                    )
                )

        return artifacts

    def _call_result_processor(
        self,
        *,
        path: Path,
        tool_name: str | None,
        action: str | None,
        session: MissionSession,
        target: Target,
    ) -> Any:
        """Call result processor with a tolerant adapter."""

        processor = self.result_processor

        if hasattr(processor, "process_evidence_file"):
            method = processor.process_evidence_file
            kwargs = {
                "path": path,
                "file_path": path,
                "evidence_file": path,
                "tool_name": tool_name,
                "action": action,
                "tool_action": action,
                "session_id": session.session_id,
                "session": session,
                "target": target,
            }
            return self._call_with_supported_kwargs(method, kwargs)

        if hasattr(processor, "process_record"):
            return processor.process_record(
                record={
                    "path": str(path),
                    "tool_name": tool_name,
                    "action": action,
                    "session_id": session.session_id,
                    "target": self._safe_json(target),
                }
            )

        raise AttributeError("result_processor has no supported processing method")

    @staticmethod
    def _call_with_supported_kwargs(method: Any, kwargs: dict[str, Any]) -> Any:
        """Call a method with only supported keyword arguments."""

        signature = inspect.signature(method)

        if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values()):
            return method(**kwargs)

        supported = {
            key: value
            for key, value in kwargs.items()
            if key in signature.parameters and value is not None
        }

        return method(**supported)

    def _get_report_finalizer(self) -> ReportFinalizer | None:
        """Return configured or lazily-built report finalizer."""

        if self.report_finalizer is not None:
            return self.report_finalizer

        if self.result_processor is None:
            return None

        finding_store = getattr(self.result_processor, "finding_store", None)
        if finding_store is None:
            return None

        connection = getattr(finding_store, "connection", None)
        self.report_finalizer = ReportFinalizer(
            finding_store=finding_store,
            output_dir=self.reports_dir,
            connection=connection,
        )
        return self.report_finalizer

    def _target_to_report_string(self, result: MissionRunResult) -> str:
        """Best-effort target string for reports."""

        if isinstance(result.metadata, dict):
            if result.metadata.get("target"):
                return str(result.metadata["target"])
            if result.metadata.get("target_value"):
                return str(result.metadata["target_value"])

        return "unknown-target"

    def _finalize_result(self, result: MissionRunResult) -> MissionRunResult:
        """Write final mission/report artifacts and return updated result."""

        if not self.export_artifacts:
            return result

        artifacts = list(result.artifacts)

        if result.status.value == "completed":
            finalizer = self._get_report_finalizer()
            if finalizer is not None:
                report_result = finalizer.finalize(
                    session_id=result.session.session_id,
                    mission_name=result.session.mission_name,
                    target=self._target_to_report_string(result),
                    metadata={
                        "mission_status": result.status.value,
                        "orchestrator": "MissionOrchestrator",
                    },
                )

                for report_artifact in report_result.artifacts:
                    artifacts.append(
                        MissionArtifact(
                            path=report_artifact.path,
                            kind=f"report_{report_artifact.report_type}",
                            metadata={
                                **report_artifact.metadata,
                                "sha256": report_artifact.sha256,
                                "size_bytes": report_artifact.size_bytes,
                                "report_id": report_result.report_id,
                            },
                        )
                    )

                if report_result.errors:
                    artifacts.append(
                        MissionArtifact(
                            path=str(self.reports_dir / result.session.session_id),
                            kind="report_export_error",
                            metadata={
                                "report_id": report_result.report_id,
                                "errors": report_result.errors,
                            },
                        )
                    )

        result_with_reports = MissionRunResult(
            session=result.session,
            plan=result.plan,
            status=result.status,
            observations=result.observations,
            records=result.records,
            artifacts=artifacts,
            metadata=result.metadata,
        )

        mission_artifact = self._write_mission_result(result_with_reports)

        return MissionRunResult(
            session=result.session,
            plan=result.plan,
            status=result.status,
            observations=result.observations,
            records=result.records,
            artifacts=[*artifacts, mission_artifact],
            metadata=result.metadata,
        )

    def _write_mission_result(self, result: MissionRunResult) -> MissionArtifact:
        """Write mission result JSON artifact."""

        output_dir = self.reports_dir / result.session.session_id
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / "mission_result.json"

        artifact = MissionArtifact(
            path=str(output_path),
            kind="mission_result_json",
            metadata={"status": result.status.value},
        )

        payload = result.to_dict()
        payload["artifacts"] = [
            artifact.to_dict()
            for artifact in [*result.artifacts, artifact]
        ]

        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

        return artifact

    @staticmethod
    def _collect_existing_paths(value: Any) -> list[Path]:
        """Collect existing filesystem paths from nested dict/list structures."""

        paths: list[Path] = []

        def walk(item: Any) -> None:
            if isinstance(item, dict):
                for key, nested in item.items():
                    lowered = str(key).lower()
                    if any(token in lowered for token in ("path", "file", "artifact")):
                        maybe_path = MissionOrchestrator._coerce_existing_path(nested)
                        if maybe_path is not None:
                            paths.append(maybe_path)
                    walk(nested)

            elif isinstance(item, list | tuple):
                for nested in item:
                    walk(nested)

        walk(value)
        return paths

    @staticmethod
    def _coerce_existing_path(value: Any) -> Path | None:
        """Convert value to an existing path when possible."""

        if not isinstance(value, str) or not value:
            return None

        candidates = [Path(value)]

        if value.startswith("/workspace/"):
            candidates.append(Path.cwd() / value.removeprefix("/workspace/"))

        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate.resolve()
            except OSError:
                continue

        return None

    @staticmethod
    def _to_dict(value: Any) -> dict[str, Any]:
        """Best-effort object to dict conversion."""

        if isinstance(value, dict):
            return value

        if hasattr(value, "to_dict"):
            converted = value.to_dict()
            return converted if isinstance(converted, dict) else {}

        if hasattr(value, "__dict__"):
            return dict(value.__dict__)

        return {}

    @staticmethod
    def _first_string(data: dict[str, Any], *keys: str) -> str | None:
        """Return first non-empty string value for keys."""

        for key in keys:
            value = data.get(key)
            if isinstance(value, str) and value:
                return value

        return None

    @staticmethod
    def _safe_json(value: Any) -> Any:
        """Return JSON-safe representation."""

        if value is None or isinstance(value, str | int | float | bool):
            return value

        if isinstance(value, list | tuple):
            return [MissionOrchestrator._safe_json(item) for item in value]

        if isinstance(value, dict):
            return {
                str(key): MissionOrchestrator._safe_json(item)
                for key, item in value.items()
            }

        if hasattr(value, "to_dict"):
            return MissionOrchestrator._safe_json(value.to_dict())

        return str(value)

    @staticmethod
    def _next_runnable_step(plan: ExecutionPlan) -> ExecutionStep | None:
        """Return first runnable step."""

        runnable = plan.runnable_steps()
        return runnable[0] if runnable else None

    @staticmethod
    def _result(
        session: MissionSession,
        plan: ExecutionPlan,
        status: MissionRunStatus,
        observations: list[AgentObservation],
        records: list[StepRunRecord],
        artifacts: list[MissionArtifact] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> MissionRunResult:
        """Create mission run result."""

        return MissionRunResult(
            session=session,
            plan=plan,
            status=status,
            observations=observations,
            records=records,
            artifacts=artifacts or [],
            metadata=metadata or {},
        )
