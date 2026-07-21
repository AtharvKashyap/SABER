"""Mission orchestrator for SABER."""

from __future__ import annotations

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
from saber.orchestration.execution_plan import (
    ExecutionPlan,
    ExecutionStep,
    ExecutionStepStatus,
    build_default_execution_plan,
)
from saber.orchestration.step_runner import StepRunner, StepRunRecord
from saber.orchestration.strategies.base import select_strategy
from saber.tools.registry import ToolRegistry

if TYPE_CHECKING:
    from saber.orchestration.mission_loop import MissionLoop, MissionLoopResult
    from saber.reporting.finalizer import ReportFinalizer


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
    """Top-level SABER mission orchestrator.

    Missions are driven exclusively by the injected ``MissionLoop`` (state-first
    agentic loop). The legacy plan-first driver (``run_until_pause_or_complete``
    plus the static chain runner) has been retired. ``create_plan()`` remains
    available as an optional recon seed helper and is not used to drive missions.
    """

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: ToolRegistry,
        sandbox: Sandbox,
        step_runner: StepRunner | None = None,
        result_processor: Any | None = None,
        report_finalizer: ReportFinalizer | None = None,
        reports_dir: Path | str | None = None,
        export_artifacts: bool = True,
        max_steps: int = 50,
        mission_loop: MissionLoop | None = None,
    ) -> None:
        """Initialize mission orchestrator.

        A ``mission_loop`` is required: the orchestrator drives missions solely
        through the loop and no longer has a plan-first fallback.
        """

        if not agents:
            raise ValueError("MissionOrchestrator requires at least one agent.")
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1.")
        if mission_loop is None:
            raise ValueError("MissionOrchestrator requires a mission_loop.")

        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox
        self.mission_loop = mission_loop
        self.step_runner = step_runner or StepRunner(
            agents=agents,
            tool_registry=tool_registry,
            sandbox=sandbox,
        )
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

        Optional recon seed helper only. This is NOT used to drive missions
        (the ``MissionLoop`` does that); callers may use it to seed an initial
        plan/summary. Prefers ``PlannerAgent`` when present and falls back to the
        static default plan.
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
        """Run a mission. State-first, driven by the injected MissionLoop.

        ``plan`` and ``initial_observations`` are accepted for backward
        compatibility but are not used to drive: the loop builds its own
        ``MissionState`` from the target, objective, and session scope.

        The target's ``TargetStrategy`` (selected from the target and caller
        metadata) seeds the loop: a blank ``objective`` falls back to the
        strategy's default objective, and the strategy's ``initial_metadata`` is
        merged into ``MissionState.metadata``. Caller-provided metadata keys take
        precedence over strategy defaults.
        """

        constraints = constraints or {}
        caller_metadata = metadata or {}
        strategy = select_strategy(target, caller_metadata)
        seeded_objective = (
            objective if (objective or "").strip() else strategy.seed_objective(target)
        )
        seeded_metadata = {**strategy.initial_metadata(target), **caller_metadata}
        state = MissionState(
            session_id=session.session_id,
            target=target,
            objective=seeded_objective,
            scope=session.scope,
            autonomy_level=AutonomyLevel(
                str(constraints.get("autonomy_level", AutonomyLevel.AUTONOMOUS.value))
            ),
            roe=constraints.get("roe", {}),
            metadata=seeded_metadata,
        )
        loop_result = self.mission_loop.run(state=state, session=session, strategy=strategy)
        return self._result_from_loop(loop_result)

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

        # The loop surfaces report artifacts as reporting.ReportArtifact objects;
        # adapt them to the orchestrator's MissionArtifact shape, preserving the
        # integrity fields (size/hash) in metadata.
        artifacts = [
            MissionArtifact(
                path=artifact.path,
                kind=artifact.report_type,
                metadata={
                    **artifact.metadata,
                    "size_bytes": artifact.size_bytes,
                    "sha256": artifact.sha256,
                },
            )
            for artifact in loop_result.artifacts
        ]

        return MissionRunResult(
            session=loop_result.session,
            plan=plan,
            status=loop_result.status,
            observations=[],
            records=[],
            artifacts=artifacts,
            metadata={
                "reason": loop_result.reason,
                "mission_state": loop_result.state.to_summary_dict(),
            },
        )
