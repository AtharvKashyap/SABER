"""Mission orchestrator for SABER."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.agents.base_agent import AgentObservation, BaseAgent
from saber.core.sandbox import Sandbox
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


class MissionRunStatus(StrEnum):
    """Top-level mission run status."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED_FOR_APPROVAL = "paused_for_approval"
    STOPPED = "stopped"


@dataclass(frozen=True)
class MissionRunResult:
    """Result of a mission orchestration run."""

    session: MissionSession
    plan: ExecutionPlan
    status: MissionRunStatus
    observations: list[AgentObservation] = field(default_factory=list)
    records: list[StepRunRecord] = field(default_factory=list)
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
            "metadata": self.metadata,
        }


class MissionOrchestrator:
    """Top-level deterministic mission orchestrator."""

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: ToolRegistry,
        sandbox: Sandbox,
        step_runner: StepRunner | None = None,
        chain_runner: ChainRunner | None = None,
        max_steps: int = 50,
    ) -> None:
        """Initialize mission orchestrator."""

        if not agents:
            raise ValueError("MissionOrchestrator requires at least one agent.")
        if max_steps < 1:
            raise ValueError("max_steps must be at least 1.")

        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox
        self.step_runner = step_runner or StepRunner(
            agents=agents,
            tool_registry=tool_registry,
            sandbox=sandbox,
        )
        self.chain_runner = chain_runner or ChainRunner()
        self.max_steps = max_steps

    def create_plan(
        self,
        mission_name: str,
        target: Target,
        objective: str,
        metadata: dict[str, Any] | None = None,
    ) -> ExecutionPlan:
        """Create a default execution plan."""

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
        """Create or use a plan, then run until pause or completion."""

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

        for step_count in range(self.max_steps):
            if active_plan.has_blocking_approval():
                return self._result(
                    session=session,
                    plan=active_plan,
                    status=MissionRunStatus.PAUSED_FOR_APPROVAL,
                    observations=all_observations,
                    records=records,
                    metadata={"reason": "blocking_approval", "steps_run": step_count},
                )

            if active_plan.has_failed_step():
                return self._result(
                    session=session,
                    plan=active_plan,
                    status=MissionRunStatus.FAILED,
                    observations=all_observations,
                    records=records,
                    metadata={"reason": "step_failed", "steps_run": step_count},
                )

            runnable = self._next_runnable_step(active_plan)
            if runnable is None:
                status = MissionRunStatus.COMPLETED if active_plan.is_complete() else MissionRunStatus.STOPPED
                return self._result(
                    session=session,
                    plan=active_plan,
                    status=status,
                    observations=all_observations,
                    records=records,
                    metadata={"reason": "no_runnable_steps", "steps_run": step_count},
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

            active_plan = self.chain_runner.process_step_record(active_plan, record)

            if record.requires_approval:
                return self._result(
                    session=session,
                    plan=active_plan,
                    status=MissionRunStatus.PAUSED_FOR_APPROVAL,
                    observations=all_observations,
                    records=records,
                    metadata={"reason": "record_requires_approval", "steps_run": step_count + 1},
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

                return self._result(
                    session=session,
                    plan=active_plan,
                    status=status,
                    observations=all_observations,
                    records=records,
                    metadata={"reason": reason, "steps_run": step_count + 1},
                )

        return self._result(
            session=session,
            plan=active_plan,
            status=MissionRunStatus.STOPPED,
            observations=all_observations,
            records=records,
            metadata={"reason": "max_steps_reached", "max_steps": self.max_steps},
        )

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
        metadata: dict[str, Any] | None = None,
    ) -> MissionRunResult:
        """Create mission run result."""

        return MissionRunResult(
            session=session,
            plan=plan,
            status=status,
            observations=observations,
            records=records,
            metadata=metadata or {},
        )
