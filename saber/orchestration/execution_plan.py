"""Execution plan models for SABER orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from saber.models.scope import AssessmentPhase
from saber.models.target import Target


class ExecutionStepStatus(StrEnum):
    """Status for one execution step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NEEDS_APPROVAL = "needs_approval"
    HANDOFF = "handoff"
    STOPPED = "stopped"


@dataclass(frozen=True)
class ExecutionStep:
    """One planned mission step."""

    step_id: str
    agent_name: str
    objective: str
    phase: AssessmentPhase
    target: Target | None = None
    status: ExecutionStepStatus = ExecutionStepStatus.PENDING
    depends_on: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    result_metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate execution step basics."""

        if not self.step_id.strip():
            raise ValueError("ExecutionStep.step_id cannot be empty.")
        if not self.agent_name.strip():
            raise ValueError("ExecutionStep.agent_name cannot be empty.")
        if not self.objective.strip():
            raise ValueError("ExecutionStep.objective cannot be empty.")

    def can_run(self, completed_step_ids: set[str]) -> bool:
        """Return whether this pending step can run."""

        return self.status == ExecutionStepStatus.PENDING and all(
            dependency in completed_step_ids for dependency in self.depends_on
        )

    def mark_running(self) -> ExecutionStep:
        """Return copy marked running."""

        return replace(self, status=ExecutionStepStatus.RUNNING)

    def mark_completed(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked completed."""

        return replace(
            self,
            status=ExecutionStepStatus.COMPLETED,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def mark_failed(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked failed."""

        return replace(
            self,
            status=ExecutionStepStatus.FAILED,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def mark_skipped(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked skipped."""

        return replace(
            self,
            status=ExecutionStepStatus.SKIPPED,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def mark_needs_approval(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked needs approval."""

        return replace(
            self,
            status=ExecutionStepStatus.NEEDS_APPROVAL,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def mark_handoff(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked handoff."""

        return replace(
            self,
            status=ExecutionStepStatus.HANDOFF,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def mark_stopped(self, result_metadata: dict | None = None) -> ExecutionStep:
        """Return copy marked stopped."""

        return replace(
            self,
            status=ExecutionStepStatus.STOPPED,
            result_metadata={**self.result_metadata, **(result_metadata or {})},
        )

    def to_dict(self) -> dict:
        """Return JSON-compatible step."""

        return {
            "step_id": self.step_id,
            "agent_name": self.agent_name,
            "objective": self.objective,
            "phase": self.phase.value,
            "target": self._target_to_dict(),
            "status": self.status.value,
            "depends_on": self.depends_on,
            "metadata": self.metadata,
            "result_metadata": self.result_metadata,
        }

    def _target_to_dict(self) -> dict | None:
        """Return JSON-compatible target."""

        if self.target is None:
            return None

        if hasattr(self.target, "model_dump"):
            data = self.target.model_dump(mode="json")
            return dict(data)

        if hasattr(self.target, "to_dict"):
            return self.target.to_dict()

        return {
            "type": getattr(self.target, "type", None),
            "value": getattr(self.target, "value", None),
        }


@dataclass(frozen=True)
class ExecutionPlan:
    """Mission execution plan."""

    plan_id: str
    mission_name: str
    steps: list[ExecutionStep]
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self) -> None:
        """Validate execution plan basics."""

        if not self.plan_id.strip():
            raise ValueError("ExecutionPlan.plan_id cannot be empty.")
        if not self.mission_name.strip():
            raise ValueError("ExecutionPlan.mission_name cannot be empty.")
        if not self.steps:
            raise ValueError("ExecutionPlan.steps cannot be empty.")

        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("ExecutionPlan.steps cannot contain duplicate step_id values.")

    def pending_steps(self) -> list[ExecutionStep]:
        """Return pending steps."""

        return [step for step in self.steps if step.status == ExecutionStepStatus.PENDING]

    def completed_step_ids(self) -> set[str]:
        """Return completed or terminal successful step IDs."""

        terminal_statuses = {
            ExecutionStepStatus.COMPLETED,
            ExecutionStepStatus.HANDOFF,
            ExecutionStepStatus.STOPPED,
            ExecutionStepStatus.SKIPPED,
        }
        return {step.step_id for step in self.steps if step.status in terminal_statuses}

    def runnable_steps(self) -> list[ExecutionStep]:
        """Return pending steps with satisfied dependencies."""

        completed = self.completed_step_ids()
        return [step for step in self.steps if step.can_run(completed)]

    def get_step(self, step_id: str) -> ExecutionStep:
        """Get a step by ID."""

        for step in self.steps:
            if step.step_id == step_id:
                return step
        raise KeyError(f"Execution step not found: {step_id}")

    def add_step(self, step: ExecutionStep) -> ExecutionPlan:
        """Return copy with added step."""

        if any(existing.step_id == step.step_id for existing in self.steps):
            raise ValueError(f"Execution step already exists: {step.step_id}")

        return replace(self, steps=[*self.steps, step], updated_at=datetime.now(UTC))

    def update_step(self, updated_step: ExecutionStep) -> ExecutionPlan:
        """Return copy with one step updated."""

        found = False
        steps: list[ExecutionStep] = []
        for step in self.steps:
            if step.step_id == updated_step.step_id:
                steps.append(updated_step)
                found = True
            else:
                steps.append(step)

        if not found:
            raise KeyError(f"Execution step not found: {updated_step.step_id}")

        return replace(self, steps=steps, updated_at=datetime.now(UTC))

    def mark_step_completed(self, step_id: str, metadata: dict | None = None) -> ExecutionPlan:
        """Return copy with step marked completed."""

        return self.update_step(self.get_step(step_id).mark_completed(metadata))

    def mark_step_failed(self, step_id: str, metadata: dict | None = None) -> ExecutionPlan:
        """Return copy with step marked failed."""

        return self.update_step(self.get_step(step_id).mark_failed(metadata))

    def mark_step_needs_approval(self, step_id: str, metadata: dict | None = None) -> ExecutionPlan:
        """Return copy with step marked needs approval."""

        return self.update_step(self.get_step(step_id).mark_needs_approval(metadata))

    def has_blocking_approval(self) -> bool:
        """Return whether any step blocks on approval."""

        return any(step.status == ExecutionStepStatus.NEEDS_APPROVAL for step in self.steps)

    def has_failed_step(self) -> bool:
        """Return whether any step failed."""

        return any(step.status == ExecutionStepStatus.FAILED for step in self.steps)

    def is_complete(self) -> bool:
        """Return whether no pending/running steps remain."""

        active_statuses = {ExecutionStepStatus.PENDING, ExecutionStepStatus.RUNNING}
        return not any(step.status in active_statuses for step in self.steps)

    def to_dict(self) -> dict:
        """Return JSON-compatible plan."""

        return {
            "plan_id": self.plan_id,
            "mission_name": self.mission_name,
            "steps": [step.to_dict() for step in self.steps],
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


def make_step_id(agent_name: str) -> str:
    """Create readable unique step ID."""

    return f"{agent_name}_{uuid4().hex[:8]}"


def build_default_execution_plan(
    mission_name: str,
    target: Target,
    objective: str,
    metadata: dict | None = None,
) -> ExecutionPlan:
    """Build default sequential SABER execution plan."""

    planner = ExecutionStep(
        step_id="planner",
        agent_name="planner_agent",
        objective=objective,
        phase=AssessmentPhase.RECON,
        target=target,
    )
    recon = ExecutionStep(
        step_id="recon",
        agent_name="recon_agent",
        objective="Discover live targets, services, domains, and initial attack surface.",
        phase=AssessmentPhase.RECON,
        target=target,
        depends_on=["planner"],
    )
    network = ExecutionStep(
        step_id="network",
        agent_name="network_agent",
        objective="Enumerate network services and infrastructure weaknesses.",
        phase=AssessmentPhase.NETWORK,
        target=target,
        depends_on=["recon"],
    )
    web = ExecutionStep(
        step_id="web",
        agent_name="web_agent",
        objective="Test discovered web applications and web services.",
        phase=AssessmentPhase.RECON,
        target=target,
        depends_on=["recon"],
    )
    exploit = ExecutionStep(
        step_id="exploit",
        agent_name="exploit_agent",
        objective="Research and safely validate exploitability from confirmed evidence.",
        phase=AssessmentPhase.EXPLOITATION,
        target=target,
        depends_on=["network", "web"],
    )
    post_exploit = ExecutionStep(
        step_id="post_exploit",
        agent_name="post_exploit_agent",
        objective="Enumerate local context after authorized access exists.",
        phase=AssessmentPhase.EXPLOITATION,
        target=target,
        depends_on=["exploit"],
    )
    lateral = ExecutionStep(
        step_id="lateral_movement",
        agent_name="lateral_movement_agent",
        objective="Plan and validate lateral movement paths after authorized access exists.",
        phase=AssessmentPhase.LATERAL_MOVEMENT,
        target=target,
        depends_on=["post_exploit"],
    )
    reporter = ExecutionStep(
        step_id="reporter",
        agent_name="reporter_agent",
        objective="Generate evidence-backed assessment report.",
        phase=AssessmentPhase.REPORTING,
        target=target,
        depends_on=["recon"],
    )

    return ExecutionPlan(
        plan_id=f"plan_{uuid4().hex[:12]}",
        mission_name=mission_name,
        steps=[planner, recon, network, web, exploit, post_exploit, lateral, reporter],
        metadata={"objective": objective, **(metadata or {})},
    )
