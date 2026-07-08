"""Tests for ChainRunner."""

from __future__ import annotations

from saber.agents.base_agent import (
    AgentActionType,
    AgentDecision,
    AgentObservation,
    AgentRunResult,
    AgentRunStatus,
)
from saber.models.scope import AssessmentPhase
from saber.models.target import Target, TargetType
from saber.orchestration.chain_runner import ChainRunner
from saber.orchestration.execution_plan import ExecutionPlan, ExecutionStep, ExecutionStepStatus
from saber.orchestration.step_runner import StepRunRecord


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_step(
    step_id: str = "recon",
    agent_name: str = "recon_agent",
    status: ExecutionStepStatus = ExecutionStepStatus.PENDING,
) -> ExecutionStep:
    """Create step."""

    return ExecutionStep(
        step_id=step_id,
        agent_name=agent_name,
        objective="Run step.",
        phase=AssessmentPhase.RECON,
        target=make_target(),
        status=status,
    )


def make_plan(step: ExecutionStep | None = None) -> ExecutionPlan:
    """Create plan."""

    return ExecutionPlan(
        plan_id="plan1",
        mission_name="Chain Test Mission",
        steps=[step or make_step()],
    )


def make_record(
    status: ExecutionStepStatus,
    agent_status: AgentRunStatus,
    step_id: str = "recon",
    agent_name: str = "recon_agent",
    handoff_agent: str | None = None,
    requires_approval: bool = False,
) -> StepRunRecord:
    """Create record."""

    decision = AgentDecision(
        action_type=AgentActionType.HANDOFF if handoff_agent else AgentActionType.STOP,
        objective="Run step.",
        handoff_agent=handoff_agent,
        message="Record message.",
    )

    result = AgentRunResult(
        agent_name=agent_name,
        status=agent_status,
        decision=decision,
        observations=[AgentObservation(summary="New observation.")],
        metadata={"agent": agent_name},
    )

    return StepRunRecord(
        step_id=step_id,
        agent_name=agent_name,
        status=status,
        agent_result=result,
        new_observations=result.observations,
        handoff_agent=handoff_agent,
        requires_approval=requires_approval,
        metadata={"record": True},
    )


class TestChainRunner:
    """Validate ChainRunner."""

    def test_process_completed_marks_step_completed(self) -> None:
        """Completed record should mark step completed."""

        runner = ChainRunner()
        plan = make_plan()
        record = make_record(ExecutionStepStatus.COMPLETED, AgentRunStatus.COMPLETED)

        updated = runner.process_step_record(plan, record)

        assert updated.get_step("recon").status == ExecutionStepStatus.COMPLETED
        assert updated.get_step("recon").result_metadata["agent_name"] == "recon_agent"

    def test_process_needs_approval_marks_step_and_pauses(self) -> None:
        """Approval record should mark step needs approval and add no handoff."""

        runner = ChainRunner()
        plan = make_plan()
        record = make_record(
            ExecutionStepStatus.NEEDS_APPROVAL,
            AgentRunStatus.NEEDS_APPROVAL,
            requires_approval=True,
        )

        updated = runner.process_step_record(plan, record)

        assert updated.get_step("recon").status == ExecutionStepStatus.NEEDS_APPROVAL
        assert updated.has_blocking_approval() is True
        assert len(updated.steps) == 1
        assert runner.should_pause(record) is True

    def test_process_handoff_adds_dynamic_step(self) -> None:
        """Handoff should mark source and add dynamic step."""

        runner = ChainRunner()
        plan = make_plan()
        record = make_record(
            ExecutionStepStatus.HANDOFF,
            AgentRunStatus.HANDOFF,
            handoff_agent="web_agent",
        )

        updated = runner.process_step_record(plan, record)

        assert updated.get_step("recon").status == ExecutionStepStatus.HANDOFF
        assert len(updated.steps) == 2

        dynamic_step = updated.steps[1]
        assert dynamic_step.agent_name == "web_agent"
        assert dynamic_step.phase == AssessmentPhase.RECON
        assert dynamic_step.depends_on == ["recon"]
        assert dynamic_step.metadata["dynamic"] is True
        assert dynamic_step.metadata["handoff"] is True

    def test_existing_pending_handoff_step_not_duplicated(self) -> None:
        """Existing pending agent step should not be duplicated."""

        runner = ChainRunner()
        source = make_step(step_id="recon", agent_name="recon_agent")
        existing_web = make_step(step_id="web", agent_name="web_agent")
        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[source, existing_web])
        record = make_record(
            ExecutionStepStatus.HANDOFF,
            AgentRunStatus.HANDOFF,
            handoff_agent="web_agent",
        )

        updated = runner.process_step_record(plan, record)

        assert len(updated.steps) == 2
        assert updated.get_step("web").status == ExecutionStepStatus.PENDING

    def test_should_stop_for_complete_plan(self) -> None:
        """Complete plan should stop."""

        runner = ChainRunner()
        plan = make_plan(make_step(status=ExecutionStepStatus.COMPLETED))

        assert runner.should_stop(plan) is True

    def test_should_stop_for_failed_plan(self) -> None:
        """Failed plan should stop."""

        runner = ChainRunner()
        plan = make_plan(make_step(status=ExecutionStepStatus.FAILED))

        assert runner.should_stop(plan) is True

    def test_max_chain_depth_marks_failed(self) -> None:
        """Too many repeated handoffs should fail source step."""

        runner = ChainRunner(max_chain_depth=0)
        plan = make_plan()
        record = make_record(
            ExecutionStepStatus.HANDOFF,
            AgentRunStatus.HANDOFF,
            handoff_agent="web_agent",
        )

        updated = runner.process_step_record(plan, record)

        assert updated.get_step("recon").status == ExecutionStepStatus.FAILED
        assert updated.get_step("recon").result_metadata["reason"] == "max_chain_depth_exceeded"

    def test_phase_mapping_for_lateral_handoff(self) -> None:
        """Lateral movement handoff should use lateral phase."""

        runner = ChainRunner()
        plan = make_plan()
        record = make_record(
            ExecutionStepStatus.HANDOFF,
            AgentRunStatus.HANDOFF,
            handoff_agent="lateral_movement_agent",
        )

        updated = runner.process_step_record(plan, record)
        dynamic_step = updated.steps[1]

        assert dynamic_step.phase == AssessmentPhase.LATERAL_MOVEMENT
