"""Tests for orchestration execution plan models."""

from __future__ import annotations

from datetime import datetime

import pytest

from saber.models.scope import AssessmentPhase
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import (
    ExecutionPlan,
    ExecutionStep,
    ExecutionStepStatus,
    build_default_execution_plan,
    make_step_id,
)


def make_target() -> Target:
    """Create reusable target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_step(
    step_id: str = "recon",
    agent_name: str = "recon_agent",
    objective: str = "Run recon.",
    phase: AssessmentPhase = AssessmentPhase.RECON,
    depends_on: list[str] | None = None,
    status: ExecutionStepStatus = ExecutionStepStatus.PENDING,
) -> ExecutionStep:
    """Create reusable execution step."""

    return ExecutionStep(
        step_id=step_id,
        agent_name=agent_name,
        objective=objective,
        phase=phase,
        target=make_target(),
        depends_on=depends_on or [],
        status=status,
    )


class TestExecutionStep:
    """Validate ExecutionStep."""

    def test_validates_step_id(self) -> None:
        """Empty step ID should raise."""

        with pytest.raises(ValueError, match="ExecutionStep.step_id cannot be empty"):
            make_step(step_id="")

    def test_validates_agent_name(self) -> None:
        """Empty agent name should raise."""

        with pytest.raises(ValueError, match="ExecutionStep.agent_name cannot be empty"):
            make_step(agent_name="")

    def test_validates_objective(self) -> None:
        """Empty objective should raise."""

        with pytest.raises(ValueError, match="ExecutionStep.objective cannot be empty"):
            make_step(objective="")

    def test_can_run_without_dependencies(self) -> None:
        """Pending step with no dependencies can run."""

        step = make_step()

        assert step.can_run(set()) is True

    def test_can_run_with_completed_dependencies(self) -> None:
        """Pending step can run when dependencies are complete."""

        step = make_step(depends_on=["planner"])

        assert step.can_run({"planner"}) is True

    def test_cannot_run_with_missing_dependency(self) -> None:
        """Pending step cannot run with missing dependency."""

        step = make_step(depends_on=["planner"])

        assert step.can_run(set()) is False

    def test_cannot_run_when_not_pending(self) -> None:
        """Completed step cannot run again."""

        step = make_step(status=ExecutionStepStatus.COMPLETED)

        assert step.can_run({"planner"}) is False

    def test_mark_methods_return_updated_copies(self) -> None:
        """Mark helpers should preserve original and return updated copies."""

        step = make_step()

        running = step.mark_running()
        completed = running.mark_completed({"key": "value"})
        failed = step.mark_failed({"error": "bad"})
        skipped = step.mark_skipped({"reason": "skip"})
        approval = step.mark_needs_approval({"reason": "approval"})
        handoff = step.mark_handoff({"handoff_agent": "web_agent"})
        stopped = step.mark_stopped({"reason": "done"})

        assert step.status == ExecutionStepStatus.PENDING
        assert running.status == ExecutionStepStatus.RUNNING
        assert completed.status == ExecutionStepStatus.COMPLETED
        assert completed.result_metadata["key"] == "value"
        assert failed.status == ExecutionStepStatus.FAILED
        assert skipped.status == ExecutionStepStatus.SKIPPED
        assert approval.status == ExecutionStepStatus.NEEDS_APPROVAL
        assert handoff.status == ExecutionStepStatus.HANDOFF
        assert stopped.status == ExecutionStepStatus.STOPPED

    def test_to_dict(self) -> None:
        """Step should serialize."""

        step = make_step()

        data = step.to_dict()

        assert data["step_id"] == "recon"
        assert data["agent_name"] == "recon_agent"
        assert data["phase"] == "recon"
        assert data["status"] == "pending"
        assert data["target"]["value"] == "example.com"


class TestExecutionPlan:
    """Validate ExecutionPlan."""

    def test_validates_plan_id(self) -> None:
        """Empty plan ID should raise."""

        with pytest.raises(ValueError, match="ExecutionPlan.plan_id cannot be empty"):
            ExecutionPlan(plan_id="", mission_name="Mission", steps=[make_step()])

    def test_validates_mission_name(self) -> None:
        """Empty mission name should raise."""

        with pytest.raises(ValueError, match="ExecutionPlan.mission_name cannot be empty"):
            ExecutionPlan(plan_id="plan1", mission_name="", steps=[make_step()])

    def test_requires_steps(self) -> None:
        """Plan should require steps."""

        with pytest.raises(ValueError, match="ExecutionPlan.steps cannot be empty"):
            ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[])

    def test_rejects_duplicate_step_ids(self) -> None:
        """Duplicate step IDs should raise."""

        with pytest.raises(ValueError, match="duplicate step_id"):
            ExecutionPlan(
                plan_id="plan1",
                mission_name="Mission",
                steps=[make_step(step_id="a"), make_step(step_id="a")],
            )

    def test_pending_completed_and_runnable_steps(self) -> None:
        """Plan should calculate pending, completed, and runnable steps."""

        planner = make_step(step_id="planner").mark_completed()
        recon = make_step(step_id="recon", depends_on=["planner"])
        web = make_step(step_id="web", depends_on=["recon"])
        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[planner, recon, web])

        assert [step.step_id for step in plan.pending_steps()] == ["recon", "web"]
        assert plan.completed_step_ids() == {"planner"}
        assert [step.step_id for step in plan.runnable_steps()] == ["recon"]

    def test_get_step_missing_raises(self) -> None:
        """Missing step should raise."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step()])

        with pytest.raises(KeyError, match="Execution step not found"):
            plan.get_step("missing")

    def test_add_step(self) -> None:
        """add_step should return updated plan."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step(step_id="a")])
        updated = plan.add_step(make_step(step_id="b"))

        assert len(plan.steps) == 1
        assert len(updated.steps) == 2
        assert updated.get_step("b").step_id == "b"

    def test_add_duplicate_step_raises(self) -> None:
        """Adding duplicate step should raise."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step(step_id="a")])

        with pytest.raises(ValueError, match="already exists"):
            plan.add_step(make_step(step_id="a"))

    def test_update_step_and_mark_helpers(self) -> None:
        """Plan mark helpers should update target step."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step(step_id="a")])

        completed = plan.mark_step_completed("a", {"done": True})
        failed = plan.mark_step_failed("a", {"error": "bad"})
        approval = plan.mark_step_needs_approval("a", {"approval": True})

        assert completed.get_step("a").status == ExecutionStepStatus.COMPLETED
        assert completed.get_step("a").result_metadata["done"] is True
        assert failed.get_step("a").status == ExecutionStepStatus.FAILED
        assert approval.get_step("a").status == ExecutionStepStatus.NEEDS_APPROVAL

    def test_update_missing_step_raises(self) -> None:
        """Updating missing step should raise."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step(step_id="a")])

        with pytest.raises(KeyError, match="Execution step not found"):
            plan.update_step(make_step(step_id="missing"))

    def test_status_helpers(self) -> None:
        """Plan status helpers should work."""

        approval_plan = ExecutionPlan(
            plan_id="plan1",
            mission_name="Mission",
            steps=[make_step(step_id="a").mark_needs_approval()],
        )
        failed_plan = ExecutionPlan(
            plan_id="plan2",
            mission_name="Mission",
            steps=[make_step(step_id="a").mark_failed()],
        )
        complete_plan = ExecutionPlan(
            plan_id="plan3",
            mission_name="Mission",
            steps=[make_step(step_id="a").mark_completed()],
        )

        assert approval_plan.has_blocking_approval() is True
        assert failed_plan.has_failed_step() is True
        assert complete_plan.is_complete() is True

    def test_to_dict(self) -> None:
        """Plan should serialize."""

        plan = ExecutionPlan(plan_id="plan1", mission_name="Mission", steps=[make_step()])

        data = plan.to_dict()

        assert data["plan_id"] == "plan1"
        assert data["mission_name"] == "Mission"
        assert data["steps"][0]["step_id"] == "recon"
        assert isinstance(datetime.fromisoformat(data["created_at"]), datetime)

    def test_make_step_id(self) -> None:
        """make_step_id should include agent name."""

        step_id = make_step_id("web_agent")

        assert step_id.startswith("web_agent_")
        assert len(step_id) > len("web_agent_")


class TestDefaultPlan:
    """Validate default execution plan factory."""

    def test_build_default_execution_plan(self) -> None:
        """Default plan should include expected agent sequence."""

        plan = build_default_execution_plan(
            mission_name="Default Mission",
            target=make_target(),
            objective="Assess example.com.",
            metadata={"owner": "unit-test"},
        )

        assert plan.mission_name == "Default Mission"
        assert plan.metadata["objective"] == "Assess example.com."
        assert plan.metadata["owner"] == "unit-test"
        assert [step.step_id for step in plan.steps] == [
            "planner",
            "recon",
            "network",
            "web",
            "exploit",
            "post_exploit",
            "lateral_movement",
            "reporter",
        ]
        assert plan.get_step("recon").depends_on == ["planner"]
        assert plan.get_step("exploit").depends_on == ["network", "web"]
        assert plan.get_step("reporter").phase == AssessmentPhase.REPORTING
