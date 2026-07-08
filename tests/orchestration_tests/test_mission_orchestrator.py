"""Tests for MissionOrchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    AgentRunResult,
    AgentRunStatus,
    BaseAgent,
)
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.orchestration.execution_plan import ExecutionPlan, ExecutionStep, ExecutionStepStatus
from saber.orchestration.mission_orchestrator import MissionOrchestrator, MissionRunResult, MissionRunStatus
from saber.tools.registry import ToolRegistry


@dataclass
class FakeSandbox:
    """Fake sandbox."""

    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request."""

        self.requests.append(request)
        return SandboxExecutionResult(
            outcome=SandboxOutcome.EXECUTED,
            allowed=True,
            session=request.session,
            evidence=None,
            return_code=0,
            stdout="ok",
            stderr="",
            reason="ok",
            metadata={"backend": "fake"},
        )


class StaticAgent(BaseAgent):
    """Static orchestration test agent."""

    def __init__(
        self,
        name: str,
        phase: AssessmentPhase,
        status: AgentRunStatus,
        handoff_agent: str | None = None,
    ) -> None:
        """Initialize static agent."""

        super().__init__(AgentConfig(name=name, phase=phase))
        self.status = status
        self.handoff_agent = handoff_agent

    def decide(self, context: AgentContext) -> AgentDecision:
        """Unused by overridden run."""

        return AgentDecision(action_type=AgentActionType.STOP, objective=context.objective)

    def run(self, context: AgentContext) -> AgentRunResult:
        """Return configured result."""

        if self.status == AgentRunStatus.HANDOFF:
            decision = AgentDecision(
                action_type=AgentActionType.HANDOFF,
                objective=context.objective,
                handoff_agent=self.handoff_agent or "web_agent",
                message="Hand off.",
            )
        elif self.status == AgentRunStatus.NEEDS_APPROVAL:
            decision = AgentDecision(
                action_type=AgentActionType.ASK_APPROVAL,
                objective=context.objective,
                requires_approval=True,
                message="Approval required.",
            )
        elif self.status == AgentRunStatus.FAILED:
            decision = AgentDecision(
                action_type=AgentActionType.STOP,
                objective=context.objective,
                message="Failed.",
            )
        else:
            decision = AgentDecision(
                action_type=AgentActionType.STOP,
                objective=context.objective,
                message="Done.",
            )

        return AgentRunResult(
            agent_name=self.config.name,
            status=self.status,
            decision=decision,
            observations=[
                AgentObservation(
                    summary=f"{self.config.name} completed.",
                    metadata={"agent": self.config.name},
                )
            ],
            metadata={"agent": self.config.name},
        )


def make_session() -> MissionSession:
    """Create session."""

    return MissionSession(
        session_id="mission_orchestrator_session_1",
        mission_name="Mission Orchestrator Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_step(
    step_id: str,
    agent_name: str,
    depends_on: list[str] | None = None,
    phase: AssessmentPhase = AssessmentPhase.RECON,
) -> ExecutionStep:
    """Create execution step."""

    return ExecutionStep(
        step_id=step_id,
        agent_name=agent_name,
        objective=f"Run {agent_name}.",
        phase=phase,
        target=make_target(),
        depends_on=depends_on or [],
    )


def make_plan(steps: list[ExecutionStep]) -> ExecutionPlan:
    """Create plan."""

    return ExecutionPlan(
        plan_id="plan1",
        mission_name="Mission Orchestrator Test Mission",
        steps=steps,
    )


def make_orchestrator(
    agents: dict[str, BaseAgent],
    max_steps: int = 50,
) -> MissionOrchestrator:
    """Create orchestrator."""

    return MissionOrchestrator(
        agents=agents,
        tool_registry=ToolRegistry([]),
        sandbox=FakeSandbox(),
        max_steps=max_steps,
    )


class TestMissionRunResult:
    """Validate MissionRunResult."""

    def test_to_dict(self) -> None:
        """Result should serialize."""

        session = make_session()
        plan = make_plan([make_step("one", "one_agent")])
        result = MissionRunResult(
            session=session,
            plan=plan,
            status=MissionRunStatus.STOPPED,
            observations=[AgentObservation(summary="Observed.")],
            records=[],
            metadata={"reason": "test"},
        )

        data = result.to_dict()

        assert data["session_id"] == session.session_id
        assert data["status"] == "stopped"
        assert data["observations"][0]["summary"] == "Observed."
        assert data["metadata"]["reason"] == "test"


class TestMissionOrchestrator:
    """Validate MissionOrchestrator."""

    def test_requires_agents(self) -> None:
        """Orchestrator should require agents."""

        with pytest.raises(ValueError, match="requires at least one agent"):
            MissionOrchestrator(
                agents={},
                tool_registry=ToolRegistry([]),
                sandbox=FakeSandbox(),
            )

    def test_requires_positive_max_steps(self) -> None:
        """max_steps should be positive."""

        with pytest.raises(ValueError, match="max_steps must be at least 1"):
            MissionOrchestrator(
                agents={"agent": StaticAgent("agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED)},
                tool_registry=ToolRegistry([]),
                sandbox=FakeSandbox(),
                max_steps=0,
            )

    def test_create_plan_uses_default_plan(self) -> None:
        """create_plan should build default plan."""

        orchestrator = make_orchestrator(
            {"planner_agent": StaticAgent("planner_agent", AssessmentPhase.RECON, AgentRunStatus.STOPPED)}
        )

        plan = orchestrator.create_plan(
            mission_name="Created Mission",
            target=make_target(),
            objective="Assess example.com.",
            metadata={"owner": "unit-test"},
        )

        assert plan.mission_name == "Created Mission"
        assert plan.metadata["objective"] == "Assess example.com."
        assert plan.metadata["owner"] == "unit-test"
        assert plan.get_step("planner").agent_name == "planner_agent"

    def test_runs_single_step_to_completion(self) -> None:
        """Simple one-step plan should complete."""

        agents = {
            "one_agent": StaticAgent("one_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan([make_step("one", "one_agent")])

        result = orchestrator.run_until_pause_or_complete(
            plan=plan,
            session=make_session(),
            target=make_target(),
        )

        assert result.status == MissionRunStatus.COMPLETED
        assert result.plan.get_step("one").status == ExecutionStepStatus.COMPLETED
        assert len(result.records) == 1
        assert result.observations[0].metadata["agent"] == "one_agent"

    def test_runs_dependencies_in_order(self) -> None:
        """Dependent steps should run after dependencies complete."""

        agents = {
            "first_agent": StaticAgent("first_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED),
            "second_agent": StaticAgent("second_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan(
            [
                make_step("first", "first_agent"),
                make_step("second", "second_agent", depends_on=["first"]),
            ]
        )

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.COMPLETED
        assert [record.step_id for record in result.records] == ["first", "second"]
        assert result.plan.get_step("first").status == ExecutionStepStatus.COMPLETED
        assert result.plan.get_step("second").status == ExecutionStepStatus.COMPLETED

    def test_pauses_for_approval(self) -> None:
        """Approval step should pause mission."""

        agents = {
            "approval_agent": StaticAgent("approval_agent", AssessmentPhase.RECON, AgentRunStatus.NEEDS_APPROVAL),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan([make_step("approval", "approval_agent")])

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.PAUSED_FOR_APPROVAL
        assert result.plan.get_step("approval").status == ExecutionStepStatus.NEEDS_APPROVAL
        assert result.metadata["reason"] == "record_requires_approval"

    def test_failed_step_returns_failed(self) -> None:
        """Failed step should fail mission."""

        agents = {
            "bad_agent": StaticAgent("bad_agent", AssessmentPhase.RECON, AgentRunStatus.FAILED),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan([make_step("bad", "bad_agent")])

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.FAILED
        assert result.plan.get_step("bad").status == ExecutionStepStatus.FAILED

    def test_handoff_adds_dynamic_step_and_runs_it(self) -> None:
        """Handoff should add dynamic step and continue."""

        agents = {
            "recon_agent": StaticAgent(
                "recon_agent",
                AssessmentPhase.RECON,
                AgentRunStatus.HANDOFF,
                handoff_agent="web_agent",
            ),
            "web_agent": StaticAgent("web_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan([make_step("recon", "recon_agent")])

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.COMPLETED
        assert result.plan.get_step("recon").status == ExecutionStepStatus.HANDOFF
        assert len(result.records) == 2
        assert result.records[0].handoff_agent == "web_agent"
        assert result.records[1].agent_name == "web_agent"
        assert any(step.agent_name == "web_agent" for step in result.plan.steps)

    def test_no_runnable_pending_steps_returns_stopped(self) -> None:
        """Unsatisfied dependencies should stop."""

        agents = {
            "blocked_agent": StaticAgent("blocked_agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED),
        }
        orchestrator = make_orchestrator(agents)
        plan = make_plan([make_step("blocked", "blocked_agent", depends_on=["missing"])])

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.STOPPED
        assert result.metadata["reason"] == "no_runnable_steps"
        assert result.records == []

    def test_max_steps_stops(self) -> None:
        """max_steps should stop runaway missions."""

        agents = {
            "loop_agent": StaticAgent(
                "loop_agent",
                AssessmentPhase.RECON,
                AgentRunStatus.HANDOFF,
                handoff_agent="next_agent",
            ),
            "next_agent": StaticAgent(
                "next_agent",
                AssessmentPhase.RECON,
                AgentRunStatus.HANDOFF,
                handoff_agent="loop_agent",
            ),
        }
        orchestrator = make_orchestrator(agents, max_steps=1)
        plan = make_plan([make_step("loop", "loop_agent")])

        result = orchestrator.run_until_pause_or_complete(plan, make_session(), make_target())

        assert result.status == MissionRunStatus.STOPPED
        assert result.metadata["reason"] == "max_steps_reached"

    def test_run_mission_creates_plan_when_missing(self) -> None:
        """run_mission should create default plan when plan omitted."""

        agents = {
            "planner_agent": StaticAgent("planner_agent", AssessmentPhase.RECON, AgentRunStatus.STOPPED),
            "recon_agent": StaticAgent("recon_agent", AssessmentPhase.RECON, AgentRunStatus.STOPPED),
            "network_agent": StaticAgent("network_agent", AssessmentPhase.NETWORK, AgentRunStatus.STOPPED),
            "web_agent": StaticAgent("web_agent", AssessmentPhase.RECON, AgentRunStatus.STOPPED),
            "exploit_agent": StaticAgent("exploit_agent", AssessmentPhase.EXPLOITATION, AgentRunStatus.STOPPED),
            "post_exploit_agent": StaticAgent("post_exploit_agent", AssessmentPhase.EXPLOITATION, AgentRunStatus.STOPPED),
            "lateral_movement_agent": StaticAgent(
                "lateral_movement_agent",
                AssessmentPhase.LATERAL_MOVEMENT,
                AgentRunStatus.STOPPED,
            ),
            "reporter_agent": StaticAgent("reporter_agent", AssessmentPhase.REPORTING, AgentRunStatus.STOPPED),
        }
        orchestrator = make_orchestrator(agents)

        result = orchestrator.run_mission(
            session=make_session(),
            target=make_target(),
            objective="Assess example.com.",
        )

        assert result.plan.get_step("planner").agent_name == "planner_agent"
        assert result.status in {MissionRunStatus.COMPLETED, MissionRunStatus.STOPPED}
