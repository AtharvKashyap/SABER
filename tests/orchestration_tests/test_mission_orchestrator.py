"""Tests for MissionOrchestrator.

Mission driving is owned by the MissionLoop (state-first). The legacy plan-first
driver (``run_until_pause_or_complete`` + the static chain runner) has been
retired, so the tests here cover only the orchestrator's remaining surface:
constructor validation, the ``create_plan`` recon-seed helper, and
``MissionRunResult`` serialization. Loop-driven behavior is covered by
``test_orchestrator_uses_loop.py`` and the MissionLoop suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import MagicMock

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
from saber.orchestration.execution_plan import ExecutionPlan, ExecutionStep
from saber.orchestration.mission_orchestrator import (
    MissionOrchestrator,
    MissionRunResult,
    MissionRunStatus,
)
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
    """Create orchestrator with an injected (unused) loop.

    The kept tests only exercise ``create_plan``/constructor validation, so a
    ``MagicMock`` loop satisfies the now-mandatory ``mission_loop`` dependency
    without being invoked.
    """

    return MissionOrchestrator(
        agents=agents,
        tool_registry=ToolRegistry([]),
        sandbox=FakeSandbox(),
        max_steps=max_steps,
        mission_loop=MagicMock(),
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
    """Validate MissionOrchestrator construction and the create_plan seed."""

    def test_requires_agents(self) -> None:
        """Orchestrator should require agents."""

        with pytest.raises(ValueError, match="requires at least one agent"):
            MissionOrchestrator(
                agents={},
                tool_registry=ToolRegistry([]),
                sandbox=FakeSandbox(),
                mission_loop=MagicMock(),
            )

    def test_requires_positive_max_steps(self) -> None:
        """max_steps should be positive."""

        agent = StaticAgent("agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED)
        with pytest.raises(ValueError, match="max_steps must be at least 1"):
            MissionOrchestrator(
                agents={"agent": agent},
                tool_registry=ToolRegistry([]),
                sandbox=FakeSandbox(),
                max_steps=0,
                mission_loop=MagicMock(),
            )

    def test_requires_mission_loop(self) -> None:
        """Orchestrator should require a mission_loop."""

        agent = StaticAgent("agent", AssessmentPhase.RECON, AgentRunStatus.COMPLETED)
        with pytest.raises(ValueError, match="requires a mission_loop"):
            MissionOrchestrator(
                agents={"agent": agent},
                tool_registry=ToolRegistry([]),
                sandbox=FakeSandbox(),
                mission_loop=None,
            )

    def test_create_plan_uses_default_plan(self) -> None:
        """create_plan should build default plan."""

        planner = StaticAgent("planner_agent", AssessmentPhase.RECON, AgentRunStatus.STOPPED)
        orchestrator = make_orchestrator({"planner_agent": planner})

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
