"""Tests for PlannerAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.planner_agent import MissionPlan, PhaseObjective, PlannerAgent
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.registry import ToolRegistry


@dataclass
class FakeSandbox:
    """Fake sandbox."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_session() -> MissionSession:
    """Create session."""

    return MissionSession(
        session_id="planner_session_1",
        mission_name="Planner Agent Test Mission",
        status=SessionStatus.CREATED,
    )


def make_target() -> Target:
    """Create target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create sandbox result."""

    return SandboxExecutionResult(
        outcome=SandboxOutcome.EXECUTED,
        allowed=True,
        session=session or make_session(),
        evidence=None,
        return_code=0,
        stdout="ok",
        stderr="",
        reason="Command executed and evidence was saved.",
        metadata={"backend": "fake", "finished_at": datetime.now(UTC).isoformat()},
    )


def make_context(
    observations: list[AgentObservation] | None = None,
    objective: str = "Plan assessment.",
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=FakeSandbox(),
        tool_registry=ToolRegistry([]),
        objective=objective,
        phase=AssessmentPhase.RECON,
        observations=observations or [],
    )


class TestPlannerModels:
    """Validate planner data models."""

    def test_phase_objective_validates_agent_name(self) -> None:
        """Empty agent name should raise."""

        with pytest.raises(ValueError, match="PhaseObjective.agent_name cannot be empty"):
            PhaseObjective(agent_name="", phase="recon", objective="Do recon.")

    def test_phase_objective_to_dict(self) -> None:
        """Phase objective should serialize."""

        phase = PhaseObjective(
            agent_name="recon_agent",
            phase="recon",
            objective="Discover targets.",
            depends_on=["planner_agent"],
            metadata={"order": 1},
        )

        assert phase.to_dict() == {
            "agent_name": "recon_agent",
            "phase": "recon",
            "objective": "Discover targets.",
            "depends_on": ["planner_agent"],
            "metadata": {"order": 1},
        }

    def test_mission_plan_requires_phases(self) -> None:
        """Mission plan should require phases."""

        with pytest.raises(ValueError, match="MissionPlan.phases cannot be empty"):
            MissionPlan(objective="Plan assessment.", phases=[])

    def test_mission_plan_to_dict(self) -> None:
        """Mission plan should serialize."""

        plan = MissionPlan(
            objective="Plan assessment.",
            phases=[PhaseObjective(agent_name="recon_agent", phase="recon", objective="Discover targets.")],
            metadata={"observation_count": 0},
        )

        data = plan.to_dict()

        assert data["objective"] == "Plan assessment."
        assert data["phases"][0]["agent_name"] == "recon_agent"
        assert data["metadata"]["observation_count"] == 0


class TestPlannerAgent:
    """Validate PlannerAgent."""

    def test_default_config(self) -> None:
        """Planner agent should use expected defaults."""

        agent = PlannerAgent()

        assert agent.config.name == "planner_agent"
        assert agent.config.phase == AssessmentPhase.RECON
        assert agent.config.prompt_path == "prompts/planner_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "planner"

    def test_build_mission_plan_default_phases(self) -> None:
        """Default mission plan should include main agents."""

        agent = PlannerAgent()
        plan = agent.build_mission_plan(objective="Assess example.com.")

        agents = [phase.agent_name for phase in plan.phases]

        assert agents == [
            "recon_agent",
            "network_agent",
            "web_agent",
            "exploit_agent",
            "post_exploit_agent",
            "lateral_movement_agent",
            "reporter_agent",
        ]
        assert plan.metadata["observation_count"] == 0

    def test_build_mission_plan_includes_reverse_engineer(self) -> None:
        """Binary objective should insert reverse engineering phase."""

        agent = PlannerAgent()
        plan = agent.build_mission_plan(objective="Reverse engineer uploaded ELF binary.")

        agents = [phase.agent_name for phase in plan.phases]

        assert "reverse_engineer_agent" in agents
        assert agents.index("reverse_engineer_agent") == 1

    def test_no_observations_selects_recon(self) -> None:
        """No observations should select recon."""

        agent = PlannerAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "recon_agent"
        assert decision.metadata["selected_agent"] == "recon_agent"

    def test_web_observation_selects_web(self) -> None:
        """Web observations should select web agent."""

        agent = PlannerAgent()
        observations = [AgentObservation(summary="HTTPS service running nginx.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.handoff_agent == "web_agent"

    def test_network_observation_selects_network(self) -> None:
        """Network observations should select network agent."""

        agent = PlannerAgent()
        observations = [AgentObservation(summary="SMB port 445 is open.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.handoff_agent == "network_agent"

    def test_exploit_observation_selects_exploit(self) -> None:
        """CVE observations should select exploit agent."""

        agent = PlannerAgent()
        observations = [AgentObservation(summary="CVE-2024-0001 appears applicable.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.handoff_agent == "exploit_agent"

    def test_session_observation_selects_post_exploit(self) -> None:
        """Session observations should select post exploit agent."""

        agent = PlannerAgent()
        observations = [AgentObservation(summary="Meterpreter session established.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.handoff_agent == "post_exploit_agent"

    def test_report_objective_selects_reporter(self) -> None:
        """Report objective should select reporter."""

        agent = PlannerAgent()

        decision = agent.decide(make_context(objective="Write final report."))

        assert decision.handoff_agent == "reporter_agent"

    def test_run_returns_handoff(self) -> None:
        """Run should return handoff status."""

        agent = PlannerAgent()

        result = agent.run(make_context())

        assert result.status == AgentRunStatus.HANDOFF
        assert result.decision.handoff_agent == "recon_agent"
        assert result.observations[0].metadata["handoff_agent"] == "recon_agent"
