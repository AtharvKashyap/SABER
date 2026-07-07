"""Tests for LateralMovementAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.lateral_movement_agent import LateralMovementAgent
from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.capability import RequestedActionCategory
from saber.tools.registry import ToolRegistry, ToolRegistryEntry


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
        session_id="lateral_session_1",
        mission_name="Lateral Movement Agent Test Mission",
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


def make_registry() -> ToolRegistry:
    """Create lateral registry."""

    return ToolRegistry(
        [
            ToolRegistryEntry(
                name="lateral_movement_planner",
                import_path="saber.tools.lateral_movement.plan",
                class_name="LateralMovementPlannerWrapper",
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                phase=AssessmentPhase.LATERAL_MOVEMENT,
                aliases=("plan",),
            ),
            ToolRegistryEntry(
                name="path_validation",
                import_path="saber.tools.lateral_movement.path_validation",
                class_name="PathValidationWrapper",
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                phase=AssessmentPhase.LATERAL_MOVEMENT,
            ),
            ToolRegistryEntry(
                name="session_checks",
                import_path="saber.tools.lateral_movement.session_checks",
                class_name="SessionChecksWrapper",
                category=RequestedActionCategory.LATERAL_MOVEMENT,
                phase=AssessmentPhase.LATERAL_MOVEMENT,
            ),
            ToolRegistryEntry(
                name="custom_cli",
                import_path="saber.tools.custom_cli",
                class_name="CustomCliWrapper",
                category=RequestedActionCategory.UNKNOWN,
                phase=AssessmentPhase.RECON,
            ),
        ]
    )


def make_context(
    observations: list[AgentObservation] | None = None,
    sandbox: FakeSandbox | None = None,
) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=sandbox or FakeSandbox(),
        tool_registry=make_registry(),
        objective="Plan lateral movement safely.",
        phase=AssessmentPhase.LATERAL_MOVEMENT,
        observations=observations or [],
    )


class TestLateralMovementAgent:
    """Validate LateralMovementAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = LateralMovementAgent()

        assert agent.config.name == "lateral_movement_agent"
        assert agent.config.phase == AssessmentPhase.LATERAL_MOVEMENT
        assert agent.config.prompt_path == "prompts/lateral_movement_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "lateral_movement"

    def test_no_observations_stops(self) -> None:
        """No observations should stop."""

        agent = LateralMovementAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "missing_observations"

    def test_active_session_summarizes_sessions(self) -> None:
        """Session evidence should request session summary."""

        agent = LateralMovementAgent()
        observations = [AgentObservation(summary="Foothold session established on hostA.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "session_checks"
        assert decision.tool_call.action == "summarize_sessions"
        assert decision.metadata["workflow_step"] == "session_summary"

    def test_candidate_path_runs_dry_validation(self) -> None:
        """Candidate path should dry-run validate."""

        agent = LateralMovementAgent()
        observations = [AgentObservation(summary="Candidate path from hostA to hostB is reachable from current session.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "path_validation"
        assert decision.tool_call.action == "dry_run_path"
        assert decision.metadata["workflow_step"] == "path_dry_run"

    def test_ad_graph_data_plans_paths(self) -> None:
        """AD graph data should request path planning."""

        agent = LateralMovementAgent()
        observations = [AgentObservation(summary="BloodHound found group membership path toward Domain Admin.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "lateral_movement_planner"
        assert decision.tool_call.action == "plan_paths"
        assert decision.metadata["workflow_step"] == "path_planning"

    def test_no_lateral_evidence_stops(self) -> None:
        """Irrelevant observations should stop."""

        agent = LateralMovementAgent()
        observations = [AgentObservation(summary="No hosts responded to ping.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "no_lateral_evidence"

    def test_run_stop_result(self) -> None:
        """Run should return stopped status when no observations."""

        agent = LateralMovementAgent()

        result = agent.run(make_context())

        assert result.status == AgentRunStatus.STOPPED
        assert result.decision.metadata["reason"] == "missing_observations"

    def test_movement_approval_decision(self) -> None:
        """Movement helper should require approval."""

        agent = LateralMovementAgent()

        decision = agent.build_movement_approval_decision(
            path_id="path-001",
            reason="Validate movement path before any execution.",
            metadata={"ticket": "LAT-1"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "path_validation"
        assert decision.tool_call.action == "validate_path"
        assert decision.tool_call.args["path_id"] == "path-001"
        assert decision.metadata["approval_type"] == "lateral_movement"
        assert decision.metadata["ticket"] == "LAT-1"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI helper should require approval."""

        agent = LateralMovementAgent()

        decision = agent.build_custom_cli_decision(
            command="nxc smb 10.0.0.5 --shares",
            reason="Need a one-off movement validation command.",
            expected_output="Share list",
            risk_level="high",
            metadata={"ticket": "LAT-CLI"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.args["risk_level"] == "high"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "LAT-CLI"

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = LateralMovementAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=make_registry(),
            objective="Wrong phase.",
            phase=AssessmentPhase.RECON,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)
