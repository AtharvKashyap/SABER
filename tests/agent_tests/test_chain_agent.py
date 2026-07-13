"""Tests for ChainAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.chain_agent import ChainAgent
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
        session_id="chain_session_1",
        mission_name="Chain Agent Test Mission",
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


def make_context(observations: list[AgentObservation] | None = None) -> AgentContext:
    """Create context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=FakeSandbox(),
        tool_registry=ToolRegistry([]),
        objective="Build next attack chain step.",
        phase=AssessmentPhase.EXPLOITATION,
        observations=observations or [],
    )


class TestChainAgent:
    """Validate ChainAgent."""

    def test_default_config(self) -> None:
        """Chain agent should use expected defaults."""

        agent = ChainAgent()

        assert agent.config.name == "chain_agent"
        assert agent.config.phase == AssessmentPhase.EXPLOITATION
        assert agent.config.prompt_path == "prompts/chain_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "chain"

    def test_no_observations_hands_to_recon(self) -> None:
        """No observations should hand off to recon."""

        agent = ChainAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "recon_agent"
        assert decision.metadata["reason"] == "missing_observations"

    def test_web_surface_hands_to_web(self) -> None:
        """Web observations should hand off to web agent."""

        agent = ChainAgent()
        observations = [AgentObservation(summary="Host exposes HTTP on port 80 with nginx.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "web_agent"
        assert decision.metadata["reason"] == "web_surface_observed"

    def test_possible_vulnerability_hands_to_exploit(self) -> None:
        """Vulnerability observations should hand off to exploit agent."""

        agent = ChainAgent()
        observations = [AgentObservation(summary="Service appears outdated and vulnerable to CVE-2024-0001.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "exploit_agent"
        assert decision.metadata["reason"] == "possible_vulnerability"

    def test_confirmed_foothold_hands_to_post_exploit(self) -> None:
        """Foothold observations should hand off to post-exploit agent."""

        agent = ChainAgent()
        observations = [AgentObservation(summary="Meterpreter session established on host.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.handoff_agent == "post_exploit_agent"
        assert decision.metadata["reason"] == "confirmed_foothold"

    def test_no_actionable_observation_hands_off_to_reporter(self) -> None:
        """Non-actionable observations should stop."""

        agent = ChainAgent()
        observations = [AgentObservation(summary="No exposed services were found.")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.HANDOFF
        assert decision.metadata["reason"] == "ready_for_reporting"

    def test_run_handoff_result(self) -> None:
        """Run should return handoff status."""

        agent = ChainAgent()
        observations = [AgentObservation(summary="Apache web server found on https://example.com.")]

        result = agent.run(make_context(observations=observations))

        assert result.status == AgentRunStatus.HANDOFF
        assert result.decision.handoff_agent == "web_agent"
        assert result.observations[0].metadata["handoff_agent"] == "web_agent"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI chain decision should require approval."""

        agent = ChainAgent()

        decision = agent.build_custom_cli_decision(
            command="curl -I https://example.com",
            reason="Need a one-off chain validation.",
            expected_output="HTTP headers",
            risk_level="low",
            metadata={"ticket": "CHAIN-1"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.action == "run_command"
        assert decision.tool_call.args["command"] == "curl -I https://example.com"
        assert decision.tool_call.args["risk_level"] == "low"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "CHAIN-1"

    def test_context_phase_mismatch_raises(self) -> None:
        """Chain agent should reject wrong phase context."""

        agent = ChainAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=ToolRegistry([]),
            objective="Wrong phase.",
            phase=AssessmentPhase.RECON,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)
