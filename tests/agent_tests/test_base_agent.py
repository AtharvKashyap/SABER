"""Tests for SABER base agent abstractions."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from saber.agents.base_agent import (
    AgentActionType,
    AgentConfig,
    AgentContext,
    AgentDecision,
    AgentObservation,
    AgentRunStatus,
    AgentToolCall,
    BaseAgent,
)

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.custom_cli import CustomCliWrapper
from saber.tools.registry import ToolRegistry, ToolRegistryEntry
from saber.tools.capability import RequestedActionCategory

@dataclass

class FakeSandbox:

    """Fake sandbox that records execution requests."""
    
    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request and return configured result."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)

class StaticDecisionAgent(BaseAgent):

    """Agent that always returns a predefined decision."""
    def __init__(self, config: AgentConfig, decision: AgentDecision) -> None:
        """Initialize static decision agent."""

        super().__init__(config=config)
        self._decision = decision

    def decide(self, context: AgentContext) -> AgentDecision:
        """Return configured decision."""

        return self._decision

def make_session() -> MissionSession:
    """Create reusable session."""

    return MissionSession(

        session_id="agent_session_1",
        mission_name="Base Agent Test Mission",
        status=SessionStatus.CREATED,
    )

def make_target() -> Target:
    """Create reusable target."""

    return Target(type=TargetType.HOST, value="example.com")

def make_sandbox_result(session: MissionSession | None = None) -> SandboxExecutionResult:
    """Create reusable sandbox result."""

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

    """Create registry with custom_cli only."""

    return ToolRegistry(
        [
            ToolRegistryEntry(
                name="custom_cli",
                import_path="saber.tools.custom_cli",
                class_name="CustomCliWrapper",
                category=RequestedActionCategory.UNKNOWN,
                phase=AssessmentPhase.RECON,
                description="Explicitly authorized custom CLI execution.",
                aliases=("cli",),
            )
        ]
    )

def make_context(
    sandbox: FakeSandbox | None = None,
    phase: AssessmentPhase | None = None,
) -> AgentContext:
    """Create reusable agent context."""

    return AgentContext(
        session=make_session(),
        target=make_target(),
        sandbox=sandbox or FakeSandbox(),
        tool_registry=make_registry(),
        objective="Run a test objective.",
        phase=phase,
    )

def make_config() -> AgentConfig:
    """Create reusable agent config."""

    return AgentConfig(
        name="test_agent",
        phase=AssessmentPhase.RECON,
        description="Test agent.",
        default_metadata={"suite": "agent_tests"},
    )

class TestAgentDataModels:
    """Validate base agent dataclasses."""

    def test_agent_config_validates_name(self) -> None:
        """Agent config should reject empty names."""

        with pytest.raises(ValueError, match="AgentConfig.name cannot be empty"):
            AgentConfig(name="", phase=AssessmentPhase.RECON)

    def test_agent_tool_call_validates_tool_name(self) -> None:
        """Tool call should reject empty tool name."""

        with pytest.raises(ValueError, match="AgentToolCall.tool_name cannot be empty"):
            AgentToolCall(tool_name="", action="scan")

    def test_agent_tool_call_validates_action(self) -> None:
        """Tool call should reject empty action."""

        with pytest.raises(ValueError, match="AgentToolCall.action cannot be empty"):
            AgentToolCall(tool_name="custom_cli", action="")

    def test_tool_decision_requires_tool_call(self) -> None:
        """TOOL decisions should require tool_call."""
        
        with pytest.raises(ValueError, match="TOOL decisions require tool_call"):
            AgentDecision(action_type=AgentActionType.TOOL, objective="Run tool.")

    def test_handoff_decision_requires_handoff_agent(self) -> None:
        """HANDOFF decisions should require handoff_agent."""

        with pytest.raises(ValueError, match="HANDOFF decisions require handoff_agent"):
            AgentDecision(action_type=AgentActionType.HANDOFF, objective="Hand off.")

    def test_decision_validates_objective(self) -> None:
        """Decision should reject empty objective."""

        with pytest.raises(ValueError, match="AgentDecision.objective cannot be empty"):
            AgentDecision(action_type=AgentActionType.STOP, objective="")

    def test_observation_validates_summary(self) -> None:
        """Observation should reject empty summary."""

        with pytest.raises(ValueError, match="AgentObservation.summary cannot be empty"):
            AgentObservation(summary="")

    def test_agent_run_result_to_dict(self) -> None:
        """Run result should serialize to dict."""

        decision = AgentDecision(
            action_type=AgentActionType.STOP,
            objective="Stop.",
            message="Done.",
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context())
        data = result.to_dict()
        assert data["agent_name"] == "test_agent"
        assert data["status"] == "stopped"
        assert data["decision"]["action_type"] == "stop"
        assert data["decision"]["objective"] == "Stop."
        assert data["metadata"]["suite"] == "agent_tests"

class TestBaseAgentRun:
    """Validate BaseAgent run behavior."""

    def test_stop_decision_returns_stopped(self) -> None:
        """STOP decision should not execute tools."""

        sandbox = FakeSandbox()
        decision = AgentDecision(
            action_type=AgentActionType.STOP,
            objective="No more work.",
            message="Finished.",
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(sandbox=sandbox))
        assert result.status == AgentRunStatus.STOPPED
        assert result.decision.message == "Finished."
        assert sandbox.requests == []

    def test_handoff_decision_returns_handoff(self) -> None:
        """HANDOFF decision should return handoff result."""

        sandbox = FakeSandbox()
        decision = AgentDecision(
            action_type=AgentActionType.HANDOFF,
            objective="Move to web testing.",
            handoff_agent="web_agent",
            message="Web targets discovered.",
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(sandbox=sandbox))
        assert result.status == AgentRunStatus.HANDOFF
        assert result.observations[0].metadata["handoff_agent"] == "web_agent"
        assert sandbox.requests == []

    def test_approval_decision_returns_needs_approval(self) -> None:
        """ASK_APPROVAL decision should not execute tools."""

        sandbox = FakeSandbox()
        decision = AgentDecision(
            action_type=AgentActionType.ASK_APPROVAL,
            objective="Need approval.",
            message="Approve active scan.",
            requires_approval=True,
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(sandbox=sandbox))
        assert result.status == AgentRunStatus.NEEDS_APPROVAL
        assert result.decision.requires_approval is True
        assert sandbox.requests == []

    def test_tool_decision_executes_through_registry_and_sandbox(self) -> None:
        """TOOL decision should instantiate wrapper and execute through Sandbox."""

        sandbox = FakeSandbox()
        decision = AgentDecision(
            action_type=AgentActionType.TOOL,
            objective="Run custom CLI command.",
            tool_call=AgentToolCall(
                tool_name="custom_cli",
                action="run_command",
                args={
                    "command": "echo hello",
                    "reason": "Test custom command execution.",
                    "risk_level": "low",
                },
                reason="Need a custom one-off check.",
                metadata={"source": "unit_test"},
            ),
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(sandbox=sandbox))

        assert result.status == AgentRunStatus.COMPLETED
        assert result.result is not None
        assert result.observations[0].tool_name == "custom_cli"
        assert result.observations[0].action == "run_command"
        assert result.observations[0].success is True
        assert len(sandbox.requests) == 1

        request = sandbox.requests[0]

        assert request.command == ["bash", "-lc", "echo hello"]
        assert request.tool_request.tool_name == "custom_cli"
        assert request.tool_request.action == "run_command"
        assert request.tool_request.requires_explicit_authorization is True
        assert request.tool_request.metadata["agent_name"] == "test_agent"
        assert request.tool_request.metadata["agent_phase"] == "recon"
        assert request.tool_request.metadata["agent_reason"] == "Need a custom one-off check."
        assert request.tool_request.metadata["source"] == "unit_test"

    def test_execute_tool_can_resolve_alias(self) -> None:
        """Tool registry alias should work."""

        sandbox = FakeSandbox()
        decision = AgentDecision(
            action_type=AgentActionType.TOOL,
            objective="Run aliased custom CLI command.",
            tool_call=AgentToolCall(
                tool_name="cli",
                action="run_command",
                args={
                    "command": "echo alias",
                    "reason": "Test alias.",
                    "risk_level": "low",
                },
            ),
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(sandbox=sandbox))
        assert result.status == AgentRunStatus.COMPLETED
        assert sandbox.requests[0].command == ["bash", "-lc", "echo alias"]

    def test_context_phase_mismatch_raises(self) -> None:
        """Agent should reject mismatched context phase."""

        decision = AgentDecision(
            action_type=AgentActionType.STOP,
            objective="Stop.",
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(make_context(phase=AssessmentPhase.EXPLOITATION))

    def test_context_matching_phase_is_allowed(self) -> None:
        """Matching context phase should be accepted."""

        decision = AgentDecision(
            action_type=AgentActionType.STOP,
            objective="Stop.",
        )

        agent = StaticDecisionAgent(config=make_config(), decision=decision)
        result = agent.run(make_context(phase=AssessmentPhase.RECON))
        assert result.status == AgentRunStatus.STOPPED

class TestBaseAgentHelpers:
    """Validate BaseAgent helper methods."""

    def test_load_prompt_returns_empty_when_unconfigured(self) -> None:
        """No prompt path should return empty string."""

        agent = StaticDecisionAgent(
            config=make_config(),
            decision=AgentDecision(action_type=AgentActionType.STOP, objective="Stop."),
        )
        assert agent.load_prompt() == ""

    def test_load_prompt_reads_file(self, tmp_path: Path) -> None:
        """Prompt path should read file text."""

        prompt_path = tmp_path / "prompt.txt"
        prompt_path.write_text("You are a test agent.")
        config = AgentConfig(
            name="prompt_agent",
            phase=AssessmentPhase.RECON,
            prompt_path=str(prompt_path),
        )

        agent = StaticDecisionAgent(
            config=config,
            decision=AgentDecision(action_type=AgentActionType.STOP, objective="Stop."),
        )

        assert agent.load_prompt() == "You are a test agent."

    def test_load_prompt_missing_file_raises(self, tmp_path: Path) -> None:
        """Missing prompt path should raise."""
        
        config = AgentConfig(
            name="prompt_agent",
            phase=AssessmentPhase.RECON,
            prompt_path=str(tmp_path / "missing.txt"),
        )

        agent = StaticDecisionAgent(
            config=config,
            decision=AgentDecision(action_type=AgentActionType.STOP, objective="Stop."),
        )

        with pytest.raises(FileNotFoundError, match="Agent prompt not found"):
            agent.load_prompt()

    def test_require_tool_call_raises_for_missing_tool_call(self) -> None:
        """require_tool_call should reject decisions without tool call."""

        decision = AgentDecision(action_type=AgentActionType.STOP, objective="Stop.")
        with pytest.raises(ValueError, match="does not include a tool call"):
            BaseAgent.require_tool_call(decision)

    def test_to_summary_dict(self) -> None:
        """Agent summary should include config values."""

        agent = StaticDecisionAgent(
            config=make_config(),
            decision=AgentDecision(action_type=AgentActionType.STOP, objective="Stop."),
        )

        data = agent.to_summary_dict()
        
        assert data["name"] == "test_agent"
        assert data["phase"] == "recon"
        assert data["description"] == "Test agent."
        assert data["default_metadata"] == {"suite": "agent_tests"}

class TestBaseAgentImports:
    """Validate dependencies used by base agent tests."""

    def test_custom_cli_wrapper_is_importable(self) -> None:
        """Custom CLI wrapper should remain importable."""

        assert CustomCliWrapper.__name__ == "CustomCliWrapper"