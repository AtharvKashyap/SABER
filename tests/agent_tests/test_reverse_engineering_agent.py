"""Tests for ReverseEngineeringAgent."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.agents.base_agent import AgentActionType, AgentContext, AgentObservation, AgentRunStatus
from saber.agents.reverse_engineering_agent import ReverseEngineerAgent
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
        session_id="reverse_engineer_session_1",
        mission_name="Reverse Engineer Agent Test Mission",
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
    objective: str = "Analyze binary.",
    metadata: dict | None = None,
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
        metadata=metadata or {"binary_path": "samples/app"},
    )


class TestReverseEngineerAgent:
    """Validate ReverseEngineerAgent."""

    def test_default_config(self) -> None:
        """Agent should use expected defaults."""

        agent = ReverseEngineerAgent()

        assert agent.config.name == "reverse_engineer_agent"
        assert agent.config.phase == AssessmentPhase.RECON
        assert agent.config.prompt_path == "prompts/reverse_engineer_agent_prompt.txt"
        assert agent.config.default_metadata["agent_type"] == "reverse_engineering"

    def test_no_file_identification_selects_file(self) -> None:
        """Initial step should identify file type."""

        agent = ReverseEngineerAgent()

        decision = agent.decide(make_context())

        assert decision.action_type == AgentActionType.TOOL
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "file"
        assert decision.tool_call.action == "identify"
        assert decision.tool_call.args["file_path"] == "samples/app"
        assert decision.metadata["workflow_step"] == "file_identification"

    def test_file_identified_selects_strings(self) -> None:
        """After file identification, extract strings."""

        agent = ReverseEngineerAgent()
        observations = [AgentObservation(summary="ELF 64-bit executable.", tool_name="file", action="identify")]

        decision = agent.decide(make_context(observations=observations))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "strings"
        assert decision.tool_call.action == "extract"
        assert decision.tool_call.args["file_path"] == "samples/app"
        assert decision.metadata["workflow_step"] == "strings_extraction"

    def test_executable_with_strings_selects_checksec(self) -> None:
        """Executable with strings should run checksec."""

        agent = ReverseEngineerAgent()
        observations = [
            AgentObservation(summary="ELF 64-bit executable.", tool_name="file", action="identify"),
            AgentObservation(summary="Printable strings extracted.", tool_name="strings", action="extract"),
        ]

        decision = agent.decide(make_context(observations=observations))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "checksec"
        assert decision.tool_call.action == "binary"
        assert decision.tool_call.args["output_format"] == "json"
        assert decision.metadata["workflow_step"] == "binary_hardening"

    def test_function_objective_selects_radare2(self) -> None:
        """Function analysis objective should select radare2 after basics."""

        agent = ReverseEngineerAgent()
        observations = [
            AgentObservation(summary="ELF 64-bit executable.", tool_name="file", action="identify"),
            AgentObservation(summary="Printable strings extracted.", tool_name="strings", action="extract"),
            AgentObservation(summary="checksec found NX enabled and PIE disabled.", tool_name="checksec", action="binary"),
        ]

        decision = agent.decide(make_context(observations=observations, objective="List functions and symbols."))

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "radare2"
        assert decision.tool_call.action == "functions"
        assert decision.tool_call.args["binary_path"] == "samples/app"
        assert decision.metadata["workflow_step"] == "function_listing"

    def test_deep_analysis_selects_ghidra(self) -> None:
        """Deep analysis objective should select Ghidra after basics."""

        agent = ReverseEngineerAgent()
        observations = [
            AgentObservation(summary="ELF 64-bit executable.", tool_name="file", action="identify"),
            AgentObservation(summary="Printable strings extracted.", tool_name="strings", action="extract"),
            AgentObservation(summary="checksec found NX enabled and PIE disabled.", tool_name="checksec", action="binary"),
        ]

        decision = agent.decide(
            make_context(
                observations=observations,
                objective="Run Ghidra deep analysis.",
                metadata={
                    "binary_path": "samples/app",
                    "project_dir": "ghidra_projects",
                    "project_name": "app_project",
                },
            )
        )

        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "ghidra_headless"
        assert decision.tool_call.action == "analyze_binary"
        assert decision.tool_call.args["project_dir"] == "ghidra_projects"
        assert decision.tool_call.args["project_name"] == "app_project"
        assert decision.metadata["workflow_step"] == "ghidra_analysis"

    def test_complete_context_stops(self) -> None:
        """Complete analysis should stop."""

        agent = ReverseEngineerAgent()

        decision = agent.decide(make_context(objective="Reverse engineering complete."))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "reverse_engineering_complete"

    def test_no_additional_action_stops(self) -> None:
        """If basics are done and no deeper objective, stop."""

        agent = ReverseEngineerAgent()
        observations = [
            AgentObservation(summary="ELF 64-bit executable.", tool_name="file", action="identify"),
            AgentObservation(summary="Printable strings extracted.", tool_name="strings", action="extract"),
            AgentObservation(summary="checksec found NX enabled and PIE disabled.", tool_name="checksec", action="binary"),
        ]

        decision = agent.decide(make_context(observations=observations))

        assert decision.action_type == AgentActionType.STOP
        assert decision.metadata["reason"] == "no_reverse_engineering_action"

    def test_custom_cli_decision_requires_approval(self) -> None:
        """Custom CLI helper should require approval."""

        agent = ReverseEngineerAgent()

        decision = agent.build_custom_cli_decision(
            command="objdump -d samples/app | head",
            reason="Need one-off disassembly preview.",
            expected_output="Disassembly preview",
            risk_level="low",
            metadata={"ticket": "RE-CLI"},
        )

        assert decision.action_type == AgentActionType.ASK_APPROVAL
        assert decision.requires_approval is True
        assert decision.tool_call is not None
        assert decision.tool_call.tool_name == "custom_cli"
        assert decision.tool_call.args["risk_level"] == "low"
        assert decision.metadata["custom_cli"] is True
        assert decision.metadata["ticket"] == "RE-CLI"

    def test_context_phase_mismatch_raises(self) -> None:
        """Wrong context phase should raise."""

        agent = ReverseEngineerAgent()
        context = AgentContext(
            session=make_session(),
            target=make_target(),
            sandbox=FakeSandbox(),
            tool_registry=ToolRegistry([]),
            objective="Wrong phase.",
            phase=AssessmentPhase.EXPLOITATION,
        )

        with pytest.raises(ValueError, match="does not match agent phase"):
            agent.run(context)

    def test_run_stop_result(self) -> None:
        """Run should return stopped when complete."""

        agent = ReverseEngineerAgent()

        result = agent.run(make_context(objective="Static analysis complete."))

        assert result.status == AgentRunStatus.STOPPED
        assert result.decision.metadata["reason"] == "reverse_engineering_complete"
