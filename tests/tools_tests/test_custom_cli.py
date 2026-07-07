"""Tests for custom CLI tool wrapper."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.base_wrapper import ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.custom_cli import CustomCliWrapper


@dataclass
class FakeSandbox:
    """Fake sandbox that records requests and returns a configured result."""

    result: SandboxExecutionResult | None = None
    requests: list[SandboxExecutionRequest] = field(default_factory=list)

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record request and return configured result."""

        self.requests.append(request)
        return self.result or make_sandbox_result(session=request.session)


def make_target() -> Target:
    """Create reusable target."""

    return Target(type=TargetType.HOST, value="example.com")


def make_session() -> MissionSession:
    """Create reusable session."""

    return MissionSession(
        session_id="session_custom_cli_1",
        mission_name="Custom CLI Wrapper Test Mission",
        status=SessionStatus.CREATED,
    )


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


class TestCustomCliWrapper:
    """Validate custom CLI wrapper."""

    def test_default_config(self) -> None:
        """Custom CLI should use safe defaults."""

        wrapper = CustomCliWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "custom_cli"
        assert wrapper.config.image == "saber/custom-cli:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.UNKNOWN
        assert wrapper.config.requested_by == "CustomCliWrapper"

    def test_run_command_command(self) -> None:
        """run_command should build bash command and require authorization."""

        wrapper = CustomCliWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="run_command",
            command="curl -I https://example.com",
            reason="Check headers not covered by a predefined wrapper.",
            expected_output="HTTP headers",
            risk_level="low",
        )

        assert command.command == ["bash", "-lc", "curl -I https://example.com"]
        assert command.action == "run_command"
        assert command.evidence_relative_dir == "custom_cli/run_command"
        assert command.requires_explicit_authorization is True
        assert command.metadata["reason"] == "Check headers not covered by a predefined wrapper."
        assert command.metadata["expected_output"] == "HTTP headers"
        assert command.metadata["risk_level"] == "low"
        assert command.metadata["custom_cli"] is True

    def test_run_script_command(self) -> None:
        """run_script should include script path and args."""

        wrapper = CustomCliWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="run_script",
            script_path="scripts/check_headers.sh",
            script_args=["https://example.com", "json"],
            reason="Run a local helper script approved by the operator.",
            risk_level="medium",
        )

        assert command.command == ["bash", "scripts/check_headers.sh", "https://example.com", "json"]
        assert command.action == "run_script"
        assert command.evidence_relative_dir == "custom_cli/run_script"
        assert command.requires_explicit_authorization is True
        assert command.metadata["script_path"] == "scripts/check_headers.sh"
        assert command.metadata["script_args"] == ["https://example.com", "json"]

    def test_run_pipeline_command(self) -> None:
        """run_pipeline should run through bash -lc."""

        wrapper = CustomCliWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="run_pipeline",
            pipeline="printf 'a\\nb\\n' | grep a",
            reason="Run a simple pipeline.",
            risk_level="low",
        )

        assert command.command == ["bash", "-lc", "printf 'a\\nb\\n' | grep a"]
        assert command.action == "run_pipeline"
        assert command.evidence_relative_dir == "custom_cli/run_pipeline"
        assert command.requires_explicit_authorization is True
        assert command.metadata["pipeline"] == "printf 'a\\nb\\n' | grep a"

    def test_run_command_delegates_to_sandbox(self) -> None:
        """run_command method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = CustomCliWrapper(sandbox)

        wrapper.run_command(
            target=make_target(),
            session=make_session(),
            command="curl -I https://example.com",
            reason="Check response headers.",
            risk_level="low",
        )

        assert sandbox.requests[0].command == ["bash", "-lc", "curl -I https://example.com"]
        assert sandbox.requests[0].tool_request.tool_name == "custom_cli"
        assert sandbox.requests[0].tool_request.action == "run_command"
        assert sandbox.requests[0].tool_request.requires_explicit_authorization is True
        assert sandbox.requests[0].tool_request.metadata["custom_cli"] is True

    def test_run_script_delegates_to_sandbox(self) -> None:
        """run_script method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = CustomCliWrapper(sandbox)

        wrapper.run_script(
            target=make_target(),
            session=make_session(),
            script_path="scripts/review.sh",
            script_args=["arg1"],
            reason="Run approved review script.",
        )

        assert sandbox.requests[0].command == ["bash", "scripts/review.sh", "arg1"]
        assert sandbox.requests[0].tool_request.action == "run_script"
        assert sandbox.requests[0].tool_request.requires_explicit_authorization is True

    def test_run_pipeline_delegates_to_sandbox(self) -> None:
        """run_pipeline method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = CustomCliWrapper(sandbox)

        wrapper.run_pipeline(
            target=make_target(),
            session=make_session(),
            pipeline="echo test | wc -c",
            reason="Run approved shell pipeline.",
        )

        assert sandbox.requests[0].command == ["bash", "-lc", "echo test | wc -c"]
        assert sandbox.requests[0].tool_request.action == "run_pipeline"
        assert sandbox.requests[0].tool_request.requires_explicit_authorization is True

    def test_missing_reason_raises(self) -> None:
        """Custom CLI commands must include reason."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="reason is required"):
            wrapper.build_command(
                target=make_target(),
                action="run_command",
                command="id",
                reason="",
            )

    def test_missing_command_raises(self) -> None:
        """run_command must include command."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="command is required"):
            wrapper.build_command(
                target=make_target(),
                action="run_command",
                command="",
                reason="Need a command.",
            )

    def test_missing_script_path_raises(self) -> None:
        """run_script must include script path."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="script_path is required"):
            wrapper.build_command(
                target=make_target(),
                action="run_script",
                script_path="",
                reason="Need a script.",
            )

    def test_missing_pipeline_raises(self) -> None:
        """run_pipeline must include pipeline."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="pipeline is required"):
            wrapper.build_command(
                target=make_target(),
                action="run_pipeline",
                pipeline="",
                reason="Need a pipeline.",
            )

    def test_bad_risk_level_raises(self) -> None:
        """Bad risk level should raise."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="risk_level must be one of"):
            wrapper.build_command(
                target=make_target(),
                action="run_command",
                command="id",
                reason="Test invalid risk.",
                risk_level="critical",
            )

    def test_unsupported_action_raises(self) -> None:
        """Unsupported action should raise."""

        wrapper = CustomCliWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported custom CLI action"):
            wrapper.build_command(
                target=make_target(),
                action="bad",
                reason="Test unsupported action.",
            )

    def test_validate_command_blocks_non_authorized_custom_command(self) -> None:
        """Custom CLI commands must always require explicit authorization."""

        wrapper = CustomCliWrapper(FakeSandbox())
        command = ToolCommand(
            command=["bash", "-lc", "id"],
            action="run_command",
            evidence_title="Bad Custom CLI",
            evidence_relative_dir="custom_cli/bad",
            requires_explicit_authorization=False,
        )

        with pytest.raises(ValueError, match="must require explicit authorization"):
            wrapper.validate_command(command)

    def test_validate_command_blocks_non_bash_command(self) -> None:
        """Custom CLI commands must go through bash."""

        wrapper = CustomCliWrapper(FakeSandbox())
        command = ToolCommand(
            command=["python", "-V"],
            action="run_command",
            evidence_title="Bad Custom CLI",
            evidence_relative_dir="custom_cli/bad",
            requires_explicit_authorization=True,
        )

        with pytest.raises(ValueError, match="must execute through bash"):
            wrapper.validate_command(command)


class TestCustomCliCustomConfig:
    """Validate custom config support."""

    def test_custom_config(self) -> None:
        """Custom CLI should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_cli_dev",
            image="custom/cli:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.UNKNOWN,
            requested_by="CustomCliDev",
        )

        wrapper = CustomCliWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_cli_dev"
        assert wrapper.config.image == "custom/cli:dev"
        assert wrapper.config.requested_by == "CustomCliDev"
