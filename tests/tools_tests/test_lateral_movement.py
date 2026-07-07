"""Tests for lateral movement planning and validation wrappers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.base_wrapper import ToolCommand, ToolWrapperConfig
from saber.tools.capability import RequestedActionCategory
from saber.tools.lateral_movement import (
    LateralMovementPlannerWrapper,
    PathValidationWrapper,
    SessionChecksWrapper,
)


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

    return Target(type=TargetType.HOST, value="dc01.corp.example.com")


def make_session() -> MissionSession:
    """Create reusable session."""

    return MissionSession(
        session_id="session_lateral_1",
        mission_name="Lateral Movement Wrapper Test Mission",
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


class TestLateralMovementExports:
    """Validate lateral movement exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export all lateral movement wrappers."""

        assert LateralMovementPlannerWrapper is not None
        assert SessionChecksWrapper is not None
        assert PathValidationWrapper is not None


class TestLateralMovementPlannerWrapper:
    """Validate planner wrapper."""

    def test_default_config(self) -> None:
        """Planner should use lateral movement defaults."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "lateral_movement_planner"
        assert wrapper.config.image == "saber/lateral-movement:latest"
        assert wrapper.config.phase == AssessmentPhase.LATERAL_MOVEMENT
        assert wrapper.config.category == RequestedActionCategory.LATERAL_MOVEMENT
        assert wrapper.config.requested_by == "LateralMovementPlannerWrapper"

    def test_plan_paths_command(self) -> None:
        """Plan paths command should include source, target, max depth, and graph."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="plan_paths",
            source="web01.corp.example.com",
            graph_path="output/graph.json",
            max_depth=3,
        )

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.plan",
            "plan-paths",
            "--source",
            "web01.corp.example.com",
            "--target",
            "dc01.corp.example.com",
            "--max-depth",
            "3",
            "--graph",
            "output/graph.json",
        ]
        assert command.action == "plan_paths"
        assert command.requires_explicit_authorization is False
        assert command.metadata["source"] == "web01.corp.example.com"
        assert command.metadata["target"] == "dc01.corp.example.com"
        assert command.metadata["max_depth"] == 3

    def test_rank_paths_command(self) -> None:
        """Rank paths command should include input file and criteria."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())
        command = wrapper.build_command(
            action="rank_paths",
            candidate_paths_file="output/paths.json",
            criteria="fewest_steps",
        )

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.plan",
            "rank-paths",
            "--input",
            "output/paths.json",
            "--criteria",
            "fewest_steps",
        ]
        assert command.metadata["candidate_paths_file"] == "output/paths.json"
        assert command.metadata["criteria"] == "fewest_steps"

    def test_export_plan_command(self) -> None:
        """Export plan should validate format."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())
        command = wrapper.build_command(action="export_plan", plan_id="plan-1", output_format="md")

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.plan",
            "export-plan",
            "--plan-id",
            "plan-1",
            "--format",
            "md",
        ]

    def test_plan_paths_delegates_to_sandbox(self) -> None:
        """Public plan method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = LateralMovementPlannerWrapper(sandbox)

        result = wrapper.plan_paths(
            target=make_target(),
            session=make_session(),
            source="web01.corp.example.com",
            max_depth=2,
        )

        assert result.outcome == SandboxOutcome.EXECUTED
        assert len(sandbox.requests) == 1
        request = sandbox.requests[0]
        assert request.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.plan",
            "plan-paths",
            "--source",
            "web01.corp.example.com",
            "--target",
            "dc01.corp.example.com",
            "--max-depth",
            "2",
        ]
        assert request.tool_request.tool_name == "lateral_movement_planner"
        assert request.tool_request.action == "plan_paths"
        assert request.tool_request.category == RequestedActionCategory.LATERAL_MOVEMENT

    def test_rank_paths_delegates_to_sandbox(self) -> None:
        """Public rank method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = LateralMovementPlannerWrapper(sandbox)

        wrapper.rank_paths(
            target=make_target(),
            session=make_session(),
            candidate_paths_file="output/paths.json",
        )

        assert sandbox.requests[0].tool_request.action == "rank_paths"
        assert sandbox.requests[0].command[-4:] == [
            "--input",
            "output/paths.json",
            "--criteria",
            "lowest_risk",
        ]

    def test_export_plan_delegates_to_sandbox(self) -> None:
        """Public export method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = LateralMovementPlannerWrapper(sandbox)

        wrapper.export_plan(target=make_target(), session=make_session(), plan_id="plan-1")

        assert sandbox.requests[0].tool_request.action == "export_plan"
        assert sandbox.requests[0].command[-4:] == ["--plan-id", "plan-1", "--format", "json"]

    def test_bad_output_format_raises(self) -> None:
        """Unsupported output format should raise."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="output_format must be one of"):
            wrapper.build_command(action="export_plan", plan_id="plan-1", output_format="pdf")

    def test_missing_source_raises(self) -> None:
        """Missing source should raise."""

        wrapper = LateralMovementPlannerWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="source is required"):
            wrapper.build_command(target=make_target(), action="plan_paths", source=" ")


class TestSessionChecksWrapper:
    """Validate session checks wrapper."""

    def test_default_config(self) -> None:
        """Session checks should use lateral movement defaults."""

        wrapper = SessionChecksWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "session_checks"
        assert wrapper.config.image == "saber/lateral-movement:latest"
        assert wrapper.config.phase == AssessmentPhase.LATERAL_MOVEMENT
        assert wrapper.config.category == RequestedActionCategory.LATERAL_MOVEMENT

    def test_validate_session_command(self) -> None:
        """Validate session command should include target/user/protocol when provided."""

        wrapper = SessionChecksWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="validate_session",
            session_id="sess-1",
            expected_user="CORP\\alice",
            protocol="smb",
        )

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.session_checks",
            "validate-session",
            "--session-id",
            "sess-1",
            "--target",
            "dc01.corp.example.com",
            "--expected-user",
            "CORP\\alice",
            "--protocol",
            "smb",
        ]
        assert command.metadata["session_id"] == "sess-1"

    def test_summarize_sessions_command(self) -> None:
        """Summarize sessions command should include input file."""

        wrapper = SessionChecksWrapper(FakeSandbox())
        command = wrapper.build_command(action="summarize_sessions", sessions_file="output/sessions.json")

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.session_checks",
            "summarize-sessions",
            "--input",
            "output/sessions.json",
        ]

    def test_authenticated_reachability_requires_authorization(self) -> None:
        """Authenticated reachability should be marked explicit authorization."""

        wrapper = SessionChecksWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="authenticated_reachability",
            source="web01.corp.example.com",
            protocol="smb",
            credential_ref="cred-1",
        )

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.session_checks",
            "authenticated-reachability",
            "--source",
            "web01.corp.example.com",
            "--target",
            "dc01.corp.example.com",
            "--protocol",
            "smb",
            "--credential-ref",
            "cred-1",
        ]
        assert command.requires_explicit_authorization is True

    def test_validate_session_delegates_to_sandbox(self) -> None:
        """Public validate method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SessionChecksWrapper(sandbox)

        wrapper.validate_session(
            target=make_target(),
            session=make_session(),
            session_id="sess-1",
            expected_user="alice",
        )

        assert sandbox.requests[0].tool_request.action == "validate_session"
        assert "--session-id" in sandbox.requests[0].command

    def test_summarize_sessions_delegates_to_sandbox(self) -> None:
        """Public summarize method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SessionChecksWrapper(sandbox)

        wrapper.summarize_sessions(
            target=make_target(),
            session=make_session(),
            sessions_file="output/sessions.json",
        )

        assert sandbox.requests[0].tool_request.action == "summarize_sessions"
        assert sandbox.requests[0].command[-2:] == ["--input", "output/sessions.json"]

    def test_authenticated_reachability_delegates_to_sandbox(self) -> None:
        """Public reachability method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = SessionChecksWrapper(sandbox)

        wrapper.check_authenticated_reachability_requires_authorization(
            target=make_target(),
            session=make_session(),
            source="web01.corp.example.com",
            protocol="smb",
            credential_ref="cred-1",
        )

        assert sandbox.requests[0].tool_request.requires_explicit_authorization is True
        assert sandbox.requests[0].tool_request.action == "authenticated_reachability"

    def test_unsupported_action_raises(self) -> None:
        """Unsupported session-check action should raise."""

        wrapper = SessionChecksWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported session-check action"):
            wrapper.build_command(action="nope")


class TestPathValidationWrapper:
    """Validate path validation wrapper."""

    def test_default_config(self) -> None:
        """Path validation should use lateral movement defaults."""

        wrapper = PathValidationWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "path_validation"
        assert wrapper.config.image == "saber/lateral-movement:latest"
        assert wrapper.config.phase == AssessmentPhase.LATERAL_MOVEMENT
        assert wrapper.config.category == RequestedActionCategory.LATERAL_MOVEMENT

    def test_validate_step_command(self) -> None:
        """Validate step command should include source, target, technique, and credential ref."""

        wrapper = PathValidationWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="validate_step",
            source="web01.corp.example.com",
            technique="smb_admin_share",
            credential_ref="cred-1",
        )

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.path_validation",
            "validate-step",
            "--source",
            "web01.corp.example.com",
            "--target",
            "dc01.corp.example.com",
            "--technique",
            "smb_admin_share",
            "--credential-ref",
            "cred-1",
        ]
        assert command.requires_explicit_authorization is False

    def test_validate_path_command(self) -> None:
        """Validate path command should include input file."""

        wrapper = PathValidationWrapper(FakeSandbox())
        command = wrapper.build_command(action="validate_path", path_file="output/path.json")

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.path_validation",
            "validate-path",
            "--input",
            "output/path.json",
        ]

    def test_dry_run_path_requires_authorization(self) -> None:
        """Dry run path should be marked explicit authorization."""

        wrapper = PathValidationWrapper(FakeSandbox())
        command = wrapper.build_command(action="dry_run_path", path_file="output/path.json")

        assert command.command == [
            "python",
            "-m",
            "saber.tools.lateral_movement.path_validation",
            "dry-run-path",
            "--input",
            "output/path.json",
        ]
        assert command.requires_explicit_authorization is True

    def test_validate_step_delegates_to_sandbox(self) -> None:
        """Public validate step should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = PathValidationWrapper(sandbox)

        wrapper.validate_step(
            target=make_target(),
            session=make_session(),
            source="web01.corp.example.com",
            technique="smb_admin_share",
        )

        assert sandbox.requests[0].tool_request.action == "validate_step"
        assert sandbox.requests[0].command[2] == "saber.tools.lateral_movement.path_validation"

    def test_validate_path_delegates_to_sandbox(self) -> None:
        """Public validate path should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = PathValidationWrapper(sandbox)

        wrapper.validate_path(target=make_target(), session=make_session(), path_file="output/path.json")

        assert sandbox.requests[0].tool_request.action == "validate_path"
        assert sandbox.requests[0].command[-2:] == ["--input", "output/path.json"]

    def test_dry_run_delegates_to_sandbox(self) -> None:
        """Public dry-run path should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = PathValidationWrapper(sandbox)

        wrapper.dry_run_path_requires_authorization(
            target=make_target(),
            session=make_session(),
            path_file="output/path.json",
        )

        assert sandbox.requests[0].tool_request.action == "dry_run_path"
        assert sandbox.requests[0].tool_request.requires_explicit_authorization is True

    def test_missing_path_file_raises(self) -> None:
        """Missing path file should raise."""

        wrapper = PathValidationWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="path_file is required"):
            wrapper.build_command(action="validate_path", path_file="")


class TestCustomConfigs:
    """Validate custom ToolWrapperConfig support."""

    def test_custom_planner_config(self) -> None:
        """Planner should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_lm_planner",
            image="custom/lm:dev",
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            requested_by="CustomPlanner",
        )
        wrapper = LateralMovementPlannerWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_lm_planner"
        assert wrapper.config.image == "custom/lm:dev"

    def test_custom_session_checks_config(self) -> None:
        """Session checks should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_session_checks",
            image="custom/lm:dev",
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            requested_by="CustomSessionChecks",
        )
        wrapper = SessionChecksWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_session_checks"

    def test_custom_path_validation_config(self) -> None:
        """Path validation should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_path_validation",
            image="custom/lm:dev",
            phase=AssessmentPhase.LATERAL_MOVEMENT,
            category=RequestedActionCategory.LATERAL_MOVEMENT,
            requested_by="CustomPathValidation",
        )
        wrapper = PathValidationWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_path_validation"


class TestToolCommandValidation:
    """Validate ToolCommand remains available for lateral movement wrappers."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
