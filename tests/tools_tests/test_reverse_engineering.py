"""Tests for reverse engineering tool wrappers."""

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
from saber.tools.reverse_engineering import (
    ChecksecWrapper,
    FileWrapper,
    GhidraHeadlessWrapper,
    Radare2Wrapper,
    StringsWrapper,
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

    return Target(type=TargetType.HOST, value="example.com")


def make_session() -> MissionSession:
    """Create reusable mission session."""

    return MissionSession(
        session_id="session_reverse_engineering_1",
        mission_name="Reverse Engineering Wrapper Test Mission",
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


class TestReverseEngineeringExports:
    """Validate reverse engineering package exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export reverse engineering wrappers."""

        assert ChecksecWrapper is not None
        assert FileWrapper is not None
        assert GhidraHeadlessWrapper is not None
        assert Radare2Wrapper is not None
        assert StringsWrapper is not None


class TestChecksecWrapper:
    """Validate checksec wrapper."""

    def test_default_config(self) -> None:
        """checksec should use reverse engineering defaults."""

        wrapper = ChecksecWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "checksec"
        assert wrapper.config.image == "saber/checksec:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_binary_command(self) -> None:
        """Binary check should include file and output format."""

        wrapper = ChecksecWrapper(FakeSandbox())
        command = wrapper.build_command(action="binary", binary_path="samples/app", output_format="json")

        assert command.command == ["checksec", "--file", "samples/app", "--output=json"]
        assert command.action == "binary"
        assert command.evidence_relative_dir == "reverse_engineering/checksec/binary"

    def test_directory_command(self) -> None:
        """Directory check should include dir and output format."""

        wrapper = ChecksecWrapper(FakeSandbox())
        command = wrapper.build_command(action="directory", directory_path="samples", output_format="csv")

        assert command.command == ["checksec", "--dir", "samples", "--output=csv"]
        assert command.metadata["directory_path"] == "samples"

    def test_kernel_delegates_to_sandbox(self) -> None:
        """Kernel check should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = ChecksecWrapper(sandbox)

        wrapper.kernel(target=make_target(), session=make_session())

        assert sandbox.requests[0].command == ["checksec", "--kernel"]
        assert sandbox.requests[0].tool_request.action == "kernel"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_bad_output_format_raises(self) -> None:
        """Bad output format should raise."""

        wrapper = ChecksecWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="output_format must be one of"):
            wrapper.build_command(action="binary", binary_path="samples/app", output_format="yaml")


class TestFileWrapper:
    """Validate file wrapper."""

    def test_default_config(self) -> None:
        """file should use reverse engineering defaults."""

        wrapper = FileWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "file"
        assert wrapper.config.image == "saber/file:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_identify_command(self) -> None:
        """Identify should build file command."""

        wrapper = FileWrapper(FakeSandbox())
        command = wrapper.build_command(action="identify", file_path="samples/app", brief=True)

        assert command.command == ["file", "-b", "samples/app"]
        assert command.action == "identify"

    def test_mime_delegates_to_sandbox(self) -> None:
        """MIME method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = FileWrapper(sandbox)

        wrapper.mime(target=make_target(), session=make_session(), file_path="samples/app")

        assert sandbox.requests[0].command == ["file", "--mime", "samples/app"]
        assert sandbox.requests[0].tool_request.action == "mime"

    def test_directory_command_nonrecursive(self) -> None:
        """Directory command should use maxdepth when not recursive."""

        wrapper = FileWrapper(FakeSandbox())
        command = wrapper.build_command(action="directory", directory_path="samples", recursive=False)

        assert command.command == ["find", "samples", "-type", "f", "-maxdepth", "1", "-exec", "file", "{}", ";"]
        assert command.metadata["recursive"] is False

    def test_missing_file_path_raises(self) -> None:
        """Missing file path should raise."""

        wrapper = FileWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="file_path is required"):
            wrapper.build_command(action="identify", file_path="")


class TestGhidraHeadlessWrapper:
    """Validate Ghidra headless wrapper."""

    def test_default_config(self) -> None:
        """Ghidra headless should use reverse engineering defaults."""

        wrapper = GhidraHeadlessWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "ghidra_headless"
        assert wrapper.config.image == "saber/ghidra-headless:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_analyze_binary_command(self) -> None:
        """Analyze binary should include project/import/script details."""

        wrapper = GhidraHeadlessWrapper(FakeSandbox())
        command = wrapper.build_command(
            action="analyze_binary",
            binary_path="samples/app",
            project_dir="ghidra_projects",
            project_name="app_project",
            script_path="ExportSymbols.py",
            script_args=["symbols.json"],
        )

        assert command.command == [
            "analyzeHeadless",
            "ghidra_projects",
            "app_project",
            "-import",
            "samples/app",
            "-overwrite",
            "-analysisTimeoutPerFile",
            "1800",
            "-postScript",
            "ExportSymbols.py",
            "symbols.json",
        ]
        assert command.action == "analyze_binary"

    def test_run_script_delegates_to_sandbox(self) -> None:
        """Run script should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = GhidraHeadlessWrapper(sandbox)

        wrapper.run_script(
            target=make_target(),
            session=make_session(),
            project_dir="ghidra_projects",
            project_name="app_project",
            script_path="ExportFunctions.py",
            script_args=["functions.json"],
        )

        assert sandbox.requests[0].command == [
            "analyzeHeadless",
            "ghidra_projects",
            "app_project",
            "-process",
            "-postScript",
            "ExportFunctions.py",
            "functions.json",
        ]
        assert sandbox.requests[0].tool_request.action == "run_script"

    def test_export_analysis_command(self) -> None:
        """Export analysis should include export script and output file."""

        wrapper = GhidraHeadlessWrapper(FakeSandbox())
        command = wrapper.build_command(
            action="export_analysis",
            binary_path="samples/app",
            project_dir="ghidra_projects",
            project_name="app_project",
            export_script="ExportAnalysis.py",
            output_file="analysis.json",
        )

        assert command.command == [
            "analyzeHeadless",
            "ghidra_projects",
            "app_project",
            "-import",
            "samples/app",
            "-overwrite",
            "-postScript",
            "ExportAnalysis.py",
            "analysis.json",
        ]

    def test_missing_project_name_raises(self) -> None:
        """Missing project name should raise."""

        wrapper = GhidraHeadlessWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="project_name is required"):
            wrapper.build_command(
                action="analyze_binary",
                binary_path="samples/app",
                project_dir="ghidra_projects",
                project_name="",
            )


class TestRadare2Wrapper:
    """Validate radare2 wrapper."""

    def test_default_config(self) -> None:
        """radare2 should use reverse engineering defaults."""

        wrapper = Radare2Wrapper(FakeSandbox())

        assert wrapper.config.tool_name == "radare2"
        assert wrapper.config.image == "saber/radare2:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_analyze_command(self) -> None:
        """Analyze command should include analysis level."""

        wrapper = Radare2Wrapper(FakeSandbox())
        command = wrapper.build_command(action="analyze", binary_path="samples/app", analysis_level="aaa")

        assert command.command == ["r2", "-q", "-c", "aaa", "-c", "q", "samples/app"]
        assert command.action == "analyze"
        assert command.evidence_relative_dir == "reverse_engineering/radare2/analyze"

    def test_info_command(self) -> None:
        """Info command should use ij for JSON."""

        wrapper = Radare2Wrapper(FakeSandbox())
        command = wrapper.build_command(action="info", binary_path="samples/app", json_output=True)

        assert command.command == ["r2", "-q", "-c", "ij", "-c", "q", "samples/app"]
        assert command.metadata["json_output"] is True

    def test_functions_delegates_to_sandbox(self) -> None:
        """Functions method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = Radare2Wrapper(sandbox)

        wrapper.functions(target=make_target(), session=make_session(), binary_path="samples/app")

        assert sandbox.requests[0].command == ["r2", "-q", "-c", "aaa", "-c", "aflj", "-c", "q", "samples/app"]
        assert sandbox.requests[0].tool_request.action == "functions"

    def test_custom_commands_command(self) -> None:
        """Custom command sequence should append q and binary path."""

        wrapper = Radare2Wrapper(FakeSandbox())
        command = wrapper.build_command(
            action="custom_commands",
            binary_path="samples/app",
            commands=["aaa", "afl"],
        )

        assert command.command == ["r2", "-q", "-c", "aaa", "-c", "afl", "-c", "q", "samples/app"]
        assert command.metadata["commands"] == ["aaa", "afl"]

    def test_bad_analysis_level_raises(self) -> None:
        """Bad analysis level should raise."""

        wrapper = Radare2Wrapper(FakeSandbox())

        with pytest.raises(ValueError, match="analysis_level must be one of"):
            wrapper.build_command(action="analyze", binary_path="samples/app", analysis_level="bad")


class TestStringsWrapper:
    """Validate strings wrapper."""

    def test_default_config(self) -> None:
        """strings should use reverse engineering defaults."""

        wrapper = StringsWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "strings"
        assert wrapper.config.image == "saber/strings:latest"
        assert wrapper.config.phase == AssessmentPhase.RECON
        assert wrapper.config.category == RequestedActionCategory.REVERSE_ENGINEERING

    def test_extract_command(self) -> None:
        """Extract command should include min length and encoding."""

        wrapper = StringsWrapper(FakeSandbox())
        command = wrapper.build_command(action="extract", file_path="samples/app", min_length=6, encoding="l")

        assert command.command == ["strings", "-n", "6", "-e", "l", "samples/app"]
        assert command.action == "extract"
        assert command.evidence_relative_dir == "reverse_engineering/strings/extract"

    def test_unicode_delegates_to_sandbox(self) -> None:
        """Unicode method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = StringsWrapper(sandbox)

        wrapper.unicode(target=make_target(), session=make_session(), file_path="samples/app", min_length=8)

        assert sandbox.requests[0].command == ["strings", "-n", "8", "-e", "l", "samples/app"]
        assert sandbox.requests[0].tool_request.action == "unicode"

    def test_grep_command(self) -> None:
        """Grep command should pipe strings to grep."""

        wrapper = StringsWrapper(FakeSandbox())
        command = wrapper.build_command(action="grep", file_path="samples/app", pattern="password", min_length=4)

        assert command.command == ["bash", "-lc", "strings -n 4 samples/app | grep -i -- password"]
        assert command.metadata["pattern"] == "password"

    def test_bad_encoding_raises(self) -> None:
        """Bad encoding should raise."""

        wrapper = StringsWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="encoding must be one of"):
            wrapper.build_command(action="extract", file_path="samples/app", encoding="utf16")


class TestCustomConfigs:
    """Validate custom ToolWrapperConfig support."""

    def test_custom_radare2_config(self) -> None:
        """radare2 should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_radare2",
            image="custom/radare2:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            requested_by="CustomRadare2",
        )

        wrapper = Radare2Wrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_radare2"
        assert wrapper.config.image == "custom/radare2:dev"

    def test_custom_strings_config(self) -> None:
        """strings should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_strings",
            image="custom/strings:dev",
            phase=AssessmentPhase.RECON,
            category=RequestedActionCategory.REVERSE_ENGINEERING,
            requested_by="CustomStrings",
        )

        wrapper = StringsWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_strings"
        assert wrapper.config.image == "custom/strings:dev"


class TestToolCommandValidation:
    """Validate ToolCommand remains available for reverse engineering wrappers."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
