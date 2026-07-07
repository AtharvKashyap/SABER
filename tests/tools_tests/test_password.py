"""Tests for password tool wrappers."""

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
from saber.tools.password import HashcatWrapper, JohnWrapper


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

    return Target(type=TargetType.HOST, value="192.0.2.10")


def make_session() -> MissionSession:
    """Create reusable mission session."""

    return MissionSession(
        session_id="session_password_1",
        mission_name="Password Wrapper Test Mission",
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


class TestPasswordExports:
    """Validate password package exports."""

    def test_exports_wrappers(self) -> None:
        """Package should export password wrapper classes."""

        assert HashcatWrapper is not None
        assert JohnWrapper is not None


class TestHashcatWrapper:
    """Validate Hashcat wrapper."""

    def test_default_config(self) -> None:
        """Hashcat should use password defaults."""

        wrapper = HashcatWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "hashcat"
        assert wrapper.config.image == "saber/hashcat:latest"
        assert wrapper.config.phase == AssessmentPhase.EXPLOITATION
        assert wrapper.config.category == RequestedActionCategory.PASSWORD_CRACKING
        assert wrapper.config.requested_by == "HashcatWrapper"

    def test_dictionary_attack_command(self) -> None:
        """Dictionary attack should include hash mode, attack mode, hash file, wordlist, rules, and workload."""

        wrapper = HashcatWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="dictionary_attack",
            hash_file="hashes/ntlm.txt",
            hash_mode=1000,
            wordlist="wordlists/rockyou.txt",
            rules=["rules/best64.rule", "rules/dive.rule"],
            workload_profile=3,
        )

        assert command.command == [
            "hashcat",
            "-m",
            "1000",
            "-a",
            "0",
            "hashes/ntlm.txt",
            "wordlists/rockyou.txt",
            "-r",
            "rules/best64.rule",
            "-r",
            "rules/dive.rule",
            "-w",
            "3",
        ]
        assert command.action == "dictionary_attack"
        assert command.evidence_relative_dir == "password/hashcat/dictionary"
        assert command.metadata["hash_mode"] == "1000"
        assert command.metadata["rules"] == ["rules/best64.rule", "rules/dive.rule"]

    def test_mask_attack_command(self) -> None:
        """Mask attack should use attack mode 3."""

        wrapper = HashcatWrapper(FakeSandbox())
        command = wrapper.build_command(
            action="mask_attack",
            hash_file="hashes/ntlm.txt",
            hash_mode="1000",
            mask="?u?l?l?l?d?d",
        )

        assert command.command == ["hashcat", "-m", "1000", "-a", "3", "hashes/ntlm.txt", "?u?l?l?l?d?d"]
        assert command.evidence_relative_dir == "password/hashcat/mask"
        assert command.metadata["mask"] == "?u?l?l?l?d?d"

    def test_show_cracked_command(self) -> None:
        """Show cracked should use --show."""

        wrapper = HashcatWrapper(FakeSandbox())
        command = wrapper.build_command(action="show_cracked", hash_file="hashes/ntlm.txt", hash_mode=1000)

        assert command.command == ["hashcat", "-m", "1000", "--show", "hashes/ntlm.txt"]
        assert command.action == "show_cracked"

    def test_benchmark_command(self) -> None:
        """Benchmark should optionally include hash mode."""

        wrapper = HashcatWrapper(FakeSandbox())
        command = wrapper.build_command(action="benchmark", hash_mode=1000)

        assert command.command == ["hashcat", "-b", "-m", "1000"]
        assert command.action == "benchmark"

    def test_dictionary_attack_delegates_to_sandbox(self) -> None:
        """Public dictionary attack method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = HashcatWrapper(sandbox)

        result = wrapper.dictionary_attack(
            target=make_target(),
            session=make_session(),
            hash_file="hashes/ntlm.txt",
            hash_mode=1000,
            wordlist="wordlists/rockyou.txt",
        )

        assert result.outcome == SandboxOutcome.EXECUTED
        assert len(sandbox.requests) == 1
        request = sandbox.requests[0]
        assert request.command == ["hashcat", "-m", "1000", "-a", "0", "hashes/ntlm.txt", "wordlists/rockyou.txt"]
        assert request.tool_request.tool_name == "hashcat"
        assert request.tool_request.action == "dictionary_attack"
        assert request.tool_request.category == RequestedActionCategory.PASSWORD_CRACKING

    def test_mask_attack_delegates_to_sandbox(self) -> None:
        """Public mask attack method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = HashcatWrapper(sandbox)

        wrapper.mask_attack(
            target=make_target(),
            session=make_session(),
            hash_file="hashes/ntlm.txt",
            hash_mode=1000,
            mask="?a?a?a?a",
        )

        assert sandbox.requests[0].tool_request.action == "mask_attack"
        assert sandbox.requests[0].command[-1] == "?a?a?a?a"

    def test_show_cracked_delegates_to_sandbox(self) -> None:
        """Public show method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = HashcatWrapper(sandbox)

        wrapper.show_cracked(target=make_target(), session=make_session(), hash_file="hashes/ntlm.txt", hash_mode=1000)

        assert sandbox.requests[0].command == ["hashcat", "-m", "1000", "--show", "hashes/ntlm.txt"]
        assert sandbox.requests[0].tool_request.action == "show_cracked"

    def test_benchmark_delegates_to_sandbox(self) -> None:
        """Public benchmark method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = HashcatWrapper(sandbox)

        wrapper.benchmark(target=make_target(), session=make_session())

        assert sandbox.requests[0].command == ["hashcat", "-b"]
        assert sandbox.requests[0].tool_request.action == "benchmark"

    def test_missing_hash_file_raises(self) -> None:
        """Missing hash file should raise."""

        wrapper = HashcatWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="hash_file is required"):
            wrapper.build_command(action="dictionary_attack", hash_file="", hash_mode=1000, wordlist="wordlists/rockyou.txt")

    def test_bad_workload_profile_raises(self) -> None:
        """Invalid workload profile should raise."""

        wrapper = HashcatWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="workload_profile must be a positive integer"):
            wrapper.build_command(
                action="dictionary_attack",
                hash_file="hashes/ntlm.txt",
                hash_mode=1000,
                wordlist="wordlists/rockyou.txt",
                workload_profile=0,
            )

    def test_unsupported_action_raises(self) -> None:
        """Unsupported Hashcat action should raise."""

        wrapper = HashcatWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported Hashcat action"):
            wrapper.build_command(action="nope")


class TestJohnWrapper:
    """Validate John wrapper."""

    def test_default_config(self) -> None:
        """John should use password defaults."""

        wrapper = JohnWrapper(FakeSandbox())

        assert wrapper.config.tool_name == "john"
        assert wrapper.config.image == "saber/john:latest"
        assert wrapper.config.phase == AssessmentPhase.EXPLOITATION
        assert wrapper.config.category == RequestedActionCategory.PASSWORD_CRACKING
        assert wrapper.config.requested_by == "JohnWrapper"

    def test_dictionary_attack_command(self) -> None:
        """Dictionary attack should include wordlist, format, rules, and hash file."""

        wrapper = JohnWrapper(FakeSandbox())
        command = wrapper.build_command(
            target=make_target(),
            action="dictionary_attack",
            hash_file="hashes/shadow.txt",
            wordlist="wordlists/rockyou.txt",
            format_name="sha512crypt",
            rules="jumbo",
        )

        assert command.command == [
            "john",
            "--wordlist=wordlists/rockyou.txt",
            "--format=sha512crypt",
            "--rules=jumbo",
            "hashes/shadow.txt",
        ]
        assert command.action == "dictionary_attack"
        assert command.evidence_relative_dir == "password/john/dictionary"
        assert command.metadata["format_name"] == "sha512crypt"
        assert command.metadata["rules"] == "jumbo"

    def test_single_crack_command(self) -> None:
        """Single crack should use --single."""

        wrapper = JohnWrapper(FakeSandbox())
        command = wrapper.build_command(action="single_crack", hash_file="hashes/shadow.txt", format_name="sha512crypt")

        assert command.command == ["john", "--single", "--format=sha512crypt", "hashes/shadow.txt"]
        assert command.action == "single_crack"

    def test_show_cracked_command(self) -> None:
        """Show cracked should use --show."""

        wrapper = JohnWrapper(FakeSandbox())
        command = wrapper.build_command(action="show_cracked", hash_file="hashes/shadow.txt")

        assert command.command == ["john", "--show", "hashes/shadow.txt"]
        assert command.evidence_relative_dir == "password/john/show"

    def test_list_formats_command(self) -> None:
        """List formats should use --list=formats."""

        wrapper = JohnWrapper(FakeSandbox())
        command = wrapper.build_command(action="list_formats")

        assert command.command == ["john", "--list=formats"]
        assert command.action == "list_formats"

    def test_dictionary_attack_delegates_to_sandbox(self) -> None:
        """Public dictionary attack method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = JohnWrapper(sandbox)

        result = wrapper.dictionary_attack(
            target=make_target(),
            session=make_session(),
            hash_file="hashes/shadow.txt",
            wordlist="wordlists/rockyou.txt",
            format_name="sha512crypt",
        )

        assert result.outcome == SandboxOutcome.EXECUTED
        assert sandbox.requests[0].command == [
            "john",
            "--wordlist=wordlists/rockyou.txt",
            "--format=sha512crypt",
            "hashes/shadow.txt",
        ]
        assert sandbox.requests[0].tool_request.tool_name == "john"
        assert sandbox.requests[0].tool_request.action == "dictionary_attack"
        assert sandbox.requests[0].tool_request.category == RequestedActionCategory.PASSWORD_CRACKING

    def test_single_crack_delegates_to_sandbox(self) -> None:
        """Public single crack method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = JohnWrapper(sandbox)

        wrapper.single_crack(target=make_target(), session=make_session(), hash_file="hashes/shadow.txt")

        assert sandbox.requests[0].command == ["john", "--single", "hashes/shadow.txt"]
        assert sandbox.requests[0].tool_request.action == "single_crack"

    def test_show_cracked_delegates_to_sandbox(self) -> None:
        """Public show cracked method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = JohnWrapper(sandbox)

        wrapper.show_cracked(target=make_target(), session=make_session(), hash_file="hashes/shadow.txt")

        assert sandbox.requests[0].command == ["john", "--show", "hashes/shadow.txt"]
        assert sandbox.requests[0].tool_request.action == "show_cracked"

    def test_list_formats_delegates_to_sandbox(self) -> None:
        """Public list formats method should execute through Sandbox."""

        sandbox = FakeSandbox()
        wrapper = JohnWrapper(sandbox)

        wrapper.list_formats(target=make_target(), session=make_session())

        assert sandbox.requests[0].command == ["john", "--list=formats"]
        assert sandbox.requests[0].tool_request.action == "list_formats"

    def test_missing_wordlist_raises(self) -> None:
        """Missing wordlist should raise."""

        wrapper = JohnWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="wordlist is required"):
            wrapper.build_command(action="dictionary_attack", hash_file="hashes/shadow.txt", wordlist="")

    def test_unsupported_action_raises(self) -> None:
        """Unsupported John action should raise."""

        wrapper = JohnWrapper(FakeSandbox())

        with pytest.raises(ValueError, match="Unsupported John action"):
            wrapper.build_command(action="nope")


class TestCustomConfigs:
    """Validate custom ToolWrapperConfig support."""

    def test_hashcat_custom_config(self) -> None:
        """Hashcat should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_hashcat",
            image="custom/hashcat:dev",
            phase=AssessmentPhase.EXPLOITATION,
            category=RequestedActionCategory.PASSWORD_CRACKING,
            requested_by="CustomHashcat",
        )

        wrapper = HashcatWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_hashcat"
        assert wrapper.config.image == "custom/hashcat:dev"

    def test_john_custom_config(self) -> None:
        """John should accept custom config."""

        config = ToolWrapperConfig(
            tool_name="custom_john",
            image="custom/john:dev",
            phase=AssessmentPhase.EXPLOITATION,
            category=RequestedActionCategory.PASSWORD_CRACKING,
            requested_by="CustomJohn",
        )

        wrapper = JohnWrapper(FakeSandbox(), config=config)

        assert wrapper.config.tool_name == "custom_john"
        assert wrapper.config.image == "custom/john:dev"


class TestToolCommandValidation:
    """Validate ToolCommand remains available for password wrappers."""

    def test_tool_command_validates_empty_command(self) -> None:
        """Empty command should raise ValueError."""

        with pytest.raises(ValueError, match="command cannot be empty"):
            ToolCommand(
                command=[],
                action="bad",
                evidence_title="Bad",
                evidence_relative_dir="bad",
            )
