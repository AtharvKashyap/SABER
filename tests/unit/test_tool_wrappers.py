"""Tests for SABER tool wrapper behavior.

These tests define small fake wrappers to lock in the expected wrapper contract
before real wrappers such as NmapWrapper, HttpxWrapper, and NucleiWrapper are
implemented.

A tool wrapper should not bypass SABER's safety layers. Its job is to translate a
high-level wrapper call into:
    - a ToolRequest describing the tool action
    - a command list for the runner backend
    - a SandboxExecutionRequest for guarded execution and evidence capture

The wrapper should then delegate to Sandbox and return the SandboxExecutionResult
without running commands directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.core.sandbox import SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.tools.capability import RequestedActionCategory, ToolRequest
from saber.models.evidence import EvidenceRecord, EvidenceSource, EvidenceStatus, EvidenceType
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType


class FakeSandbox:
    """Fake sandbox that records execution requests and returns a configured result."""

    def __init__(self, result: SandboxExecutionResult) -> None:
        """Initialize fake sandbox.

        Args:
            result: Result returned from execute.
        """

        self.result = result
        self.calls: list[SandboxExecutionRequest] = []

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Record a sandbox execution request.

        Args:
            request: Sandbox request to record.

        Returns:
            Configured sandbox result.
        """

        self.calls.append(request)
        return self.result


@dataclass(frozen=True)
class FakeToolWrapperConfig:
    """Configuration for a fake tool wrapper."""

    tool_name: str = "fake-httpx"
    image: str = "saber/fake-httpx:latest"
    requested_by: str = "FakeHttpxWrapper"
    default_timeout_seconds: int = 60
    metadata: dict[str, Any] = field(default_factory=lambda: {"wrapper": "fake"})


class FakeHttpxWrapper:
    """Minimal wrapper used to verify the expected tool-wrapper contract."""

    def __init__(self, sandbox: FakeSandbox, config: FakeToolWrapperConfig | None = None) -> None:
        """Initialize the fake wrapper.

        Args:
            sandbox: Sandbox-like object used for guarded execution.
            config: Optional wrapper configuration.
        """

        self.sandbox = sandbox
        self.config = config or FakeToolWrapperConfig()

    def build_tool_request(
        self,
        target: Target,
        requires_explicit_authorization: bool = False,
    ) -> ToolRequest:
        """Build the ToolRequest for this wrapper.

        Args:
            target: Target to scan.
            requires_explicit_authorization: Whether this action requires approval.

        Returns:
            ToolRequest for Sandbox metadata.
        """

        return ToolRequest(
            tool_name=self.config.tool_name,
            action="probe_http_service",
            phase=AssessmentPhase.WEB,
            target=target,
            category=RequestedActionCategory.WEB,
            requires_explicit_authorization=requires_explicit_authorization,
            metadata={"wrapper": self.config.requested_by},
        )

    def build_command(self, target: Target) -> list[str]:
        """Build the command for the runner backend.

        Args:
            target: Target to scan.

        Returns:
            Command argument list.
        """

        return ["httpx", "-u", target.tool_value()]

    def build_execution_request(
        self,
        target: Target,
        session: MissionSession,
        requires_explicit_authorization: bool = False,
        timeout_seconds: int | None = None,
    ) -> SandboxExecutionRequest:
        """Build a SandboxExecutionRequest.

        Args:
            target: Target to scan.
            session: Current mission session.
            requires_explicit_authorization: Whether this action requires approval.
            timeout_seconds: Optional timeout override.

        Returns:
            SandboxExecutionRequest ready for Sandbox.
        """

        tool_request = self.build_tool_request(
            target=target,
            requires_explicit_authorization=requires_explicit_authorization,
        )
        return SandboxExecutionRequest(
            tool_request=tool_request,
            command=self.build_command(target),
            session=session,
            requested_by=self.config.requested_by,
            image=self.config.image,
            timeout_seconds=timeout_seconds or self.config.default_timeout_seconds,
            evidence_title=f"{self.config.tool_name}: {target.value}",
            evidence_relative_dir=self.config.tool_name,
            metadata=self.config.metadata,
        )

    def run(
        self,
        target: Target,
        session: MissionSession,
        requires_explicit_authorization: bool = False,
    ) -> SandboxExecutionResult:
        """Run the wrapper through Sandbox.

        Args:
            target: Target to scan.
            session: Current mission session.
            requires_explicit_authorization: Whether this action requires approval.

        Returns:
            SandboxExecutionResult from the configured sandbox.
        """

        request = self.build_execution_request(
            target=target,
            session=session,
            requires_explicit_authorization=requires_explicit_authorization,
        )
        return self.sandbox.execute(request)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact wrapper summary.

        Returns:
            JSON-compatible wrapper summary.
        """

        return {
            "tool_name": self.config.tool_name,
            "image": self.config.image,
            "requested_by": self.config.requested_by,
            "default_timeout_seconds": self.config.default_timeout_seconds,
            "metadata": self.config.metadata,
        }


def make_target() -> Target:
    """Create a reusable web target.

    Returns:
        Validated Target object.
    """

    return Target(type=TargetType.URL, value="https://example.com")


def make_session() -> MissionSession:
    """Create a reusable mission session.

    Returns:
        Validated MissionSession object.
    """

    return MissionSession(
        session_id="session_1",
        mission_name="Tool Wrapper Test Mission",
        status=SessionStatus.CREATED,
    )


def make_evidence(target: Target | None = None) -> EvidenceRecord:
    """Create reusable evidence for wrapper tests.

    Args:
        target: Optional target to attach.

    Returns:
        Validated EvidenceRecord.
    """

    return EvidenceRecord(
        evidence_id="ev_1",
        type=EvidenceType.COMMAND_OUTPUT,
        source=EvidenceSource.TOOL_WRAPPER,
        status=EvidenceStatus.COLLECTED,
        title="Fake httpx output",
        target=target or make_target(),
        tool_name="fake-httpx",
        content_preview="https://example.com [200]",
        parsed_data={},
    )


def make_sandbox_result(
    outcome: SandboxOutcome = SandboxOutcome.EXECUTED,
    allowed: bool = True,
    session: MissionSession | None = None,
    evidence: EvidenceRecord | None = None,
    reason: str = "Command executed and evidence was saved.",
) -> SandboxExecutionResult:
    """Create a reusable SandboxExecutionResult.

    Args:
        outcome: Sandbox outcome.
        allowed: Whether the sandbox allowed execution.
        session: Optional session.
        evidence: Optional evidence.
        reason: Result reason.

    Returns:
        SandboxExecutionResult.
    """

    resolved_session = session or make_session()
    return SandboxExecutionResult(
        outcome=outcome,
        allowed=allowed,
        session=resolved_session,
        evidence=evidence,
        return_code=0 if outcome == SandboxOutcome.EXECUTED else None,
        stdout="https://example.com [200]" if outcome == SandboxOutcome.EXECUTED else "",
        stderr="",
        reason=reason,
        metadata={"source": "fake-sandbox"},
    )


class TestFakeToolWrapperRequestBuilding:
    """Validate wrapper request and command construction."""

    def test_build_tool_request_uses_safe_web_defaults(self) -> None:
        """Wrapper should build a web ToolRequest with stable metadata."""

        target = make_target()
        sandbox = FakeSandbox(make_sandbox_result())
        wrapper = FakeHttpxWrapper(sandbox)

        request = wrapper.build_tool_request(target)

        assert request.tool_name == "fake-httpx"
        assert request.action == "probe_http_service"
        assert request.phase == AssessmentPhase.WEB
        assert request.target == target
        assert request.category == RequestedActionCategory.WEB
        assert request.requires_explicit_authorization is False
        assert request.metadata == {"wrapper": "FakeHttpxWrapper"}

    def test_build_tool_request_can_require_explicit_authorization(self) -> None:
        """Wrapper should preserve explicit-authorization requirements."""

        target = make_target()
        sandbox = FakeSandbox(make_sandbox_result())
        wrapper = FakeHttpxWrapper(sandbox)

        request = wrapper.build_tool_request(target, requires_explicit_authorization=True)

        assert request.requires_explicit_authorization is True

    def test_build_command_uses_target_tool_value(self) -> None:
        """Wrapper commands should use the normalized tool value."""

        target = make_target()
        sandbox = FakeSandbox(make_sandbox_result())
        wrapper = FakeHttpxWrapper(sandbox)

        assert wrapper.build_command(target) == ["httpx", "-u", "https://example.com/"]

    def test_build_execution_request_contains_sandbox_fields(self) -> None:
        """Wrapper should build a complete SandboxExecutionRequest."""

        target = make_target()
        session = make_session()
        sandbox = FakeSandbox(make_sandbox_result(session=session))
        wrapper = FakeHttpxWrapper(sandbox)

        request = wrapper.build_execution_request(
            target=target,
            session=session,
            requires_explicit_authorization=True,
            timeout_seconds=15,
        )

        assert request.tool_request.requires_explicit_authorization is True
        assert request.command == ["httpx", "-u", "https://example.com/"]
        assert request.session == session
        assert request.requested_by == "FakeHttpxWrapper"
        assert request.image == "saber/fake-httpx:latest"
        assert request.timeout_seconds == 15
        assert request.evidence_title == "fake-httpx: https://example.com/"
        assert request.evidence_relative_dir == "fake-httpx"
        assert request.metadata == {"wrapper": "fake"}


class TestFakeToolWrapperExecution:
    """Validate wrapper execution delegation behavior."""

    def test_run_delegates_to_sandbox_and_returns_result(self) -> None:
        """Wrapper should not execute directly; it should call Sandbox."""

        target = make_target()
        session = make_session()
        evidence = make_evidence(target)
        sandbox_result = make_sandbox_result(session=session, evidence=evidence)
        sandbox = FakeSandbox(sandbox_result)
        wrapper = FakeHttpxWrapper(sandbox)

        result = wrapper.run(target=target, session=session)

        assert result == sandbox_result
        assert len(sandbox.calls) == 1
        assert sandbox.calls[0].command == ["httpx", "-u", "https://example.com/"]
        assert sandbox.calls[0].tool_request.target == target
        assert sandbox.calls[0].session == session

    def test_run_preserves_runner_failed_result(self) -> None:
        """Wrapper should return runner-failed sandbox results without overriding them."""

        target = make_target()
        session = make_session()
        sandbox_result = make_sandbox_result(
            outcome=SandboxOutcome.RUNNER_FAILED,
            allowed=False,
            session=session,
            evidence=None,
            reason="Runner failed before returning a result.",
        )
        sandbox = FakeSandbox(sandbox_result)
        wrapper = FakeHttpxWrapper(sandbox)

        result = wrapper.run(
            target=target,
            session=session,
            requires_explicit_authorization=True,
        )

        assert result.outcome == SandboxOutcome.RUNNER_FAILED
        assert result.allowed is False
        assert result.evidence is None
        assert len(sandbox.calls) == 1
        assert sandbox.calls[0].tool_request.requires_explicit_authorization is True

    def test_run_preserves_evidence_failed_result(self) -> None:
        """Wrapper should return evidence-failed sandbox results without overriding them."""

        target = make_target()
        session = make_session()
        sandbox_result = make_sandbox_result(
            outcome=SandboxOutcome.EVIDENCE_FAILED,
            allowed=False,
            session=session,
            evidence=None,
            reason="Command executed but evidence persistence failed.",
        )
        sandbox = FakeSandbox(sandbox_result)
        wrapper = FakeHttpxWrapper(sandbox)

        result = wrapper.run(target=target, session=session)

        assert result.outcome == SandboxOutcome.EVIDENCE_FAILED
        assert result.allowed is False
        assert result.reason == "Command executed but evidence persistence failed."
        assert len(sandbox.calls) == 1


class TestFakeToolWrapperConfiguration:
    """Validate wrapper configuration behavior."""

    def test_custom_config_changes_request_fields(self) -> None:
        """Custom wrapper config should flow into generated sandbox requests."""

        target = make_target()
        session = make_session()
        config = FakeToolWrapperConfig(
            tool_name="custom-httpx",
            image="custom/httpx:1.0",
            requested_by="CustomWrapper",
            default_timeout_seconds=10,
            metadata={"profile": "fast"},
        )
        sandbox = FakeSandbox(make_sandbox_result(session=session))
        wrapper = FakeHttpxWrapper(sandbox=sandbox, config=config)

        request = wrapper.build_execution_request(target=target, session=session)

        assert request.tool_request.tool_name == "custom-httpx"
        assert request.requested_by == "CustomWrapper"
        assert request.image == "custom/httpx:1.0"
        assert request.timeout_seconds == 10
        assert request.metadata == {"profile": "fast"}
        assert request.evidence_title == "custom-httpx: https://example.com/"
        assert request.evidence_relative_dir == "custom-httpx"

    def test_to_summary_dict_returns_stable_wrapper_summary(self) -> None:
        """Wrapper summaries should be compact and JSON-compatible."""

        sandbox = FakeSandbox(make_sandbox_result())
        wrapper = FakeHttpxWrapper(sandbox)

        assert wrapper.to_summary_dict() == {
            "tool_name": "fake-httpx",
            "image": "saber/fake-httpx:latest",
            "requested_by": "FakeHttpxWrapper",
            "default_timeout_seconds": 60,
            "metadata": {"wrapper": "fake"},
        }
