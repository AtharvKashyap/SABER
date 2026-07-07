"""Tests for SABER Sandbox.

Sandbox is the bridge between tool wrappers, a runner backend, and EvidenceStore.
These tests use fake runners so no Docker containers or shell commands are
executed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from saber.core.evidence_store import EvidenceStore
from saber.core.sandbox import Sandbox, SandboxExecutionRequest, SandboxOutcome
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession, SessionStatus
from saber.models.target import Target, TargetType
from saber.tools.capability import RequestedActionCategory, ToolRequest


@dataclass(frozen=True)
class FakeRunnerResult:
    """Simple object-style runner result for sandbox tests."""

    stdout: str = "runner stdout"
    stderr: str = ""
    return_code: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC) - timedelta(seconds=1))
    finished_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = field(default_factory=lambda: {"backend": "fake"})


class FakeRunner:
    """Fake command runner that records inputs and returns a configured result."""

    def __init__(self, result: Any | None = None) -> None:
        """Initialize fake runner.

        Args:
            result: Optional result to return from run.
        """

        self.result = result if result is not None else FakeRunnerResult()
        self.calls: list[dict[str, Any]] = []

    def run(self, command: list[str], **kwargs: Any) -> Any:
        """Record a command execution request and return the configured result.

        Args:
            command: Command to record.
            kwargs: Runner options to record.

        Returns:
            Configured fake runner result.
        """

        self.calls.append({"command": command, "kwargs": kwargs})
        return self.result


class FailingRunner:
    """Fake command runner that raises before returning a result."""

    def run(self, command: list[str], **kwargs: Any) -> Any:
        """Raise a runner failure.

        Args:
            command: Ignored command.
            kwargs: Ignored runner options.

        Raises:
            RuntimeError: Always raised.
        """

        raise RuntimeError("runner unavailable")


class FailingEvidenceStore(EvidenceStore):
    """EvidenceStore variant that fails while saving command output."""

    def save_command_output(self, *args: Any, **kwargs: Any) -> Any:
        """Raise an evidence persistence failure.

        Args:
            args: Ignored positional arguments.
            kwargs: Ignored keyword arguments.

        Raises:
            RuntimeError: Always raised.
        """

        raise RuntimeError("disk full")


def make_target() -> Target:
    """Create a reusable target.

    Returns:
        Validated Target object.
    """

    return Target(type=TargetType.DOMAIN, value="example.com")


def make_session() -> MissionSession:
    """Create a reusable mission session.

    Returns:
        Validated MissionSession object.
    """

    return MissionSession(
        session_id="session_1",
        mission_name="Sandbox Test Mission",
        status=SessionStatus.CREATED,
    )


def make_tool_request(
    target: Target | None = None,
    action: str = "run_http_probe",
    phase: AssessmentPhase = AssessmentPhase.WEB,
    category: RequestedActionCategory = RequestedActionCategory.WEB,
    requires_explicit_authorization: bool = False,
) -> ToolRequest:
    """Create a reusable ToolRequest.

    Args:
        target: Optional request target.
        action: Requested action.
        phase: Requested phase.
        category: Requested action category.
        requires_explicit_authorization: Whether the request metadata marks approval as useful.

    Returns:
        ToolRequest object.
    """

    return ToolRequest(
        tool_name="httpx",
        action=action,
        phase=phase,
        target=target if target is not None else make_target(),
        category=category,
        requires_explicit_authorization=requires_explicit_authorization,
        metadata={"safe": True},
    )


def make_sandbox(
    tmp_path: Path,
    runner: Any | None = None,
    evidence_store: EvidenceStore | None = None,
) -> Sandbox:
    """Create a Sandbox with fake dependencies.

    Args:
        tmp_path: Temporary path for evidence.
        runner: Optional fake runner.
        evidence_store: Optional evidence store.

    Returns:
        Configured Sandbox instance.
    """

    return Sandbox(
        evidence_store=evidence_store or EvidenceStore(tmp_path / "evidence"),
        runner=runner or FakeRunner(),
    )


def make_execution_request(tool_request: ToolRequest | None = None) -> SandboxExecutionRequest:
    """Create a reusable sandbox execution request.

    Args:
        tool_request: Optional tool request.

    Returns:
        SandboxExecutionRequest object.
    """

    return SandboxExecutionRequest(
        tool_request=tool_request or make_tool_request(),
        command=["httpx", "-u", "https://example.com"],
        session=make_session(),
        requested_by="HttpxWrapper",
        image="saber/httpx:latest",
        working_directory="/work",
        environment={"API_TOKEN": "redacted"},
        timeout_seconds=30,
        evidence_title="HTTP probe output",
        evidence_relative_dir="httpx",
        runner_options={"network_disabled": False},
        metadata={"run_id": "run_1"},
    )


class TestSandboxExecutionResult:
    """Validate SandboxExecutionResult behavior."""

    def test_to_summary_dict_for_executed_result(self, tmp_path: Path) -> None:
        """Sandbox result summaries should include key IDs and status."""

        sandbox = make_sandbox(tmp_path)
        request = make_execution_request()
        result = sandbox.execute(request)

        assert result.to_summary_dict() == {
            "outcome": "executed",
            "allowed": True,
            "session_id": "session_1",
            "evidence_id": result.evidence.evidence_id if result.evidence else None,
            "return_code": 0,
            "reason": "Command executed and evidence was saved.",
            "metadata": result.metadata,
        }


class TestSandboxExecution:
    """Validate sandbox execution path."""

    def test_request_runs_runner_and_saves_evidence(self, tmp_path: Path) -> None:
        """Requests should execute and attach evidence to the session."""

        runner = FakeRunner(FakeRunnerResult(stdout="https://example.com [200]", stderr="warning", return_code=0))
        sandbox = make_sandbox(tmp_path, runner=runner)
        request = make_execution_request()

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EXECUTED
        assert result.allowed is True
        assert result.return_code == 0
        assert result.stdout == "https://example.com [200]"
        assert result.stderr == "warning"
        assert result.evidence is not None
        assert result.evidence.type.value == "command_output"
        assert result.evidence.tool_name == "httpx"
        assert result.evidence.command is not None
        assert result.evidence.command.command == ["httpx", "-u", "https://example.com"]
        assert result.evidence.command.tool == "httpx"
        assert result.evidence.command.sandboxed is True
        assert result.evidence.command.environment_redacted is True
        assert result.session.evidence == [result.evidence]
        assert result.metadata["requested_by"] == "HttpxWrapper"
        assert result.metadata["tool_name"] == "httpx"
        assert result.metadata["tool_action"] == "run_http_probe"
        assert result.metadata["tool_category"] == "web"
        assert runner.calls == [
            {
                "command": ["httpx", "-u", "https://example.com"],
                "kwargs": {
                    "image": "saber/httpx:latest",
                    "working_directory": "/work",
                    "environment": {"API_TOKEN": "redacted"},
                    "timeout_seconds": 30,
                    "network_disabled": False,
                },
            }
        ]

        saved_text = (tmp_path / "evidence" / result.evidence.file_path).read_text(encoding="utf-8")
        assert "$ httpx -u https://example.com" in saved_text
        assert "[stdout]" in saved_text
        assert "https://example.com [200]" in saved_text
        assert "[stderr]" in saved_text
        assert "warning" in saved_text

    def test_request_accepts_mapping_runner_result(self, tmp_path: Path) -> None:
        """Sandbox should accept dict-style runner results."""

        started_at = datetime.now(UTC) - timedelta(seconds=2)
        finished_at = datetime.now(UTC)
        runner = FakeRunner(
            {
                "stdout": "dict stdout",
                "stderr": "dict stderr",
                "return_code": "7",
                "started_at": started_at,
                "finished_at": finished_at,
                "metadata": {"format": "dict"},
            }
        )
        sandbox = make_sandbox(tmp_path, runner=runner)
        request = make_execution_request()

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EXECUTED
        assert result.return_code == 7
        assert result.stdout == "dict stdout"
        assert result.stderr == "dict stderr"
        assert result.metadata["runner_metadata"] == {"format": "dict"}
        assert result.evidence is not None
        assert result.evidence.command is not None
        assert result.evidence.command.started_at == started_at
        assert result.evidence.command.finished_at == finished_at

    def test_request_defaults_missing_runner_fields(self, tmp_path: Path) -> None:
        """Missing runner fields should default safely."""

        runner = FakeRunner({})
        sandbox = make_sandbox(tmp_path, runner=runner)
        request = make_execution_request()

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EXECUTED
        assert result.return_code == 0
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.evidence is not None
        assert result.evidence.command is not None
        assert result.evidence.command.duration_seconds >= 0

    def test_request_marked_approval_required_still_executes_as_metadata(self, tmp_path: Path) -> None:
        """Approval-required markers are metadata now, not sandbox blockers."""

        runner = FakeRunner()
        sandbox = make_sandbox(tmp_path, runner=runner)
        tool_request = make_tool_request(requires_explicit_authorization=True)
        request = make_execution_request(tool_request=tool_request)

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EXECUTED
        assert result.allowed is True
        assert result.evidence is not None
        assert runner.calls != []

    def test_exploitation_category_still_executes_through_sandbox(self, tmp_path: Path) -> None:
        """Sandbox executes requests regardless of tool category metadata."""

        runner = FakeRunner()
        sandbox = make_sandbox(tmp_path, runner=runner)
        tool_request = make_tool_request(
            action="run_exploit_check",
            phase=AssessmentPhase.EXPLOITATION,
            category=RequestedActionCategory.EXPLOITATION,
        )
        request = make_execution_request(tool_request=tool_request)

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EXECUTED
        assert result.allowed is True
        assert result.metadata["tool_category"] == "exploitation"
        assert runner.calls != []


class TestSandboxFailures:
    """Validate runner and evidence failure behavior."""

    def test_runner_failure_returns_runner_failed(self, tmp_path: Path) -> None:
        """Runner exceptions should be converted into RUNNER_FAILED results."""

        sandbox = make_sandbox(tmp_path, runner=FailingRunner())
        request = make_execution_request()

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.RUNNER_FAILED
        assert result.allowed is False
        assert result.evidence is None
        assert result.return_code is None
        assert "runner unavailable" in result.reason
        assert result.metadata["error_type"] == "RuntimeError"
        assert result.metadata["tool_name"] == "httpx"

    def test_evidence_failure_returns_evidence_failed(self, tmp_path: Path) -> None:
        """Evidence persistence failures should preserve runner output in result."""

        sandbox = make_sandbox(
            tmp_path,
            runner=FakeRunner(FakeRunnerResult(stdout="saved nowhere", stderr="err", return_code=3)),
            evidence_store=FailingEvidenceStore(tmp_path / "evidence"),
        )
        request = make_execution_request()

        result = sandbox.execute(request)

        assert result.outcome == SandboxOutcome.EVIDENCE_FAILED
        assert result.allowed is True
        assert result.evidence is None
        assert result.return_code == 3
        assert result.stdout == "saved nowhere"
        assert result.stderr == "err"
        assert "disk full" in result.reason
        assert result.metadata["error_type"] == "RuntimeError"
        assert result.metadata["tool_name"] == "httpx"


class TestSandboxResultHelpers:
    """Validate internal result coercion helpers."""

    def test_result_helpers_read_object_values(self) -> None:
        """Result helper methods should read object-style results."""

        result = FakeRunnerResult(stdout="abc", stderr=None, return_code="5")

        assert Sandbox._result_text(result, "stdout") == "abc"
        assert Sandbox._result_text(result, "stderr") == ""
        assert Sandbox._result_int(result, "return_code", default=0) == 5
        assert Sandbox._result_mapping(result, "metadata") == {"backend": "fake"}
        assert Sandbox._result_datetime(result, "started_at") == result.started_at

    def test_result_helpers_read_mapping_values(self) -> None:
        """Result helper methods should read dict-style results."""

        started_at = datetime.now(UTC)
        result = {
            "stdout": 123,
            "stderr": None,
            "return_code": "bad",
            "metadata": ["not", "dict"],
            "started_at": started_at,
        }

        assert Sandbox._result_text(result, "stdout") == "123"
        assert Sandbox._result_text(result, "stderr") == ""
        assert Sandbox._result_int(result, "return_code", default=9) == 9
        assert Sandbox._result_mapping(result, "metadata") == {}
        assert Sandbox._result_datetime(result, "started_at") == started_at
