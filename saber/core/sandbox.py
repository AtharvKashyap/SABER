"""Sandboxed execution orchestration for SABER.

This module defines Sandbox, the safe bridge between policy enforcement,
approval handling, sandboxed command execution, and evidence persistence.

Sandbox does not decide mission strategy, parse tool output into findings, choose
phases, or generate reports. Its responsibility is narrower:

    1. Ask ScopeGuard whether a proposed ToolRequest is allowed.
    2. Route review-required decisions through ApprovalGate.
    3. Refuse denied or pending requests before any command runs.
    4. Execute allowed commands through DockerRunner or another compatible runner.
    5. Save command output as EvidenceRecord objects through EvidenceStore.

The runner dependency is intentionally duck-typed. DockerRunner can implement its
own return object as long as the object exposes command output through common
attributes such as stdout, stderr, return_code, started_at, finished_at, and
metadata, or through an equivalent mapping interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from saber.core.approval_gate import ApprovalGate, ApprovalGateOutcome, ApprovalGateResult
from saber.core.evidence_store import EvidenceStore
from saber.core.scope_guard import ScopeGuard, ToolRequest
from saber.models.evidence import CommandMetadata, EvidenceRecord
from saber.models.session import MissionSession
from saber.models.scope import ScopeDecision


class SandboxOutcome(StrEnum):
    """Possible outcomes from a sandbox execution request.

    Values:
        EXECUTED: The command ran and evidence was saved.
        DENIED: Scope policy or approval denied the request.
        WAITING_FOR_APPROVAL: The request requires approval before execution.
        RUNNER_FAILED: The runner raised an exception before a result was returned.
        EVIDENCE_FAILED: Execution finished, but evidence persistence failed.
    """

    EXECUTED = "executed"
    DENIED = "denied"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    RUNNER_FAILED = "runner_failed"
    EVIDENCE_FAILED = "evidence_failed"


@dataclass(frozen=True)
class SandboxExecutionRequest:
    """Request to execute one command through the sandbox layer.

    Args:
        tool_request: Scope-aware tool request describing the action.
        command: Command and arguments to execute.
        session: Current mission session.
        requested_by: Component or wrapper requesting execution.
        image: Optional container image name for Docker-backed runners.
        working_directory: Optional working directory inside the runner context.
        environment: Optional environment variables for the runner.
        timeout_seconds: Optional execution timeout in seconds.
        evidence_title: Optional evidence title. Defaults to a tool/action title.
        evidence_relative_dir: Optional evidence directory below the EvidenceStore root.
        runner_options: Optional runner-specific keyword arguments.
        metadata: Optional structured request metadata.

    Returns:
        Immutable sandbox execution request.
    """

    tool_request: ToolRequest
    command: list[str]
    session: MissionSession
    requested_by: str
    image: str | None = None
    working_directory: str | None = None
    environment: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int | None = None
    evidence_title: str | None = None
    evidence_relative_dir: str | None = None
    runner_options: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SandboxExecutionResult:
    """Result returned after a sandbox execution request.

    Args:
        outcome: High-level sandbox outcome.
        allowed: Whether execution was allowed to run.
        session: Updated mission session.
        scope_decision: ScopeGuard decision.
        approval_result: Optional ApprovalGate result.
        evidence: Optional saved EvidenceRecord.
        return_code: Optional process return code.
        stdout: Captured standard output when available.
        stderr: Captured standard error when available.
        reason: Human-readable result reason.
        metadata: Optional structured result metadata.

    Returns:
        Immutable sandbox execution result.
    """

    outcome: SandboxOutcome
    allowed: bool
    session: MissionSession
    scope_decision: ScopeDecision
    approval_result: ApprovalGateResult | None = None
    evidence: EvidenceRecord | None = None
    return_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return compact sandbox result data.

        Returns:
            JSON-compatible sandbox result summary.
        """

        return {
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "session_id": self.session.session_id,
            "evidence_id": self.evidence.evidence_id if self.evidence else None,
            "return_code": self.return_code,
            "reason": self.reason,
            "metadata": self.metadata,
        }


@runtime_checkable
class SandboxRunner(Protocol):
    """Protocol for DockerRunner-compatible execution backends."""

    def run(self, command: list[str], **kwargs: Any) -> Any:
        """Run a command and return a command-result-like object.

        Args:
            command: Command and arguments to execute.
            kwargs: Runner-specific execution options.

        Returns:
            Runner-specific result object or mapping.
        """


class Sandbox:
    """Coordinate guarded command execution and evidence persistence.

    Args:
        scope_guard: ScopeGuard used to evaluate ToolRequest policy.
        approval_gate: ApprovalGate used for review-required requests.
        evidence_store: EvidenceStore used to persist command output.
        runner: DockerRunner or compatible execution backend.

    Returns:
        Sandbox instance.
    """

    def __init__(
        self,
        scope_guard: ScopeGuard,
        approval_gate: ApprovalGate,
        evidence_store: EvidenceStore,
        runner: SandboxRunner,
    ) -> None:
        """Initialize Sandbox dependencies.

        Args:
            scope_guard: Scope policy evaluator.
            approval_gate: Approval workflow manager.
            evidence_store: Evidence persistence layer.
            runner: Command execution backend.
        """

        self.scope_guard = scope_guard
        self.approval_gate = approval_gate
        self.evidence_store = evidence_store
        self.runner = runner

    def execute(self, request: SandboxExecutionRequest) -> SandboxExecutionResult:
        """Evaluate policy, run an allowed command, and save evidence.

        Args:
            request: Sandbox execution request.

        Returns:
            SandboxExecutionResult describing the outcome.
        """

        scope_decision = self.scope_guard.evaluate_tool_request(request.tool_request)
        if not scope_decision.allowed:
            approval_result = self.approval_gate.require_approval_for_decision(
                session=request.session,
                decision=scope_decision,
                request=request.tool_request,
                requested_by=request.requested_by,
            )
            if approval_result.outcome == ApprovalGateOutcome.WAITING_FOR_APPROVAL:
                return SandboxExecutionResult(
                    outcome=SandboxOutcome.WAITING_FOR_APPROVAL,
                    allowed=False,
                    session=approval_result.session,
                    scope_decision=scope_decision,
                    approval_result=approval_result,
                    reason=approval_result.reason,
                    metadata=request.metadata,
                )

            return SandboxExecutionResult(
                outcome=SandboxOutcome.DENIED,
                allowed=False,
                session=approval_result.session,
                scope_decision=scope_decision,
                approval_result=approval_result,
                reason=approval_result.reason,
                metadata=request.metadata,
            )

        started_at = datetime.now(UTC)
        try:
            runner_result = self.runner.run(
                request.command,
                image=request.image,
                working_directory=request.working_directory,
                environment=request.environment,
                timeout_seconds=request.timeout_seconds,
                **request.runner_options,
            )
        except Exception as exc:  # noqa: BLE001 - preserve runner failure as result data.
            finished_at = datetime.now(UTC)
            return SandboxExecutionResult(
                outcome=SandboxOutcome.RUNNER_FAILED,
                allowed=True,
                session=request.session,
                scope_decision=scope_decision,
                reason=f"Runner failed before returning a result: {exc}",
                metadata={
                    **request.metadata,
                    "error_type": type(exc).__name__,
                    "started_at": started_at.isoformat(),
                    "finished_at": finished_at.isoformat(),
                },
            )

        finished_at = self._result_datetime(runner_result, "finished_at") or datetime.now(UTC)
        actual_started_at = self._result_datetime(runner_result, "started_at") or started_at
        stdout = self._result_text(runner_result, "stdout")
        stderr = self._result_text(runner_result, "stderr")
        return_code = self._result_int(runner_result, "return_code", default=0)
        result_metadata = self._result_mapping(runner_result, "metadata")

        command_metadata = CommandMetadata(
            command=request.command,
            tool=request.tool_request.tool_name,
            return_code=return_code,
            started_at=actual_started_at,
            finished_at=finished_at,
            duration_seconds=max((finished_at - actual_started_at).total_seconds(), 0.0),
            sandboxed=True,
            working_directory=request.working_directory,
            environment_redacted=bool(request.environment),
        )

        try:
            evidence = self.evidence_store.save_command_output(
                title=request.evidence_title
                or f"{request.tool_request.tool_name}: {request.tool_request.action}",
                stdout=stdout,
                stderr=stderr,
                command=command_metadata,
                relative_dir=request.evidence_relative_dir,
                target=request.tool_request.target,
                tool_name=request.tool_request.tool_name,
                metadata={
                    **request.metadata,
                    "runner_metadata": result_metadata,
                    "image": request.image,
                    "timeout_seconds": request.timeout_seconds,
                },
            )
        except Exception as exc:  # noqa: BLE001 - preserve evidence failure as result data.
            return SandboxExecutionResult(
                outcome=SandboxOutcome.EVIDENCE_FAILED,
                allowed=True,
                session=request.session,
                scope_decision=scope_decision,
                return_code=return_code,
                stdout=stdout,
                stderr=stderr,
                reason=f"Command executed but evidence persistence failed: {exc}",
                metadata={
                    **request.metadata,
                    "runner_metadata": result_metadata,
                    "error_type": type(exc).__name__,
                },
            )

        updated_session = request.session.add_evidence(evidence)
        return SandboxExecutionResult(
            outcome=SandboxOutcome.EXECUTED,
            allowed=True,
            session=updated_session,
            scope_decision=scope_decision,
            evidence=evidence,
            return_code=return_code,
            stdout=stdout,
            stderr=stderr,
            reason="Command executed and evidence was saved.",
            metadata={
                **request.metadata,
                "runner_metadata": result_metadata,
                "image": request.image,
                "timeout_seconds": request.timeout_seconds,
            },
        )

    @staticmethod
    def _result_text(result: Any, key: str) -> str:
        """Read a string-like field from a runner result.

        Args:
            result: Runner result object or mapping.
            key: Field name to read.

        Returns:
            String value, or an empty string when missing.
        """

        value = Sandbox._result_value(result, key, default="")
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _result_int(result: Any, key: str, default: int) -> int:
        """Read an integer-like field from a runner result.

        Args:
            result: Runner result object or mapping.
            key: Field name to read.
            default: Default value when missing or invalid.

        Returns:
            Integer value.
        """

        value = Sandbox._result_value(result, key, default=default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _result_datetime(result: Any, key: str) -> datetime | None:
        """Read a datetime-like field from a runner result.

        Args:
            result: Runner result object or mapping.
            key: Field name to read.

        Returns:
            Datetime value when available, else None.
        """

        value = Sandbox._result_value(result, key, default=None)
        if isinstance(value, datetime):
            return value
        return None

    @staticmethod
    def _result_mapping(result: Any, key: str) -> dict[str, Any]:
        """Read a mapping-like field from a runner result.

        Args:
            result: Runner result object or mapping.
            key: Field name to read.

        Returns:
            Dictionary value, or an empty dictionary.
        """

        value = Sandbox._result_value(result, key, default={})
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _result_value(result: Any, key: str, default: Any) -> Any:
        """Read a value from an object or mapping.

        Args:
            result: Runner result object or mapping.
            key: Field name to read.
            default: Default value when missing.

        Returns:
            Field value or default.
        """

        if isinstance(result, dict):
            return result.get(key, default)
        return getattr(result, key, default)