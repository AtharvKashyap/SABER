

"""Base classes for SABER tool wrappers.

Tool wrappers translate high-level SABER actions into safe, structured execution
requests. A wrapper should not run shell commands directly. Instead, it should:

    1. Build a ToolRequest for ScopeGuard policy evaluation.
    2. Build a command list for the configured runner backend.
    3. Build a SandboxExecutionRequest.
    4. Delegate execution to Sandbox.
    5. Return the SandboxExecutionResult unchanged.

This keeps all safety controls centralized in ScopeGuard, ApprovalGate, Sandbox,
DockerRunner, and EvidenceStore.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionRequest, SandboxExecutionResult
from saber.core.scope_guard import RequestedActionCategory, ToolRequest
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target


@dataclass(frozen=True)
class ToolWrapperConfig:
    """Configuration shared by SABER tool wrappers.

    Args:
        tool_name: Stable internal tool name.
        image: Optional container image used by Docker-backed runners.
        phase: Assessment phase this wrapper usually belongs to.
        category: Tool action category used by ScopeGuard.
        requested_by: Component name recorded in approval requests.
        default_timeout_seconds: Default execution timeout.
        default_working_directory: Optional runner working directory.
        default_environment: Optional environment passed to the runner.
        default_runner_options: Optional runner-specific options.
        default_metadata: Optional metadata attached to generated requests.

    Returns:
        Immutable wrapper configuration.
    """

    tool_name: str
    image: str | None
    phase: AssessmentPhase
    category: RequestedActionCategory
    requested_by: str
    default_timeout_seconds: int = 300
    default_working_directory: str | None = None
    default_environment: dict[str, str] = field(default_factory=dict)
    default_runner_options: dict[str, Any] = field(default_factory=dict)
    default_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolCommand:
    """Command plan produced by a tool wrapper.

    Args:
        command: Command and arguments to execute.
        action: Stable action name for ScopeGuard and audit records.
        evidence_title: Human-readable evidence title.
        evidence_relative_dir: Directory below the EvidenceStore root.
        requires_explicit_authorization: Whether the action requires approval.
        timeout_seconds: Optional timeout override.
        working_directory: Optional working directory override.
        environment: Optional environment override or addition.
        runner_options: Optional runner-specific option override or addition.
        metadata: Optional structured metadata for the request.

    Returns:
        Immutable command plan.
    """

    command: list[str]
    action: str
    evidence_title: str
    evidence_relative_dir: str
    requires_explicit_authorization: bool = False
    timeout_seconds: int | None = None
    working_directory: str | None = None
    environment: dict[str, str] = field(default_factory=dict)
    runner_options: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate command plan basics.

        Raises:
            ValueError: If the command plan is unsafe or incomplete.
        """

        if not self.command:
            raise ValueError("ToolCommand.command cannot be empty.")
        if any(not part or "\x00" in part for part in self.command):
            raise ValueError("ToolCommand.command contains an empty or invalid argument.")
        if not self.action.strip():
            raise ValueError("ToolCommand.action cannot be empty.")
        if not self.evidence_title.strip():
            raise ValueError("ToolCommand.evidence_title cannot be empty.")
        if not self.evidence_relative_dir.strip():
            raise ValueError("ToolCommand.evidence_relative_dir cannot be empty.")


class BaseToolWrapper(ABC):
    """Base class for SABER tool wrappers.

    Args:
        sandbox: Sandbox used for guarded execution.
        config: Tool wrapper configuration.

    Returns:
        BaseToolWrapper subclass instance.
    """

    def __init__(self, sandbox: Sandbox, config: ToolWrapperConfig) -> None:
        """Initialize the wrapper.

        Args:
            sandbox: Sandbox dependency.
            config: Wrapper configuration.
        """

        self.sandbox = sandbox
        self.config = config

    @abstractmethod
    def build_command(self, target: Target, **kwargs: Any) -> ToolCommand:
        """Build a command plan for a target.

        Args:
            target: Target the tool will operate on.
            kwargs: Wrapper-specific command options.

        Returns:
            ToolCommand describing the planned execution.
        """

    def build_tool_request(self, target: Target, command: ToolCommand) -> ToolRequest:
        """Build a ToolRequest for ScopeGuard.

        Args:
            target: Target the tool will operate on.
            command: Tool command plan.

        Returns:
            ToolRequest for policy evaluation.
        """

        return ToolRequest(
            tool_name=self.config.tool_name,
            action=command.action,
            phase=self.config.phase,
            target=target,
            category=self.config.category,
            requires_explicit_authorization=command.requires_explicit_authorization,
            metadata={
                **self.config.default_metadata,
                **command.metadata,
            },
        )

    def build_execution_request(
        self,
        target: Target,
        session: MissionSession,
        **kwargs: Any,
    ) -> SandboxExecutionRequest:
        """Build a SandboxExecutionRequest for a target.

        Args:
            target: Target the tool will operate on.
            session: Current mission session.
            kwargs: Wrapper-specific command options.

        Returns:
            SandboxExecutionRequest ready for Sandbox.
        """

        command = self.build_command(target, **kwargs)
        self.validate_command(command)
        tool_request = self.build_tool_request(target=target, command=command)
        return SandboxExecutionRequest(
            tool_request=tool_request,
            command=command.command,
            session=session,
            requested_by=self.config.requested_by,
            image=self.config.image,
            working_directory=command.working_directory or self.config.default_working_directory,
            environment={
                **self.config.default_environment,
                **command.environment,
            },
            timeout_seconds=command.timeout_seconds or self.config.default_timeout_seconds,
            evidence_title=command.evidence_title,
            evidence_relative_dir=command.evidence_relative_dir,
            runner_options={
                **self.config.default_runner_options,
                **command.runner_options,
            },
            metadata={
                **self.config.default_metadata,
                **command.metadata,
            },
        )

    def run(self, target: Target, session: MissionSession, **kwargs: Any) -> SandboxExecutionResult:
        """Execute a wrapper action through Sandbox.

        Args:
            target: Target the tool will operate on.
            session: Current mission session.
            kwargs: Wrapper-specific command options.

        Returns:
            SandboxExecutionResult returned by Sandbox.
        """

        request = self.build_execution_request(target=target, session=session, **kwargs)
        return self.sandbox.execute(request)

    def validate_command(self, command: ToolCommand) -> None:
        """Validate a command plan before SandboxExecutionRequest creation.

        Subclasses can override this method to block unsafe flag combinations.

        Args:
            command: Tool command plan to validate.

        Raises:
            ValueError: If the command should not be built.
        """

        if command.command[0].startswith("-"):
            raise ValueError("Tool command executable cannot start with '-'.")

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact wrapper summary.

        Returns:
            JSON-compatible wrapper summary.
        """

        return {
            "tool_name": self.config.tool_name,
            "image": self.config.image,
            "phase": self.config.phase.value,
            "category": self.config.category.value,
            "requested_by": self.config.requested_by,
            "default_timeout_seconds": self.config.default_timeout_seconds,
            "default_working_directory": self.config.default_working_directory,
            "default_runner_options": self.config.default_runner_options,
            "default_metadata": self.config.default_metadata,
        }