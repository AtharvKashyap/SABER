"""Base agent abstractions for SABER.

Agents are the decision/orchestration layer. They consume mission context,
previous observations, and available tools, then produce structured actions.

Agents do not run shell commands directly. When an agent wants execution, it
creates an AgentToolCall and delegates to ToolRegistry + BaseToolWrapper +
Sandbox.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from saber.core.sandbox import Sandbox, SandboxExecutionResult
from saber.models.scope import AssessmentPhase
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.tools.registry import ToolRegistry


class AgentActionType(StrEnum):
    """High-level type of action an agent can request."""

    TOOL = "tool"
    HANDOFF = "handoff"
    ASK_APPROVAL = "ask_approval"
    STOP = "stop"


class AgentRunStatus(StrEnum):
    """Normalized status for an agent run."""

    COMPLETED = "completed"
    NEEDS_APPROVAL = "needs_approval"
    HANDOFF = "handoff"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(frozen=True)
class AgentConfig:
    """Configuration shared by SABER agents."""

    name: str
    phase: AssessmentPhase
    prompt_path: str | None = None
    description: str = ""
    default_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate config basics."""

        if not self.name.strip():
            raise ValueError("AgentConfig.name cannot be empty.")


@dataclass(frozen=True)
class AgentToolCall:
    """Structured request for a tool action."""

    tool_name: str
    action: str
    args: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    requires_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate tool call basics."""

        if not self.tool_name.strip():
            raise ValueError("AgentToolCall.tool_name cannot be empty.")
        if not self.action.strip():
            raise ValueError("AgentToolCall.action cannot be empty.")


@dataclass(frozen=True)
class AgentDecision:
    """Structured decision produced by an agent."""

    action_type: AgentActionType
    objective: str
    tool_call: AgentToolCall | None = None
    handoff_agent: str | None = None
    message: str = ""
    requires_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate decision consistency."""

        if not self.objective.strip():
            raise ValueError("AgentDecision.objective cannot be empty.")

        if self.action_type == AgentActionType.TOOL and self.tool_call is None:
            raise ValueError("TOOL decisions require tool_call.")

        if self.action_type == AgentActionType.HANDOFF and not self.handoff_agent:
            raise ValueError("HANDOFF decisions require handoff_agent.")


@dataclass(frozen=True)
class AgentObservation:
    """Observation emitted after a tool call or agent step."""

    summary: str
    tool_name: str | None = None
    action: str | None = None
    success: bool = True
    result: SandboxExecutionResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate observation basics."""

        if not self.summary.strip():
            raise ValueError("AgentObservation.summary cannot be empty.")


@dataclass(frozen=True)
class AgentContext:
    """Runtime context passed into agents."""

    session: MissionSession
    target: Target
    sandbox: Sandbox
    tool_registry: ToolRegistry
    objective: str = ""
    phase: AssessmentPhase | None = None
    observations: list[AgentObservation] = field(default_factory=list)
    constraints: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentRunResult:
    """Result returned by BaseAgent.run."""

    agent_name: str
    status: AgentRunStatus
    decision: AgentDecision
    observations: list[AgentObservation] = field(default_factory=list)
    result: SandboxExecutionResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible run result summary."""

        return {
            "agent_name": self.agent_name,
            "status": self.status.value,
            "decision": {
                "action_type": self.decision.action_type.value,
                "objective": self.decision.objective,
                "tool_name": self.decision.tool_call.tool_name if self.decision.tool_call else None,
                "tool_action": self.decision.tool_call.action if self.decision.tool_call else None,
                "handoff_agent": self.decision.handoff_agent,
                "message": self.decision.message,
                "requires_approval": self.decision.requires_approval,
                "metadata": self.decision.metadata,
            },
            "observations": [
                {
                    "summary": observation.summary,
                    "tool_name": observation.tool_name,
                    "action": observation.action,
                    "success": observation.success,
                    "metadata": observation.metadata,
                }
                for observation in self.observations
            ],
            "metadata": self.metadata,
        }


class BaseAgent(ABC):
    """Base class for SABER agents."""

    def __init__(self, config: AgentConfig) -> None:
        """Initialize base agent."""

        self.config = config

    @abstractmethod
    def decide(self, context: AgentContext) -> AgentDecision:
        """Produce the next structured decision for this agent."""

    def run(self, context: AgentContext) -> AgentRunResult:
        """Run one agent decision cycle."""

        self.validate_context(context)
        decision = self.decide(context)

        if decision.requires_approval or decision.action_type == AgentActionType.ASK_APPROVAL:
            return AgentRunResult(
                agent_name=self.config.name,
                status=AgentRunStatus.NEEDS_APPROVAL,
                decision=decision,
                observations=[],
                metadata={**self.config.default_metadata, "phase": self.config.phase.value},
            )

        if decision.action_type == AgentActionType.STOP:
            return AgentRunResult(
                agent_name=self.config.name,
                status=AgentRunStatus.STOPPED,
                decision=decision,
                observations=[],
                metadata={**self.config.default_metadata, "phase": self.config.phase.value},
            )

        if decision.action_type == AgentActionType.HANDOFF:
            return AgentRunResult(
                agent_name=self.config.name,
                status=AgentRunStatus.HANDOFF,
                decision=decision,
                observations=[
                    AgentObservation(
                        summary=decision.message or f"Hand off to {decision.handoff_agent}.",
                        metadata={"handoff_agent": decision.handoff_agent},
                    )
                ],
                metadata={**self.config.default_metadata, "phase": self.config.phase.value},
            )

        if decision.action_type == AgentActionType.TOOL:
            sandbox_result = self.execute_tool(context=context, tool_call=self.require_tool_call(decision))
            observation = AgentObservation(
                summary=sandbox_result.reason or "Tool execution completed.",
                tool_name=decision.tool_call.tool_name if decision.tool_call else None,
                action=decision.tool_call.action if decision.tool_call else None,
                success=sandbox_result.allowed and sandbox_result.return_code == 0,
                result=sandbox_result,
                metadata=sandbox_result.metadata,
            )

            return AgentRunResult(
                agent_name=self.config.name,
                status=AgentRunStatus.COMPLETED,
                decision=decision,
                observations=[observation],
                result=sandbox_result,
                metadata={**self.config.default_metadata, "phase": self.config.phase.value},
            )

        raise ValueError(f"Unsupported agent action type: {decision.action_type}")

    def execute_tool(self, context: AgentContext, tool_call: AgentToolCall) -> SandboxExecutionResult:
        """Execute a tool call through ToolRegistry and Sandbox."""

        wrapper = context.tool_registry.create(tool_call.tool_name, sandbox=context.sandbox)
        return wrapper.run(
            target=context.target,
            session=context.session,
            action=tool_call.action,
            **tool_call.args,
            metadata={
                "agent_name": self.config.name,
                "agent_phase": self.config.phase.value,
                "agent_reason": tool_call.reason,
                **tool_call.metadata,
            },
        )

    def load_prompt(self) -> str:
        """Load this agent's prompt text, if configured."""

        if not self.config.prompt_path:
            return ""

        path = Path(self.config.prompt_path)
        if not path.exists():
            raise FileNotFoundError(f"Agent prompt not found: {self.config.prompt_path}")

        return path.read_text()

    def validate_context(self, context: AgentContext) -> None:
        """Validate common runtime context."""

        if context.phase is not None and context.phase != self.config.phase:
            raise ValueError(
                f"Context phase {context.phase.value} does not match agent phase {self.config.phase.value}."
            )

    @staticmethod
    def require_tool_call(decision: AgentDecision) -> AgentToolCall:
        """Return decision.tool_call or raise."""

        if decision.tool_call is None:
            raise ValueError("Agent decision does not include a tool call.")
        return decision.tool_call

    def to_summary_dict(self) -> dict[str, Any]:
        """Return JSON-compatible agent summary."""

        return {
            "name": self.config.name,
            "phase": self.config.phase.value,
            "prompt_path": self.config.prompt_path,
            "description": self.config.description,
            "default_metadata": self.config.default_metadata,
        }
