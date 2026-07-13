"""Structured LLM decisions for SABER agents."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.core.tool_catalog import ToolActionSpec, ToolCatalog


class LlmDecisionType(StrEnum):
    """Allowed LLM decision types."""

    RUN_TOOL = "run_tool"
    REQUEST_APPROVAL = "request_approval"
    HANDOFF = "handoff"
    REPORT = "report"
    STOP = "stop"


class LlmDecisionRisk(StrEnum):
    """Decision risk."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class LlmDecision:
    """Validated structured agent decision."""

    decision: LlmDecisionType
    agent: str
    tool_name: str | None = None
    tool_action: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    requires_approval: bool = False
    risk: LlmDecisionRisk = LlmDecisionRisk.LOW
    reason: str = ""
    expected_evidence: str = ""
    handoff_agent: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LlmDecision":
        """Build decision from LLM JSON."""

        return cls(
            decision=LlmDecisionType(str(data.get("decision", "")).strip()),
            agent=str(data.get("agent", "")).strip(),
            tool_name=_optional_str(data.get("tool_name")),
            tool_action=_optional_str(data.get("tool_action")),
            args=data.get("args") if isinstance(data.get("args"), dict) else {},
            requires_approval=bool(data.get("requires_approval", False)),
            risk=LlmDecisionRisk(str(data.get("risk", "low")).strip().lower()),
            reason=str(data.get("reason", "")).strip(),
            expected_evidence=str(data.get("expected_evidence", "")).strip(),
            handoff_agent=_optional_str(data.get("handoff_agent")),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible dict."""

        return {
            "decision": self.decision.value,
            "agent": self.agent,
            "tool_name": self.tool_name,
            "tool_action": self.tool_action,
            "args": self.args,
            "requires_approval": self.requires_approval,
            "risk": self.risk.value,
            "reason": self.reason,
            "expected_evidence": self.expected_evidence,
            "handoff_agent": self.handoff_agent,
        }


@dataclass(frozen=True)
class LlmDecisionValidationResult:
    """Validation result."""

    valid: bool
    errors: list[str] = field(default_factory=list)
    action_spec: ToolActionSpec | None = None
    normalized_requires_approval: bool = False

    def raise_if_invalid(self) -> None:
        """Raise ValueError if invalid."""

        if not self.valid:
            raise ValueError("; ".join(self.errors))


class LlmDecisionValidator:
    """Validates LLM decisions against the real ToolCatalog."""

    def __init__(self, tool_catalog: ToolCatalog) -> None:
        self.tool_catalog = tool_catalog

    def validate(self, decision: LlmDecision) -> LlmDecisionValidationResult:
        """Validate a decision."""

        errors: list[str] = []

        if not decision.agent:
            errors.append("agent is required")

        if decision.decision == LlmDecisionType.RUN_TOOL:
            action_spec = self._find_action(decision.tool_name, decision.tool_action)

            if action_spec is None:
                errors.append(f"unknown tool/action: {decision.tool_name}/{decision.tool_action}")
                return LlmDecisionValidationResult(valid=False, errors=errors)

            normalized_requires_approval = action_spec.requires_approval or decision.requires_approval

            return LlmDecisionValidationResult(
                valid=not errors,
                errors=errors,
                action_spec=action_spec,
                normalized_requires_approval=normalized_requires_approval,
            )

        if decision.decision == LlmDecisionType.REQUEST_APPROVAL:
            if not decision.reason:
                errors.append("request_approval requires reason")
            if not decision.tool_name or not decision.tool_action:
                errors.append("request_approval requires tool_name and tool_action")

            action_spec = self._find_action(decision.tool_name, decision.tool_action)
            if action_spec is None:
                errors.append(f"unknown tool/action: {decision.tool_name}/{decision.tool_action}")

            return LlmDecisionValidationResult(
                valid=not errors,
                errors=errors,
                action_spec=action_spec,
                normalized_requires_approval=True,
            )

        if decision.decision == LlmDecisionType.HANDOFF:
            if not decision.handoff_agent:
                errors.append("handoff requires handoff_agent")

        return LlmDecisionValidationResult(valid=not errors, errors=errors)

    def _find_action(self, tool_name: str | None, tool_action: str | None) -> ToolActionSpec | None:
        """Find a catalog action."""

        if not tool_name or not tool_action:
            return None

        for tool in self.tool_catalog.tools:
            if tool.name != tool_name:
                continue
            for action in tool.actions:
                if action.action == tool_action:
                    return action

        return None


def _optional_str(value: Any) -> str | None:
    """Return string or None."""

    if value is None:
        return None

    text = str(value).strip()
    if not text or text.lower() == "null":
        return None

    return text
