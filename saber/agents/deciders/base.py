"""Decider abstractions for the SABER mission loop."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

from saber.core.state_summary import StateSummary
from saber.models.mission_state import MissionState
from saber.models.target import Target


class RiskLevel(IntEnum):
    """Ordered risk level (LOW < MEDIUM < HIGH)."""

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @classmethod
    def from_str(cls, value: str | None) -> RiskLevel:
        """Parse a risk string, defaulting to LOW."""

        return {"low": cls.LOW, "medium": cls.MEDIUM, "high": cls.HIGH}.get(
            str(value or "").strip().lower(), cls.LOW
        )

    @property
    def label(self) -> str:
        """Return the lowercase label."""

        return self.name.lower()


class ActionKind(StrEnum):
    """What the decider wants the loop to do next."""

    TOOL = "tool"
    STOP = "stop"
    REPORT = "report"


@dataclass(frozen=True)
class ProposedAction:
    """A single next action proposed by a decider."""

    kind: ActionKind
    objective: str
    risk: RiskLevel = RiskLevel.LOW
    tool_name: str | None = None
    tool_action: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    agent_name: str | None = None
    target: Target | None = None
    rationale: str = ""
    expected_evidence: str = ""
    requires_confirmation: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate proposed-action consistency."""

        if not self.objective.strip():
            raise ValueError("ProposedAction.objective cannot be empty.")
        if self.kind == ActionKind.TOOL and not (self.tool_name and self.tool_action):
            raise ValueError("TOOL actions require tool_name and tool_action.")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible dict."""

        return {
            "kind": self.kind.value,
            "objective": self.objective,
            "risk": self.risk.label,
            "tool_name": self.tool_name,
            "tool_action": self.tool_action,
            "args": self.args,
            "agent_name": self.agent_name,
            "target": self.target.to_agent_dict() if self.target else None,
            "rationale": self.rationale,
            "expected_evidence": self.expected_evidence,
            "requires_confirmation": self.requires_confirmation,
            "metadata": self.metadata,
        }


class NextActionDecider(ABC):
    """Interface for choosing the next mission action."""

    @abstractmethod
    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the single best next action for the current state."""
