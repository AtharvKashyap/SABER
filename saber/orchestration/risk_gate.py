"""Risk-gated autonomy for the mission loop.

Autonomous by default. Only high-risk/destructive actions pause for a human
confirmation. Out-of-scope actions are refused, never offered for confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState

EXPLOIT_CLASS = {"exploitation", "post_exploit", "lateral_movement"}


class GateDecision(StrEnum):
    """Outcome of the risk gate."""

    ALLOW = "allow"
    CONFIRM = "confirm"
    REFUSE = "refuse"


@dataclass(frozen=True)
class GateResult:
    """Gate decision with a human-readable reason."""

    decision: GateDecision
    reason: str


class RiskGate:
    """Decide whether an action may auto-run, needs confirmation, or is refused."""

    def __init__(self, tool_catalog: Any | None = None) -> None:
        """Initialize the gate with an optional ToolCatalog for category lookup."""

        self.tool_catalog = tool_catalog

    def evaluate(self, state: MissionState, action: ProposedAction) -> GateResult:
        """Return the gate decision for one proposed action."""

        if action.kind != ActionKind.TOOL:
            return GateResult(GateDecision.ALLOW, "non-tool action")

        if not self._scope_allows(state, action):
            return GateResult(GateDecision.REFUSE, "target or action is out of scope")

        category = self._category(action)
        exploit_class = category in EXPLOIT_CLASS

        if state.autonomy_level == AutonomyLevel.RECON_ONLY and exploit_class:
            return GateResult(GateDecision.REFUSE, "recon_only forbids exploit-class actions")

        if state.autonomy_level == AutonomyLevel.ASSISTED and (
            exploit_class or action.risk >= RiskLevel.MEDIUM
        ):
            return GateResult(GateDecision.CONFIRM, "assisted mode requires confirmation")

        if state.autonomy_level == AutonomyLevel.AUTONOMOUS and (
            action.risk == RiskLevel.HIGH or action.requires_confirmation
        ):
            return GateResult(GateDecision.CONFIRM, "high-risk action requires confirmation")

        return GateResult(GateDecision.ALLOW, "within autonomy budget")

    def _category(self, action: ProposedAction) -> str:
        category = str(action.metadata.get("category") or "").lower()
        if category:
            return category
        if self.tool_catalog is not None:
            for tool in getattr(self.tool_catalog, "tools", []):
                if tool.name == action.tool_name:
                    return str(getattr(tool, "category", "")).lower()
        return ""

    @staticmethod
    def _scope_allows(state: MissionState, action: ProposedAction) -> bool:
        scope = state.scope
        if scope is None:
            return True
        if scope.is_action_prohibited(f"{action.tool_name}.{action.tool_action}"):
            return False
        target_value = action.target.value if action.target else state.target.value
        allowed = set(scope.target_values())
        if not allowed:
            return True
        return target_value in allowed
