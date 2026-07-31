"""Risk-gated autonomy for the mission loop.

Autonomous by default. Only high-risk/destructive actions pause for a human
confirmation. Out-of-scope actions are refused, never offered for confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AutonomyLevel, MissionState


def _scope_host(value: str) -> str:
    """Return the bare host/authority of a target value, lowercased.

    Used ONLY to decide that two spellings name the same host ("http://dvwa:80/x" and
    "dvwa"). Returns "" when no host can be determined, and the caller treats that as
    "not in scope" — fail closed, never open.
    """

    text = (value or "").strip().lower()
    if not text:
        return ""
    if "://" in text:
        host = urlsplit(text).hostname or ""
        return host
    # Strip a userinfo prefix and any port/path suffix from a bare authority.
    text = text.rsplit("@", 1)[-1]
    text = text.split("/", 1)[0]
    # Keep IPv6 literals intact; only strip a trailing :port from non-bracketed hosts.
    if not text.startswith("[") and text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text

EXPLOIT_CLASS = {"exploitation", "post_exploit", "post_exploitation", "lateral_movement"}


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
        if target_value in allowed:
            return True
        # Same host expressed differently must not be refused. Observed live: scope
        # held "http://dvwa" while the decider proposed the bare host "dvwa" for a
        # per-action target, and the exact string compare refused a perfectly in-scope
        # action — so the mission executed nothing and MissionState stayed empty.
        #
        # Deliberately narrow: this compares the HOST/authority only, so a genuinely
        # different host is still refused. It does NOT expand CIDR membership (an IP
        # inside an in-scope network is still refused) — widening a network range is a
        # real scope decision, not something to slip in through normalization.
        normalized = _scope_host(target_value)
        if not normalized:
            return False
        return any(_scope_host(candidate) == normalized for candidate in allowed)
