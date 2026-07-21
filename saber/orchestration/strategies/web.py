"""Web / URL target strategy."""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class WebStrategy(TargetStrategy):
    """Fingerprint -> nuclei -> safe web checks -> report."""

    kind = StrategyKind.WEB

    def seed_objective(self, target: Target) -> str:
        """Return the default fingerprint-and-report objective for a web target."""

        return f"Fingerprint {target.value}, run safe web vulnerability checks, and report."

    def objective_met(self, state: MissionState) -> bool:
        """Return True once technologies are fingerprinted and a web scan has run."""

        return bool(state.technologies) and bool(state.metadata.get("web_scanned"))
