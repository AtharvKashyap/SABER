"""Web / URL target strategy.

Thin stub: only the pieces the selector in ``base.py`` needs to import and
construct. Fleshed out in Task 15.
"""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class WebStrategy(TargetStrategy):
    """Web application strategy (thin stub pending Task 15)."""

    kind = StrategyKind.WEB

    def seed_objective(self, target: Target) -> str:
        """Return the default assess-and-report objective for a web target."""

        return f"Assess the web application at {target.value} and report findings."

    def objective_met(self, state: MissionState) -> bool:
        """Stub: never signals completion until Task 15 defines the criteria."""

        return False
