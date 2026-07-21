"""CTF / lab target strategy.

Thin stub: only the pieces the selector in ``base.py`` needs to import and
construct. Fleshed out in Task 16.
"""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class CtfStrategy(TargetStrategy):
    """CTF / lab strategy (thin stub pending Task 16)."""

    kind = StrategyKind.CTF

    def seed_objective(self, target: Target) -> str:
        """Return the default capture-the-flag objective for a CTF target."""

        return f"Capture the flag on {target.value} and report the path taken."

    def objective_met(self, state: MissionState) -> bool:
        """Stub: never signals completion until Task 16 defines the criteria."""

        return False
