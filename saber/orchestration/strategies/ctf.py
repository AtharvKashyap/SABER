"""CTF / SSH box strategy."""

from __future__ import annotations

from typing import Any

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class CtfStrategy(TargetStrategy):
    """Recon -> foothold -> creds/sessions -> post-exploit/lateral -> capture flag."""

    kind = StrategyKind.CTF

    def seed_objective(self, target: Target) -> str:
        """Return the default compromise-and-capture-the-flag objective."""

        return f"Compromise {target.value} and capture the flag."

    def initial_metadata(self, target: Target) -> dict[str, Any]:
        """Seed CTF metadata; ``lab=True`` marks the target as an owned lab."""

        return {"strategy": self.kind.value, "lab": True}

    def objective_met(self, state: MissionState) -> bool:
        """Return True once a flag is captured or credentials/loot are collected.

        Checks BOTH flag paths. ``state.metadata["flag"]`` is what the loop's own
        text detector writes; ``state.flags`` is what a parser emits as a canonical
        ``flag`` observation (strings, pwntools). Reading only metadata meant a flag
        captured by binary exploitation — the entire point of the pwntools path —
        did not count as meeting the objective, so the mission ran on to max_steps.
        """

        return bool(state.metadata.get("flag")) or bool(state.flags) or bool(state.credentials)
