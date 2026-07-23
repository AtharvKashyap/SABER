"""Per-target-type strategies that seed the mission loop."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from saber.models.mission_state import MissionState
from saber.models.target import Target, TargetType


class StrategyKind(StrEnum):
    """Kind of target strategy."""

    NETWORK = "network"
    WEB = "web"
    CTF = "ctf"


class TargetStrategy(ABC):
    """Seed objective/metadata and define objective-met for one target type."""

    kind: StrategyKind

    @abstractmethod
    def seed_objective(self, target: Target) -> str:
        """Return the default objective for this target."""

    def initial_metadata(self, target: Target) -> dict[str, Any]:
        """Return metadata seeded onto MissionState (strategy hints)."""

        return {"strategy": self.kind.value}

    @abstractmethod
    def objective_met(self, state: MissionState) -> bool:
        """Return whether the mission objective is satisfied."""


def select_strategy(target: Target, metadata: dict[str, Any] | None = None) -> TargetStrategy:
    """Pick the right strategy for a target.

    Precedence: an explicit ``metadata["strategy_override"]`` in
    {"network","web","ctf"} wins; then ``ctf``/``lab`` metadata selects CTF;
    then the target type is auto-detected.
    """

    from saber.orchestration.strategies.ctf import CtfStrategy
    from saber.orchestration.strategies.network import NetworkStrategy
    from saber.orchestration.strategies.web import WebStrategy

    metadata = metadata or {}

    override = str(metadata.get("strategy_override") or "").strip().lower()
    if override == "ctf":
        return CtfStrategy()
    if override == "web":
        return WebStrategy()
    if override == "network":
        return NetworkStrategy()

    if metadata.get("ctf") or metadata.get("lab"):
        return CtfStrategy()
    if target.type == TargetType.URL or target.is_web_target:
        return WebStrategy()
    return NetworkStrategy()
