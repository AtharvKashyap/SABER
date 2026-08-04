"""Network / IP host strategy."""

from __future__ import annotations

from saber.models.mission_state import MissionState
from saber.models.target import Target
from saber.orchestration.strategies.base import StrategyKind, TargetStrategy


class NetworkStrategy(TargetStrategy):
    """Recon -> services -> web/network/exploit-intel branches."""

    kind = StrategyKind.NETWORK

    def seed_objective(self, target: Target) -> str:
        """Return the default enumerate-and-report objective for a network host."""

        return f"Enumerate {target.value}, identify services and known vulnerabilities, and report."

    def objective_met(self, state: MissionState) -> bool:
        """Return True once vulnerabilities are known and exploit intel is gathered."""

        return bool(state.vulns) and bool(state.metadata.get("exploit_intel_done"))
