"""Stop-condition evaluation for the mission loop."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from saber.agents.deciders.base import ActionKind, ProposedAction
from saber.models.mission_state import MissionState


@dataclass(frozen=True)
class StopDecision:
    """Whether the loop should stop, and why."""

    should_stop: bool
    reason: str


class StopEvaluator:
    """Evaluate when the mission loop should terminate."""

    def __init__(self, max_steps: int = 50, max_repeat_failures: int = 3) -> None:
        """Initialize evaluator."""

        self.max_steps = max_steps
        self.max_repeat_failures = max_repeat_failures

    def evaluate(self, state: MissionState, last_action: ProposedAction | None) -> StopDecision:
        """Return the stop decision given current state and the last action."""

        if state.objective_met:
            return StopDecision(True, "objective met")

        if last_action is not None and last_action.kind in {ActionKind.STOP, ActionKind.REPORT}:
            return StopDecision(True, f"decider requested {last_action.kind.value}")

        if state.step_count >= self.max_steps:
            return StopDecision(True, f"reached max_steps ({self.max_steps})")

        failures = Counter(action.signature for action in state.failed_actions)
        for signature, count in failures.items():
            if count >= self.max_repeat_failures:
                return StopDecision(True, f"repeated failure ({count}x): {signature}")

        return StopDecision(False, "continue")
