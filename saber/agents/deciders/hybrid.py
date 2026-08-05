"""Spend model tokens only on decisions that are actually decisions.

Early in a mission the next action is not a judgement call. With no services known
there is nothing to reason about: the only sensible move is to look. Asking a model
to conclude that costs a full prompt — measured at ~8k tokens, ~2.6k effective with
caching — and it returns the same answer the rule ladder would have given for free.

So the ladder handles FORCED moves and the model handles everything else. The rule
is deliberately one-directional: the ladder never overrides the model on a decision
where more than one action is defensible. It only answers where there is no real
choice, which is why ``_is_forced`` is a narrow allow-list of states rather than
"whatever the ladder happens to suggest".

Rungs three onward of the deterministic ladder (which scanner, which exploit query,
whether to skip ahead) are genuine judgement and go to the model. Anything else
would be dressing up token savings as reasoning.
"""

from __future__ import annotations

from dataclasses import replace

from saber.agents.deciders.base import ActionKind, NextActionDecider, ProposedAction
from saber.agents.deciders.deterministic import DeterministicDecider
from saber.core.state_summary import StateSummary
from saber.models.mission_state import MissionState

# Ports where an HTTP fingerprint is the obvious cheap next step.
_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443, 3000, 5000})


class HybridDecider(NextActionDecider):
    """Answer forced moves deterministically; ask the model for real decisions."""

    def __init__(
        self,
        llm_decider: NextActionDecider,
        deterministic: NextActionDecider | None = None,
    ) -> None:
        """Initialize with the model decider to defer to for genuine decisions."""

        self.llm_decider = llm_decider
        self.deterministic = deterministic or DeterministicDecider()

    def decide(self, state: MissionState, summary: StateSummary) -> ProposedAction:
        """Return the next action, using the ladder only where nothing is in doubt."""

        if self._is_forced(state):
            action = self.deterministic.decide(state, summary)
            # A forced state must still produce a runnable action. If the ladder has
            # nothing (already attempted, or it wants to stop), fall through to the
            # model rather than ending a mission on a technicality.
            if action.kind == ActionKind.TOOL:
                return replace(
                    action,
                    metadata={**action.metadata, "decided_by": "deterministic", "forced": True},
                )

        action = self.llm_decider.decide(state, summary)
        return replace(action, metadata={**action.metadata, "decided_by": "llm"})

    @staticmethod
    def _is_forced(state: MissionState) -> bool:
        """Return whether the next action is obvious enough to skip the model.

        Kept narrow on purpose. Each case has exactly one reasonable move, so the
        model would be paid to restate it.
        """

        # Nothing is known about the target yet. Any action other than looking would
        # be guessing, and every later decision depends on what a scan returns.
        if not state.services:
            return True

        # An open web port whose host has no recorded technology. Fingerprinting is
        # cheap, safe, and informs everything that follows, so there is no branch
        # worth reasoning over.
        fingerprinted = {tech.host for tech in state.technologies}
        for service in state.services:
            if service.port in _WEB_PORTS and service.host not in fingerprinted:
                return True

        return False


__all__ = ["HybridDecider"]
