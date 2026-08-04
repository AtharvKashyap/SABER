"""Deterministic PTES phase progression for the mission loop.

The decider chooses the next *action*; it does NOT choose what phase the mission is
in. Phase transitions are decided here, from what is actually present in
``MissionState``, for two reasons:

1. **Testability.** "Has recon achieved its goal?" is a question about state
   (are there hosts and services?), so it can be asserted in a unit test. If the
   model declared its own phase, progression would be unverifiable.
2. **Honesty.** A model cannot claim to have finished exploitation when state holds
   no session, credential or confirmed vuln. The gate is evidence-based.

The checker never skips: it advances at most one phase per evaluation, so a mission
that suddenly acquires a session still records that it passed through exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass

from saber.models.mission_state import MissionState, PtesPhase


@dataclass(frozen=True)
class PhaseDecision:
    """Whether the current phase's goal is met, and what follows."""

    goal_met: bool
    reason: str
    current_phase: PtesPhase
    next_phase: PtesPhase | None = None

    @property
    def should_advance(self) -> bool:
        """Return whether the loop should move to ``next_phase``."""

        return self.goal_met and self.next_phase is not None


class PhaseGoalChecker:
    """Decide, from state alone, whether a PTES phase's goal has been achieved."""

    def evaluate(self, state: MissionState) -> PhaseDecision:
        """Return the phase decision for the mission's current phase."""

        phase = state.current_phase
        goal_met, reason = self._goal_for(phase)(state)
        return PhaseDecision(
            goal_met=goal_met,
            reason=reason,
            current_phase=phase,
            next_phase=phase.next_phase() if goal_met else None,
        )

    def advance(self, state: MissionState) -> MissionState:
        """Return state moved to the next phase when the current goal is met.

        Immutable-by-copy, like every other MissionState mutation. Returns the same
        state object when the goal is not met or the mission is in the final phase.
        """

        decision = self.evaluate(state)
        if not decision.should_advance:
            return state
        return state.model_copy(update={"current_phase": decision.next_phase})

    def _goal_for(self, phase: PtesPhase):
        """Return the goal predicate for a phase."""

        return self._GOALS.get(phase, self._goal_unknown)

    # --- per-phase goals -------------------------------------------------------
    # Each returns (goal_met, human-readable reason). Reasons land in the report, so
    # they state the evidence, not just "done".

    @staticmethod
    def _goal_pre_engagement(state: MissionState) -> tuple[bool, str]:
        """Scope and objective must be settled before touching anything."""

        if state.scope is None:
            return False, "no scope defined yet"
        if not state.objective.strip():
            return False, "no objective defined yet"
        return True, "scope and objective are defined"

    @staticmethod
    def _goal_recon(state: MissionState) -> tuple[bool, str]:
        """Recon is done when we know a host AND something reachable on it."""

        if not state.hosts:
            return False, "no hosts discovered yet"
        if not state.services and not state.technologies:
            return False, f"{len(state.hosts)} host(s) but no services or technologies yet"
        return (
            True,
            f"{len(state.hosts)} host(s), {len(state.services)} service(s), "
            f"{len(state.technologies)} technology/ies discovered",
        )

    @staticmethod
    def _goal_vuln_assessment(state: MissionState) -> tuple[bool, str]:
        """Assessment is done once there is something worth trying to exploit."""

        if state.vulns:
            return True, f"{len(state.vulns)} vulnerability/ies identified"
        # Credentials found during enumeration are themselves an attack path.
        if state.credentials:
            return True, f"{len(state.credentials)} credential(s) available to try"
        return False, "no vulnerabilities or credentials identified yet"

    @staticmethod
    def _goal_exploitation(state: MissionState) -> tuple[bool, str]:
        """Exploitation succeeded only with a foothold or validated access."""

        if state.sessions:
            return True, f"{len(state.sessions)} session(s) established"
        if any(credential.validated for credential in state.credentials):
            return True, "validated credential(s) confirm access"
        if any(vuln.confirmed for vuln in state.vulns):
            return True, "confirmed exploitable vulnerability"
        return False, "no session, validated credential or confirmed vuln yet"

    @staticmethod
    def _goal_post_exploitation(state: MissionState) -> tuple[bool, str]:
        """Post-exploitation is done once the foothold has yielded something."""

        if state.loot:
            return True, f"{len(state.loot)} artifact(s) collected"
        if state.accounts or state.shares:
            return (
                True,
                f"{len(state.accounts)} account(s) and {len(state.shares)} share(s) enumerated",
            )
        return False, "foothold has not yielded loot, accounts or shares yet"

    @staticmethod
    def _goal_lateral_movement(state: MissionState) -> tuple[bool, str]:
        """Lateral movement means reach on more than one host."""

        session_hosts = {session.host for session in state.sessions}
        if len(session_hosts) > 1:
            return True, f"sessions on {len(session_hosts)} distinct hosts"
        # Credentials validated against a host we have no session on is also movement.
        validated_hosts = {
            credential.host
            for credential in state.credentials
            if credential.validated and credential.host
        }
        if validated_hosts - session_hosts:
            return True, "validated credentials reach a host beyond the current foothold"
        return False, f"reach is still limited to {len(session_hosts) or 0} host(s)"

    @staticmethod
    def _goal_proof_of_concept(state: MissionState) -> tuple[bool, str]:
        """The objective needs demonstrable proof, not just access."""

        if state.flags:
            return True, f"{len(state.flags)} flag(s) captured"
        if state.evidence_refs:
            return True, f"{len(state.evidence_refs)} evidence artifact(s) recorded"
        return False, "no flag or evidence captured to prove impact"

    @staticmethod
    def _goal_post_engagement(state: MissionState) -> tuple[bool, str]:
        """Terminal phase: reporting is the loop's finalize step, not a transition."""

        return False, "final phase; reporting is handled by mission finalization"

    @staticmethod
    def _goal_unknown(state: MissionState) -> tuple[bool, str]:
        """An unrecognized phase must never silently advance."""

        return False, f"no goal defined for phase {state.current_phase.value}"

    _GOALS = {
        PtesPhase.PRE_ENGAGEMENT: _goal_pre_engagement,
        PtesPhase.RECON: _goal_recon,
        PtesPhase.VULN_ASSESSMENT: _goal_vuln_assessment,
        PtesPhase.EXPLOITATION: _goal_exploitation,
        PtesPhase.POST_EXPLOITATION: _goal_post_exploitation,
        PtesPhase.LATERAL_MOVEMENT: _goal_lateral_movement,
        PtesPhase.PROOF_OF_CONCEPT: _goal_proof_of_concept,
        PtesPhase.POST_ENGAGEMENT: _goal_post_engagement,
    }
