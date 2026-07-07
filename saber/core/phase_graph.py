"""Mission phase transition logic for SABER.

This module defines PhaseGraph, the pure state-transition layer for SABER mission
phases. It knows which assessment phases can follow which other phases and how
to update MissionSession phase records safely.

PhaseGraph does not execute tools, save evidence, ask for approval, call Docker,
call an LLM, or decide target scope. Those responsibilities belong to agents, Sandbox, DockerRunner, and EvidenceStore.

Typical use:
    1. Mission asks PhaseGraph whether a phase can start.
    2. PhaseGraph returns a PhaseTransitionResult.
    3. Mission starts the phase if allowed.
    4. Runtime layers execute approved actions.
    5. Mission marks the phase completed, failed, skipped, or blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from datetime import UTC, datetime
from typing import Any

from saber.models.scope import AssessmentPhase, MissionScope
from saber.models.session import MissionSession, PhaseExecution, PhaseStatus


class PhaseTransitionOutcome(StrEnum):
    """Outcome of a requested phase transition.

    Values:
        ALLOWED: The transition is valid.
        DENIED: The transition is invalid.
        ALREADY_RUNNING: The requested phase is already running.
        ALREADY_COMPLETED: The requested phase is already completed.
        BLOCKED: The requested phase is blocked by phase state or scope policy.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    ALREADY_RUNNING = "already_running"
    ALREADY_COMPLETED = "already_completed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class PhaseTransitionResult:
    """Result returned by PhaseGraph transition checks.

    Args:
        outcome: High-level transition outcome.
        allowed: Whether the transition may proceed.
        phase: Requested phase.
        session: Mission session related to the result.
        reason: Human-readable result reason.
        metadata: Optional structured result metadata.

    Returns:
        Immutable phase transition result.
    """

    outcome: PhaseTransitionOutcome
    allowed: bool
    phase: AssessmentPhase
    session: MissionSession
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return compact transition result data.

        Returns:
            JSON-compatible summary dictionary.
        """

        return {
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "phase": self.phase.value,
            "session_id": self.session.session_id,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class PhaseGraph:
    """Validate and apply SABER mission phase transitions.

    Args:
        scope: Mission scope controlling which phases are allowed.
        transitions: Optional custom transition map. If omitted, SABER's default
            assessment phase graph is used.

    Returns:
        PhaseGraph instance.
    """

    DEFAULT_TRANSITIONS: dict[AssessmentPhase | None, set[AssessmentPhase]] = {
        None: {AssessmentPhase.RECON, AssessmentPhase.REPORTING},
        AssessmentPhase.RECON: {
            AssessmentPhase.WEB,
            AssessmentPhase.NETWORK,
            AssessmentPhase.ACTIVE_DIRECTORY,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.WEB: {
            AssessmentPhase.NETWORK,
            AssessmentPhase.ACTIVE_DIRECTORY,
            AssessmentPhase.EXPLOITATION,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.NETWORK: {
            AssessmentPhase.WEB,
            AssessmentPhase.ACTIVE_DIRECTORY,
            AssessmentPhase.EXPLOITATION,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.ACTIVE_DIRECTORY: {
            AssessmentPhase.EXPLOITATION,
            AssessmentPhase.PASSWORD_CRACKING,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.EXPLOITATION: {
            AssessmentPhase.POST_EXPLOITATION,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.POST_EXPLOITATION: {
            AssessmentPhase.PASSWORD_CRACKING,
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.PASSWORD_CRACKING: {
            AssessmentPhase.REPORTING,
        },
        AssessmentPhase.REPORTING: set(),
    }

    def __init__(
        self,
        scope: MissionScope,
        transitions: dict[AssessmentPhase | None, set[AssessmentPhase]] | None = None,
    ) -> None:
        """Initialize the phase graph.

        Args:
            scope: Mission scope controlling allowed phases.
            transitions: Optional custom transition map.
        """

        self.scope = scope
        self.transitions = self.DEFAULT_TRANSITIONS if transitions is None else transitions

    def can_start_phase(
        self,
        session: MissionSession,
        phase: AssessmentPhase,
    ) -> PhaseTransitionResult:
        """Return whether a phase can start for the given session.

        Args:
            session: Current mission session.
            phase: Requested phase to start.

        Returns:
            PhaseTransitionResult describing whether the phase can start.
        """

        existing = self.get_phase_execution(session, phase)
        if existing and existing.status == PhaseStatus.RUNNING:
            return PhaseTransitionResult(
                outcome=PhaseTransitionOutcome.ALREADY_RUNNING,
                allowed=False,
                phase=phase,
                session=session,
                reason=f"Phase {phase.value} is already running.",
            )

        if existing and existing.status == PhaseStatus.COMPLETED:
            return PhaseTransitionResult(
                outcome=PhaseTransitionOutcome.ALREADY_COMPLETED,
                allowed=False,
                phase=phase,
                session=session,
                reason=f"Phase {phase.value} is already completed.",
            )

        if existing and existing.status == PhaseStatus.BLOCKED:
            return PhaseTransitionResult(
                outcome=PhaseTransitionOutcome.BLOCKED,
                allowed=False,
                phase=phase,
                session=session,
                reason=f"Phase {phase.value} is blocked.",
            )

        if not self.scope.is_phase_allowed(phase):
            return PhaseTransitionResult(
                outcome=PhaseTransitionOutcome.BLOCKED,
                allowed=False,
                phase=phase,
                session=session,
                reason=f"Phase {phase.value} is not allowed by mission scope.",
                metadata={"blocked_by": "mission_scope"},
            )

        current_phase = self.current_phase(session)
        allowed_next = self.next_phases(current_phase)
        if phase not in allowed_next:
            return PhaseTransitionResult(
                outcome=PhaseTransitionOutcome.DENIED,
                allowed=False,
                phase=phase,
                session=session,
                reason=f"Cannot transition from {current_phase.value if current_phase else 'start'} to {phase.value}.",
                metadata={
                    "current_phase": current_phase.value if current_phase else None,
                    "allowed_next": [candidate.value for candidate in sorted(allowed_next, key=lambda item: item.value)],
                },
            )

        return PhaseTransitionResult(
            outcome=PhaseTransitionOutcome.ALLOWED,
            allowed=True,
            phase=phase,
            session=session,
            reason=f"Phase {phase.value} can start.",
            metadata={"current_phase": current_phase.value if current_phase else None},
        )

    def start_phase(self, session: MissionSession, phase: AssessmentPhase) -> MissionSession:
        """Start a phase and return an updated session.

        Args:
            session: Current mission session.
            phase: Phase to start.

        Returns:
            Updated MissionSession.

        Raises:
            ValueError: If the phase transition is not allowed.
        """

        decision = self.can_start_phase(session, phase)
        if not decision.allowed:
            raise ValueError(decision.reason)

        existing = self.get_phase_execution(session, phase)
        phase_execution = existing.mark_running() if existing else PhaseExecution(phase=phase).mark_running()
        return self._replace_phase_execution(session, phase_execution).model_copy(update={"current_phase": phase})

    def complete_phase(
        self,
        session: MissionSession,
        phase: AssessmentPhase,
        findings_count: int = 0,
        evidence_count: int = 0,
    ) -> MissionSession:
        """Mark a phase completed.

        Args:
            session: Current mission session.
            phase: Phase to complete.
            findings_count: Number of findings produced by the phase.
            evidence_count: Number of evidence records produced by the phase.

        Returns:
            Updated MissionSession.
        """

        phase_execution = self._existing_or_new_phase(session, phase).mark_completed().model_copy(
            update={
                "findings_count": findings_count,
                "evidence_count": evidence_count,
            }
        )
        return self._replace_phase_execution(session, phase_execution)

    def fail_phase(
        self,
        session: MissionSession,
        phase: AssessmentPhase,
        error_message: str,
    ) -> MissionSession:
        """Mark a phase failed.

        Args:
            session: Current mission session.
            phase: Phase to fail.
            error_message: Failure message.

        Returns:
            Updated MissionSession.
        """

        phase_execution = self._existing_or_new_phase(session, phase).mark_failed(error_message)
        return self._replace_phase_execution(session, phase_execution)

    def skip_phase(
        self,
        session: MissionSession,
        phase: AssessmentPhase,
        reason: str,
    ) -> MissionSession:
        """Mark a phase skipped.

        Args:
            session: Current mission session.
            phase: Phase to skip.
            reason: Skip reason.

        Returns:
            Updated MissionSession.
        """

        phase_execution = self._existing_or_new_phase(session, phase).model_copy(
            update={
                "status": PhaseStatus.SKIPPED,
                "finished_at": datetime.now(UTC),
                "error_message": reason,
            }
        )
        return self._replace_phase_execution(session, phase_execution)

    def block_phase(
        self,
        session: MissionSession,
        phase: AssessmentPhase,
        reason: str,
    ) -> MissionSession:
        """Mark a phase blocked.

        Args:
            session: Current mission session.
            phase: Phase to block.
            reason: Block reason.

        Returns:
            Updated MissionSession.
        """

        phase_execution = self._existing_or_new_phase(session, phase).model_copy(
            update={
                "status": PhaseStatus.BLOCKED,
                "finished_at": datetime.now(UTC),
                "error_message": reason,
            }
        )
        return self._replace_phase_execution(session, phase_execution)

    def available_next_phases(self, session: MissionSession) -> list[AssessmentPhase]:
        """Return scope-allowed phases that can follow the current phase.

        Args:
            session: Current mission session.

        Returns:
            Sorted list of available next phases.
        """

        current = self.current_phase(session)
        candidates = self.next_phases(current)
        allowed = [phase for phase in candidates if self.scope.is_phase_allowed(phase)]
        return sorted(allowed, key=lambda item: item.value)

    def next_phases(self, phase: AssessmentPhase | None) -> set[AssessmentPhase]:
        """Return phases that can follow a phase.

        Args:
            phase: Current phase, or None for mission start.

        Returns:
            Set of next allowed phases according to the graph.
        """

        return set(self.transitions.get(phase, set()))

    @staticmethod
    def current_phase(session: MissionSession) -> AssessmentPhase | None:
        """Return the session's current phase.

        Args:
            session: Mission session.

        Returns:
            Current phase or None.
        """

        return session.current_phase

    @staticmethod
    def get_phase_execution(
        session: MissionSession,
        phase: AssessmentPhase,
    ) -> PhaseExecution | None:
        """Return a phase execution record from a session.

        Args:
            session: Mission session to inspect.
            phase: Phase to find.

        Returns:
            Matching PhaseExecution, or None.
        """

        for phase_execution in session.phases:
            if phase_execution.phase == phase:
                return phase_execution
        return None

    def _existing_or_new_phase(self, session: MissionSession, phase: AssessmentPhase) -> PhaseExecution:
        """Return an existing phase execution or create a new one.

        Args:
            session: Mission session.
            phase: Phase to retrieve or create.

        Returns:
            PhaseExecution object.
        """

        return self.get_phase_execution(session, phase) or PhaseExecution(phase=phase)

    @staticmethod
    def _replace_phase_execution(
        session: MissionSession,
        phase_execution: PhaseExecution,
    ) -> MissionSession:
        """Replace or append a phase execution in a session.

        Args:
            session: Mission session to update.
            phase_execution: Phase execution to store.

        Returns:
            Updated MissionSession.
        """

        replaced = False
        phases: list[PhaseExecution] = []
        for existing in session.phases:
            if existing.phase == phase_execution.phase:
                phases.append(phase_execution)
                replaced = True
            else:
                phases.append(existing)
        if not replaced:
            phases.append(phase_execution)
        return session.model_copy(update={"phases": phases})