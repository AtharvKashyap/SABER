"""Mission session management for SABER.

This module defines SessionManager, the core state-management service for
MissionSession objects. The model layer in `saber.models.session` defines the
validated data contracts. This module provides convenient lifecycle operations
around those contracts.

SessionManager is intentionally not an execution layer. It does not run tools,
call Docker, decide scope, ask for approvals, write evidence files, parse tool
output, call an LLM, or generate reports. It only creates, stores, retrieves, and
updates MissionSession objects in memory.

Persistence to disk or a database can be added later behind the same API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from saber.models.evidence import EvidenceRecord
from saber.models.finding import Finding
from saber.models.scope import AssessmentPhase, MissionScope
from saber.models.session import ApprovalRequest, MissionSession, PhaseExecution, SessionStatus


class SessionManagerOutcome(StrEnum):
    """Outcome values returned by SessionManager operations.

    Values:
        CREATED: A session was created.
        UPDATED: A session was updated.
        FOUND: A session was found.
        NOT_FOUND: A session was not found.
        INVALID_STATE: The requested operation is invalid for the session state.
    """

    CREATED = "created"
    UPDATED = "updated"
    FOUND = "found"
    NOT_FOUND = "not_found"
    INVALID_STATE = "invalid_state"


@dataclass(frozen=True)
class SessionManagerResult:
    """Result returned by SessionManager operations.

    Args:
        outcome: Operation outcome.
        session: Session related to the result, if any.
        reason: Human-readable result reason.
        metadata: Optional structured result metadata.

    Returns:
        Immutable session manager result.
    """

    outcome: SessionManagerOutcome
    session: MissionSession | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        """Return whether this result contains a session.

        Returns:
            True when a session is present, else False.
        """

        return self.session is not None

    def to_summary_dict(self) -> dict[str, Any]:
        """Return compact result data.

        Returns:
            JSON-compatible result summary.
        """

        return {
            "outcome": self.outcome.value,
            "session_id": self.session.session_id if self.session else None,
            "status": self.session.status.value if self.session else None,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class SessionManager:
    """Manage MissionSession objects in memory.

    Args:
        sessions: Optional initial session list.

    Returns:
        SessionManager instance.
    """

    def __init__(self, sessions: list[MissionSession] | None = None) -> None:
        """Initialize the manager.

        Args:
            sessions: Optional initial sessions to register.
        """

        self._sessions: dict[str, MissionSession] = {}
        for session in sessions or []:
            self._sessions[session.session_id] = session

    def create_session(
        self,
        scope: MissionScope,
        session_id: str | None = None,
        mission_name: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> SessionManagerResult:
        """Create and register a new mission session.

        Args:
            scope: Mission scope associated with the session.
            session_id: Optional explicit session ID.
            mission_name: Optional override mission name.
            metadata: Optional structured session metadata.

        Returns:
            SessionManagerResult containing the created session.
        """

        resolved_session_id = session_id or f"session_{uuid4().hex}"
        if resolved_session_id in self._sessions:
            return SessionManagerResult(
                outcome=SessionManagerOutcome.INVALID_STATE,
                session=self._sessions[resolved_session_id],
                reason=f"Session already exists: {resolved_session_id}",
            )

        session = MissionSession(
            session_id=resolved_session_id,
            mission_name=mission_name or scope.mission_name,
            scope=scope,
            status=SessionStatus.CREATED,
            metadata=metadata or {},
        )
        self._sessions[session.session_id] = session
        return SessionManagerResult(
            outcome=SessionManagerOutcome.CREATED,
            session=session,
            reason="Session created.",
        )

    def register_session(self, session: MissionSession) -> SessionManagerResult:
        """Register or replace a session.

        Args:
            session: Session to register.

        Returns:
            SessionManagerResult containing the registered session.
        """

        self._sessions[session.session_id] = session
        return SessionManagerResult(
            outcome=SessionManagerOutcome.UPDATED,
            session=session,
            reason="Session registered.",
        )

    def get_session(self, session_id: str) -> SessionManagerResult:
        """Return a session by ID.

        Args:
            session_id: Session ID to retrieve.

        Returns:
            SessionManagerResult containing the found session or NOT_FOUND.
        """

        session = self._sessions.get(session_id)
        if session is None:
            return SessionManagerResult(
                outcome=SessionManagerOutcome.NOT_FOUND,
                reason=f"Session not found: {session_id}",
            )
        return SessionManagerResult(
            outcome=SessionManagerOutcome.FOUND,
            session=session,
            reason="Session found.",
        )

    def list_sessions(self) -> list[MissionSession]:
        """Return all managed sessions.

        Returns:
            Sessions in insertion order.
        """

        return list(self._sessions.values())

    def start_session(self, session_id: str) -> SessionManagerResult:
        """Start a session.

        Args:
            session_id: Session ID to start.

        Returns:
            SessionManagerResult containing the updated session.
        """

        return self._update_lifecycle(session_id, "start")

    def pause_session(self, session_id: str) -> SessionManagerResult:
        """Pause a session.

        Args:
            session_id: Session ID to pause.

        Returns:
            SessionManagerResult containing the updated session.
        """

        return self._update_lifecycle(session_id, "pause")

    def complete_session(self, session_id: str) -> SessionManagerResult:
        """Complete a session.

        Args:
            session_id: Session ID to complete.

        Returns:
            SessionManagerResult containing the updated session.
        """

        return self._update_lifecycle(session_id, "complete")

    def fail_session(self, session_id: str, reason: str) -> SessionManagerResult:
        """Fail a session.

        Args:
            session_id: Session ID to fail.
            reason: Failure reason.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        try:
            updated = result.session.fail(reason)
        except ValueError as exc:
            return SessionManagerResult(
                outcome=SessionManagerOutcome.INVALID_STATE,
                session=result.session,
                reason=str(exc),
            )
        return self._store_updated(updated, "Session failed.")

    def cancel_session(self, session_id: str) -> SessionManagerResult:
        """Cancel a session.

        Args:
            session_id: Session ID to cancel.

        Returns:
            SessionManagerResult containing the updated session.
        """

        return self._update_lifecycle(session_id, "cancel")

    def add_evidence(self, session_id: str, evidence: EvidenceRecord) -> SessionManagerResult:
        """Attach evidence to a session.

        Args:
            session_id: Session ID to update.
            evidence: EvidenceRecord to attach.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        updated = result.session.add_evidence(evidence)
        return self._store_updated(updated, "Evidence added to session.")

    def add_finding(self, session_id: str, finding: Finding) -> SessionManagerResult:
        """Attach a finding to a session.

        Args:
            session_id: Session ID to update.
            finding: Finding to attach.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        updated = result.session.add_finding(finding)
        return self._store_updated(updated, "Finding added to session.")

    def add_approval(self, session_id: str, approval: ApprovalRequest) -> SessionManagerResult:
        """Attach an approval request to a session.

        Args:
            session_id: Session ID to update.
            approval: ApprovalRequest to attach.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        updated = result.session.add_approval(approval)
        return self._store_updated(updated, "Approval added to session.")

    def add_phase(self, session_id: str, phase_execution: PhaseExecution) -> SessionManagerResult:
        """Attach a phase execution to a session.

        Args:
            session_id: Session ID to update.
            phase_execution: PhaseExecution to attach.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        updated = result.session.add_phase(phase_execution)
        return self._store_updated(updated, "Phase added to session.")

    def set_current_phase(
        self,
        session_id: str,
        phase: AssessmentPhase | None,
    ) -> SessionManagerResult:
        """Set the current phase on a session.

        Args:
            session_id: Session ID to update.
            phase: Current phase, or None.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        updated = result.session.model_copy(update={"current_phase": phase})
        return self._store_updated(updated, "Current phase updated.")

    def update_metadata(
        self,
        session_id: str,
        metadata: dict[str, Any],
        replace: bool = False,
    ) -> SessionManagerResult:
        """Update session metadata.

        Args:
            session_id: Session ID to update.
            metadata: Metadata to merge or replace.
            replace: Whether to replace existing metadata instead of merging.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result
        new_metadata = metadata if replace else {**result.session.metadata, **metadata}
        updated = result.session.model_copy(update={"metadata": new_metadata})
        return self._store_updated(updated, "Session metadata updated.")

    def delete_session(self, session_id: str) -> SessionManagerResult:
        """Delete a session from memory.

        Args:
            session_id: Session ID to delete.

        Returns:
            SessionManagerResult containing the deleted session or NOT_FOUND.
        """

        session = self._sessions.pop(session_id, None)
        if session is None:
            return SessionManagerResult(
                outcome=SessionManagerOutcome.NOT_FOUND,
                reason=f"Session not found: {session_id}",
            )
        return SessionManagerResult(
            outcome=SessionManagerOutcome.UPDATED,
            session=session,
            reason="Session deleted.",
        )

    def summary(self) -> dict[str, Any]:
        """Return a manager-level session summary.

        Returns:
            JSON-compatible summary dictionary.
        """

        sessions = self.list_sessions()
        status_counts: dict[str, int] = {}
        for session in sessions:
            status_counts[session.status.value] = status_counts.get(session.status.value, 0) + 1
        return {
            "session_count": len(sessions),
            "status_counts": status_counts,
            "session_ids": [session.session_id for session in sessions],
        }

    def _update_lifecycle(self, session_id: str, action: str) -> SessionManagerResult:
        """Apply a MissionSession lifecycle method.

        Args:
            session_id: Session ID to update.
            action: Lifecycle action name.

        Returns:
            SessionManagerResult containing the updated session.
        """

        result = self.get_session(session_id)
        if result.session is None:
            return result

        try:
            if action == "start":
                updated = result.session.start(datetime.now(UTC))
                message = "Session started."
            elif action == "pause":
                updated = result.session.pause()
                message = "Session paused."
            elif action == "complete":
                updated = result.session.complete(datetime.now(UTC))
                message = "Session completed."
            elif action == "cancel":
                updated = result.session.cancel(datetime.now(UTC))
                message = "Session cancelled."
            else:
                return SessionManagerResult(
                    outcome=SessionManagerOutcome.INVALID_STATE,
                    session=result.session,
                    reason=f"Unsupported lifecycle action: {action}",
                )
        except ValueError as exc:
            return SessionManagerResult(
                outcome=SessionManagerOutcome.INVALID_STATE,
                session=result.session,
                reason=str(exc),
            )

        return self._store_updated(updated, message)

    def _store_updated(self, session: MissionSession, reason: str) -> SessionManagerResult:
        """Store an updated session and return a result.

        Args:
            session: Updated session.
            reason: Result reason.

        Returns:
            SessionManagerResult containing the updated session.
        """

        self._sessions[session.session_id] = session
        return SessionManagerResult(
            outcome=SessionManagerOutcome.UPDATED,
            session=session,
            reason=reason,
        )
