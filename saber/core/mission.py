

"""Mission orchestration for SABER.

This module defines MissionController, the high-level coordinator for a SABER
mission. It wires together session lifecycle, phase transitions, sandboxed tool
execution, evidence attachment, finding attachment, and mission summaries.

MissionController does not parse tool output into findings, implement Docker,
write evidence files directly, render reports, call an LLM, or contain
exploit/tool-specific logic. Those responsibilities belong to tool wrappers,
DockerRunner, EvidenceStore, report generators, parsers, and agent layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from saber.core.phase_graph import PhaseGraph, PhaseTransitionResult
from saber.core.sandbox import Sandbox, SandboxExecutionRequest, SandboxExecutionResult, SandboxOutcome
from saber.core.session import SessionManager, SessionManagerOutcome, SessionManagerResult
from saber.models.evidence import EvidenceRecord
from saber.models.finding import Finding
from saber.models.scope import AssessmentPhase, MissionScope
from saber.models.session import ApprovalRequest, MissionSession
from saber.tools.capability import ToolRequest


class MissionOutcome(StrEnum):
    """High-level mission operation outcomes.

    Values:
        CREATED: A mission session was created.
        UPDATED: Mission state was updated.
        ALLOWED: A request was accepted for continuation.
        DENIED: A phase transition or operation was denied.
        EXECUTED: A sandbox request executed and produced evidence.
        RUNNER_FAILED: Sandbox runner failed before returning a result.
        EVIDENCE_FAILED: Sandbox execution finished but evidence persistence failed.
        NOT_FOUND: The mission session was not found.
        INVALID_STATE: The requested operation was invalid.
    """

    CREATED = "created"
    UPDATED = "updated"
    ALLOWED = "allowed"
    DENIED = "denied"
    EXECUTED = "executed"
    RUNNER_FAILED = "runner_failed"
    EVIDENCE_FAILED = "evidence_failed"
    NOT_FOUND = "not_found"
    INVALID_STATE = "invalid_state"


@dataclass(frozen=True)
class MissionResult:
    """Result returned by MissionController operations.

    Args:
        outcome: High-level mission outcome.
        session: Mission session related to the operation, if available.
        phase_result: Optional phase transition result.
        sandbox_result: Optional sandbox execution result.
        evidence: Optional evidence record produced or attached.
        finding: Optional finding produced or attached.
        reason: Human-readable result reason.
        metadata: Optional structured result metadata.

    Returns:
        Immutable mission result.
    """

    outcome: MissionOutcome
    session: MissionSession | None = None
    phase_result: PhaseTransitionResult | None = None
    sandbox_result: SandboxExecutionResult | None = None
    evidence: EvidenceRecord | None = None
    finding: Finding | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        """Return whether this mission result allows continuation.

        Returns:
            True for allowed, executed, created, or updated outcomes.
        """

        return self.outcome in {
            MissionOutcome.ALLOWED,
            MissionOutcome.EXECUTED,
            MissionOutcome.CREATED,
            MissionOutcome.UPDATED,
        }

    def to_summary_dict(self) -> dict[str, Any]:
        """Return compact mission result data.

        Returns:
            JSON-compatible mission result summary.
        """

        return {
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "session_id": self.session.session_id if self.session else None,
            "session_status": self.session.status.value if self.session else None,
            "evidence_id": self.evidence.evidence_id if self.evidence else None,
            "finding_id": self.finding.finding_id if self.finding else None,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class MissionController:
    """Coordinate a SABER mission across core runtime services.

    Args:
        scope: Mission scope.
        session_manager: SessionManager used to track sessions.
        phase_graph: PhaseGraph used for phase transitions.
        sandbox: Optional Sandbox used for command execution.
        session: Optional existing mission session to control.

    Returns:
        MissionController instance.
    """

    def __init__(
        self,
        scope: MissionScope,
        session_manager: SessionManager,
        phase_graph: PhaseGraph,
        sandbox: Sandbox | None = None,
        session: MissionSession | None = None,
    ) -> None:
        """Initialize the mission controller.

        Args:
            scope: Mission scope.
            session_manager: Session manager dependency.
            phase_graph: Phase graph dependency.
            sandbox: Optional sandbox dependency.
            session: Optional existing mission session.
        """

        self.scope = scope
        self.session_manager = session_manager
        self.phase_graph = phase_graph
        self.sandbox = sandbox
        self._session_id: str | None = None

        if session is not None:
            self.session_manager.register_session(session)
            self._session_id = session.session_id

    @property
    def session_id(self) -> str | None:
        """Return the controlled session ID.

        Returns:
            Session ID, or None when no session has been created or attached.
        """

        return self._session_id

    def create(self, session_id: str | None = None, metadata: dict[str, Any] | None = None) -> MissionResult:
        """Create and register a mission session.

        Args:
            session_id: Optional explicit session ID.
            metadata: Optional session metadata.

        Returns:
            MissionResult containing the created session.
        """

        result = self.session_manager.create_session(
            scope=self.scope,
            session_id=session_id,
            mission_name=self.scope.mission_name,
            metadata=metadata,
        )
        if result.session is not None and result.outcome == SessionManagerOutcome.CREATED:
            self._session_id = result.session.session_id
            return self._from_session_result(MissionOutcome.CREATED, result)
        return self._from_session_result(MissionOutcome.INVALID_STATE, result)

    def attach(self, session: MissionSession) -> MissionResult:
        """Attach an existing session to this controller.

        Args:
            session: Existing mission session.

        Returns:
            MissionResult containing the attached session.
        """

        result = self.session_manager.register_session(session)
        self._session_id = session.session_id
        return self._from_session_result(MissionOutcome.UPDATED, result)

    def current_session(self) -> MissionSession | None:
        """Return the currently controlled session.

        Returns:
            MissionSession when available, else None.
        """

        if self._session_id is None:
            return None
        return self.session_manager.get_session(self._session_id).session

    def start(self) -> MissionResult:
        """Start the mission session.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.start_session(session.session_id)
        return self._from_session_result(self._map_session_result(result), result)

    def pause(self) -> MissionResult:
        """Pause the mission session.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.pause_session(session.session_id)
        return self._from_session_result(self._map_session_result(result), result)

    def complete(self) -> MissionResult:
        """Complete the mission session.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.complete_session(session.session_id)
        return self._from_session_result(self._map_session_result(result), result)

    def fail(self, reason: str) -> MissionResult:
        """Fail the mission session.

        Args:
            reason: Failure reason.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.fail_session(session.session_id, reason)
        return self._from_session_result(self._map_session_result(result), result)

    def cancel(self) -> MissionResult:
        """Cancel the mission session.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.cancel_session(session.session_id)
        return self._from_session_result(self._map_session_result(result), result)

    def can_start_phase(self, phase: AssessmentPhase) -> MissionResult:
        """Check whether a phase can start.

        Args:
            phase: Phase to check.

        Returns:
            MissionResult containing the phase transition decision.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        phase_result = self.phase_graph.can_start_phase(session, phase)
        outcome = MissionOutcome.ALLOWED if phase_result.allowed else MissionOutcome.DENIED
        return MissionResult(
            outcome=outcome,
            session=session,
            phase_result=phase_result,
            reason=phase_result.reason,
            metadata=phase_result.metadata,
        )

    def start_phase(self, phase: AssessmentPhase) -> MissionResult:
        """Start a mission phase.

        Args:
            phase: Phase to start.

        Returns:
            MissionResult containing the updated session or denial reason.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        phase_result = self.phase_graph.can_start_phase(session, phase)
        if not phase_result.allowed:
            return MissionResult(
                outcome=MissionOutcome.DENIED,
                session=session,
                phase_result=phase_result,
                reason=phase_result.reason,
                metadata=phase_result.metadata,
            )
        updated = self.phase_graph.start_phase(session, phase)
        store_result = self.session_manager.register_session(updated)
        return MissionResult(
            outcome=MissionOutcome.UPDATED,
            session=store_result.session,
            phase_result=phase_result,
            reason=f"Phase {phase.value} started.",
        )

    def complete_phase(
        self,
        phase: AssessmentPhase,
        findings_count: int = 0,
        evidence_count: int = 0,
    ) -> MissionResult:
        """Complete a mission phase.

        Args:
            phase: Phase to complete.
            findings_count: Number of findings produced.
            evidence_count: Number of evidence records produced.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        updated = self.phase_graph.complete_phase(
            session=session,
            phase=phase,
            findings_count=findings_count,
            evidence_count=evidence_count,
        )
        store_result = self.session_manager.register_session(updated)
        return MissionResult(
            outcome=MissionOutcome.UPDATED,
            session=store_result.session,
            reason=f"Phase {phase.value} completed.",
        )

    def fail_phase(self, phase: AssessmentPhase, error_message: str) -> MissionResult:
        """Fail a mission phase.

        Args:
            phase: Phase to fail.
            error_message: Failure message.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        updated = self.phase_graph.fail_phase(session=session, phase=phase, error_message=error_message)
        store_result = self.session_manager.register_session(updated)
        return MissionResult(
            outcome=MissionOutcome.UPDATED,
            session=store_result.session,
            reason=f"Phase {phase.value} failed.",
        )

    def evaluate_request(self, request: ToolRequest, requested_by: str) -> MissionResult:
        """Record that a tool request is accepted by mission control.

        MissionController no longer performs heavyweight scope or approval checks.
        Tool wrappers and operators can still use the request metadata for audit,
        routing, and reporting.

        Args:
            request: ToolRequest to record.
            requested_by: Component or wrapper requesting evaluation.

        Returns:
            MissionResult describing the accepted request.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        return MissionResult(
            outcome=MissionOutcome.ALLOWED,
            session=session,
            reason=f"Tool request accepted: {request.tool_name}.{request.action}",
            metadata={
                "requested_by": requested_by,
                "tool_name": request.tool_name,
                "tool_action": request.action,
                "tool_category": request.category.value,
                "requires_explicit_authorization": request.requires_explicit_authorization,
                **request.metadata,
            },
        )

    def execute(self, request: SandboxExecutionRequest) -> MissionResult:
        """Execute a sandbox request through the configured Sandbox.

        Args:
            request: Sandbox execution request.

        Returns:
            MissionResult containing sandbox execution state.
        """

        if self.sandbox is None:
            return MissionResult(
                outcome=MissionOutcome.INVALID_STATE,
                session=self.current_session(),
                reason="MissionController has no Sandbox configured.",
            )

        result = self.sandbox.execute(request)
        self.session_manager.register_session(result.session)

        if result.outcome == SandboxOutcome.EXECUTED:
            outcome = MissionOutcome.EXECUTED
        elif result.outcome == SandboxOutcome.RUNNER_FAILED:
            outcome = MissionOutcome.RUNNER_FAILED
        elif result.outcome == SandboxOutcome.EVIDENCE_FAILED:
            outcome = MissionOutcome.EVIDENCE_FAILED
        elif result.allowed:
            outcome = MissionOutcome.ALLOWED
        else:
            outcome = MissionOutcome.INVALID_STATE

        return MissionResult(
            outcome=outcome,
            session=result.session,
            sandbox_result=result,
            evidence=result.evidence,
            reason=result.reason,
            metadata=result.metadata,
        )

    def add_evidence(self, evidence: EvidenceRecord) -> MissionResult:
        """Attach evidence to the current session.

        Args:
            evidence: EvidenceRecord to attach.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.add_evidence(session.session_id, evidence)
        return MissionResult(
            outcome=self._map_session_result(result),
            session=result.session,
            evidence=evidence,
            reason=result.reason,
        )

    def add_finding(self, finding: Finding) -> MissionResult:
        """Attach a finding to the current session.

        Args:
            finding: Finding to attach.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.add_finding(session.session_id, finding)
        return MissionResult(
            outcome=self._map_session_result(result),
            session=result.session,
            finding=finding,
            reason=result.reason,
        )

    def add_approval(self, approval: ApprovalRequest) -> MissionResult:
        """Attach an approval-style note to the current session.

        ApprovalRequest remains part of the session model for audit notes and UI
        compatibility, but MissionController no longer runs an approval workflow.

        Args:
            approval: ApprovalRequest to attach.

        Returns:
            MissionResult containing the updated session.
        """

        session = self._require_session()
        if session is None:
            return self._not_found()
        result = self.session_manager.add_approval(session.session_id, approval)
        return self._from_session_result(self._map_session_result(result), result)

    def summary(self) -> dict[str, Any]:
        """Return a mission controller summary.

        Returns:
            JSON-compatible summary dictionary.
        """

        session = self.current_session()
        return {
            "mission_name": self.scope.mission_name,
            "session_id": session.session_id if session else None,
            "session_status": session.status.value if session else None,
            "current_phase": session.current_phase.value if session and session.current_phase else None,
            "finding_count": len(session.findings) if session else 0,
            "evidence_count": len(session.evidence) if session else 0,
            "approval_count": len(session.approvals) if session else 0,
            "pending_approval_count": len(session.pending_approvals) if session else 0,
        }

    def _require_session(self) -> MissionSession | None:
        """Return current session, creating one when possible.

        Returns:
            MissionSession when available, else None.
        """

        if self._session_id is None:
            created = self.create()
            return created.session
        return self.current_session()

    @staticmethod
    def _from_session_result(outcome: MissionOutcome, result: SessionManagerResult) -> MissionResult:
        """Convert a SessionManagerResult into a MissionResult.

        Args:
            outcome: Mission outcome to assign.
            result: Session manager result.

        Returns:
            MissionResult.
        """

        return MissionResult(
            outcome=outcome,
            session=result.session,
            reason=result.reason,
            metadata=result.metadata,
        )

    @staticmethod
    def _map_session_result(result: SessionManagerResult) -> MissionOutcome:
        """Map a SessionManagerResult outcome to a MissionOutcome.

        Args:
            result: Session manager result.

        Returns:
            MissionOutcome.
        """

        if result.outcome == SessionManagerOutcome.NOT_FOUND:
            return MissionOutcome.NOT_FOUND
        if result.outcome == SessionManagerOutcome.INVALID_STATE:
            return MissionOutcome.INVALID_STATE
        if result.outcome == SessionManagerOutcome.CREATED:
            return MissionOutcome.CREATED
        return MissionOutcome.UPDATED

    @staticmethod
    def _not_found() -> MissionResult:
        """Return a standard session-not-found result.

        Returns:
            MissionResult with NOT_FOUND outcome.
        """

        return MissionResult(
            outcome=MissionOutcome.NOT_FOUND,
            reason="Mission session was not found.",
        )