

"""Session models used across SABER.

This file defines runtime state models for a SABER mission. A session tracks the
mission lifecycle, phase execution, approval requests, linked evidence, linked
findings, and compact summaries for agents, reports, and persistence layers.

Inputs:
    - Validated mission scope from saber.models.scope.
    - Evidence records from tool wrappers and EvidenceStore.
    - Finding records from agents, parsers, and analyst review.
    - Approval requests from ScopeGuard or ApprovalGate.

Outputs:
    - Normalized MissionSession objects.
    - PhaseExecution and ApprovalRequest state objects.
    - Summary dictionaries for CLI, database persistence, reports, and agents.

Used by:
    - saber.core.session
    - saber.core.mission
    - saber.core.approval_gate
    - saber.core.phase_graph
    - saber.storage.database
    - saber.ui.cli
    - saber.reporting exporters
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator

from saber.models.evidence import EvidenceRecord
from saber.models.finding import Finding
from saber.models.scope import AssessmentPhase, MissionScope
from saber.models.target import Target


class SessionStatus(StrEnum):
    """Lifecycle status for a SABER mission session.

    Values:
        CREATED: Session exists but has not started.
        RUNNING: Session is actively running.
        PAUSED: Session has been paused by the operator or system.
        WAITING_FOR_APPROVAL: Session is blocked on one or more approval requests.
        COMPLETED: Session completed successfully.
        FAILED: Session ended because of an error.
        CANCELLED: Session was cancelled by the operator or system.
    """

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PhaseStatus(StrEnum):
    """Execution status for an assessment phase.

    Values:
        PENDING: Phase has not started.
        RUNNING: Phase is currently running.
        COMPLETED: Phase completed successfully.
        FAILED: Phase failed.
        SKIPPED: Phase was intentionally skipped.
        BLOCKED: Phase is blocked, usually by scope or approval requirements.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ApprovalStatus(StrEnum):
    """Decision status for an approval request.

    Values:
        PENDING: Approval has been requested but not decided.
        APPROVED: Operator approved the action.
        DENIED: Operator denied the action.
        EXPIRED: Approval request expired before decision.
        CANCELLED: Approval request was cancelled.
    """

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class PhaseExecution(BaseModel):
    """Runtime state for one SABER assessment phase.

    Args:
        phase: Assessment phase being tracked.
        status: Current phase status.
        started_at: Optional UTC timestamp when phase started.
        finished_at: Optional UTC timestamp when phase finished.
        error_message: Optional error message if the phase failed or was blocked.
        findings_count: Count of findings produced by this phase.
        evidence_count: Count of evidence records produced by this phase.
        metadata: Optional structured phase metadata.

    Returns:
        A validated phase execution state object.
    """

    phase: AssessmentPhase
    status: PhaseStatus = PhaseStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = None
    findings_count: int = Field(default=0, ge=0)
    evidence_count: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("error_message", mode="before")
    @classmethod
    def normalize_error_message(cls, value: str | None) -> str | None:
        """Normalize phase error text.

        Args:
            value: Raw error text or None.

        Returns:
            Stripped error text, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_phase_timestamps(self) -> PhaseExecution:
        """Validate phase timestamp and status consistency.

        Returns:
            The validated PhaseExecution object.

        Raises:
            ValueError: If timestamps conflict with phase status.
        """

        if self.finished_at and self.started_at and self.finished_at < self.started_at:
            raise ValueError("phase finished_at cannot be earlier than started_at")

        terminal_statuses = {
            PhaseStatus.COMPLETED,
            PhaseStatus.FAILED,
            PhaseStatus.SKIPPED,
            PhaseStatus.BLOCKED,
        }
        if self.status == PhaseStatus.RUNNING and self.started_at is None:
            raise ValueError("running phases require started_at")
        if self.status in terminal_statuses and self.finished_at is None:
            raise ValueError("terminal phases require finished_at")
        if self.status == PhaseStatus.FAILED and self.error_message is None:
            raise ValueError("failed phases require error_message")

        return self

    def mark_running(self, started_at: datetime | None = None) -> PhaseExecution:
        """Return a copy of this phase marked running.

        Args:
            started_at: Optional UTC start timestamp. Defaults to current UTC time.

        Returns:
            A new PhaseExecution with status RUNNING.
        """

        return self.model_copy(
            update={
                "status": PhaseStatus.RUNNING,
                "started_at": started_at or datetime.now(UTC),
                "finished_at": None,
                "error_message": None,
            }
        )

    def mark_completed(self, finished_at: datetime | None = None) -> PhaseExecution:
        """Return a copy of this phase marked completed.

        Args:
            finished_at: Optional UTC finish timestamp. Defaults to current UTC time.

        Returns:
            A new PhaseExecution with status COMPLETED.
        """

        return self.model_copy(
            update={"status": PhaseStatus.COMPLETED, "finished_at": finished_at or datetime.now(UTC)}
        )

    def mark_failed(
        self,
        error_message: str,
        finished_at: datetime | None = None,
    ) -> PhaseExecution:
        """Return a copy of this phase marked failed.

        Args:
            error_message: Failure reason.
            finished_at: Optional UTC finish timestamp. Defaults to current UTC time.

        Returns:
            A new PhaseExecution with status FAILED.
        """

        return self.model_copy(
            update={
                "status": PhaseStatus.FAILED,
                "error_message": error_message.strip(),
                "finished_at": finished_at or datetime.now(UTC),
            }
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact phase summary.

        Returns:
            JSON-compatible phase execution summary.
        """

        return {
            "phase": self.phase.value,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "error_message": self.error_message,
            "findings_count": self.findings_count,
            "evidence_count": self.evidence_count,
        }


class ApprovalRequest(BaseModel):
    """Operator approval request for a guarded action.

    Args:
        approval_id: Stable approval request identifier.
        action: Action requiring approval.
        reason: Human-readable reason approval is needed.
        requested_by: Component or agent that requested approval.
        target: Optional target the approval applies to.
        status: Current approval decision status.
        created_at: UTC timestamp when request was created.
        decided_at: Optional UTC timestamp when decision was made.
        decided_by: Optional operator name or ID that made the decision.
        decision_reason: Optional explanation for the decision.
        metadata: Optional structured approval metadata.

    Returns:
        A validated approval request object.
    """

    approval_id: str = Field(default_factory=lambda: f"approval_{uuid4().hex}")
    action: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    requested_by: str = Field(..., min_length=1)
    target: Target | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "approval_id",
        "action",
        "reason",
        "requested_by",
        "decided_by",
        "decision_reason",
        mode="before",
    )
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize approval text fields.

        Args:
            value: Raw string or None.

        Returns:
            Stripped string, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("approval_id")
    @classmethod
    def validate_approval_id(cls, approval_id: str) -> str:
        """Validate an approval request ID.

        Args:
            approval_id: Normalized approval identifier.

        Returns:
            The validated approval ID.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        if not approval_id:
            raise ValueError("approval_id cannot be empty")
        if any(character.isspace() for character in approval_id):
            raise ValueError("approval_id cannot contain whitespace")
        return approval_id

    @model_validator(mode="after")
    def validate_decision_state(self) -> ApprovalRequest:
        """Validate approval decision consistency.

        Returns:
            The validated ApprovalRequest object.

        Raises:
            ValueError: If decision timestamps or operator fields are inconsistent.
        """

        terminal_statuses = {
            ApprovalStatus.APPROVED,
            ApprovalStatus.DENIED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.CANCELLED,
        }
        if self.decided_at and self.decided_at < self.created_at:
            raise ValueError("approval decided_at cannot be earlier than created_at")
        if self.status in terminal_statuses:
            if self.decided_at is None:
                raise ValueError("decided approval requests require decided_at")
            if self.status in {ApprovalStatus.APPROVED, ApprovalStatus.DENIED} and not self.decided_by:
                raise ValueError("approved or denied requests require decided_by")
        if self.status == ApprovalStatus.PENDING and (self.decided_at or self.decided_by):
            raise ValueError("pending approval requests cannot include decision metadata")

        return self

    @property
    def is_pending(self) -> bool:
        """Return whether this approval is still pending.

        Returns:
            True when status is PENDING.
        """

        return self.status == ApprovalStatus.PENDING

    def approve(
        self,
        decided_by: str,
        decision_reason: str | None = None,
        decided_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Return a copy of this request marked approved.

        Args:
            decided_by: Operator who approved the request.
            decision_reason: Optional approval explanation.
            decided_at: Optional decision timestamp. Defaults to current UTC time.

        Returns:
            A new ApprovalRequest with status APPROVED.
        """

        return self.model_copy(
            update={
                "status": ApprovalStatus.APPROVED,
                "decided_by": decided_by.strip(),
                "decision_reason": decision_reason.strip() if decision_reason else None,
                "decided_at": decided_at or datetime.now(UTC),
            }
        )

    def deny(
        self,
        decided_by: str,
        decision_reason: str | None = None,
        decided_at: datetime | None = None,
    ) -> ApprovalRequest:
        """Return a copy of this request marked denied.

        Args:
            decided_by: Operator who denied the request.
            decision_reason: Optional denial explanation.
            decided_at: Optional decision timestamp. Defaults to current UTC time.

        Returns:
            A new ApprovalRequest with status DENIED.
        """

        return self.model_copy(
            update={
                "status": ApprovalStatus.DENIED,
                "decided_by": decided_by.strip(),
                "decision_reason": decision_reason.strip() if decision_reason else None,
                "decided_at": decided_at or datetime.now(UTC),
            }
        )

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact approval request summary.

        Returns:
            JSON-compatible approval request summary.
        """

        return {
            "approval_id": self.approval_id,
            "action": self.action,
            "reason": self.reason,
            "requested_by": self.requested_by,
            "target": self.target.to_agent_dict() if self.target else None,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "decided_by": self.decided_by,
            "decision_reason": self.decision_reason,
        }


class MissionSession(BaseModel):
    """Runtime state for a SABER mission.

    Args:
        session_id: Stable session identifier.
        mission_name: Human-readable mission name.
        scope: Optional mission scope object.
        status: Current session lifecycle status.
        created_at: UTC timestamp when session was created.
        started_at: Optional UTC timestamp when session started.
        finished_at: Optional UTC timestamp when session finished.
        current_phase: Optional current assessment phase.
        phases: Phase execution records.
        findings: Finding records linked to this session.
        evidence: Evidence records linked to this session.
        approvals: Approval requests linked to this session.
        output_dir: Directory where session artifacts should be written.
        metadata: Optional structured session metadata.

    Returns:
        A validated mission session state object.
    """

    session_id: str = Field(default_factory=lambda: f"session_{uuid4().hex}")
    mission_name: str = Field(..., min_length=1)
    scope: MissionScope | None = None
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    current_phase: AssessmentPhase | None = None
    phases: list[PhaseExecution] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    evidence: list[EvidenceRecord] = Field(default_factory=list)
    approvals: list[ApprovalRequest] = Field(default_factory=list)
    output_dir: str = "output"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("session_id", "mission_name", "output_dir", mode="before")
    @classmethod
    def normalize_text(cls, value: str | None) -> str | None:
        """Normalize session text fields.

        Args:
            value: Raw string or None.

        Returns:
            Stripped string, or None when empty.
        """

        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, session_id: str) -> str:
        """Validate a session ID.

        Args:
            session_id: Normalized session identifier.

        Returns:
            Validated session ID.

        Raises:
            ValueError: If the ID is empty or contains whitespace.
        """

        if not session_id:
            raise ValueError("session_id cannot be empty")
        if any(character.isspace() for character in session_id):
            raise ValueError("session_id cannot contain whitespace")
        return session_id

    @model_validator(mode="after")
    def validate_session_consistency(self) -> MissionSession:
        """Validate session timestamp and status consistency.

        Returns:
            The validated MissionSession object.

        Raises:
            ValueError: If timestamps conflict with lifecycle status.
        """

        terminal_statuses = {
            SessionStatus.COMPLETED,
            SessionStatus.FAILED,
            SessionStatus.CANCELLED,
        }
        if self.started_at and self.started_at < self.created_at:
            raise ValueError("session started_at cannot be earlier than created_at")
        if self.finished_at and self.started_at and self.finished_at < self.started_at:
            raise ValueError("session finished_at cannot be earlier than started_at")
        if self.status == SessionStatus.RUNNING and self.started_at is None:
            raise ValueError("running sessions require started_at")
        if self.status in terminal_statuses and self.finished_at is None:
            raise ValueError("terminal sessions require finished_at")
        if self.status == SessionStatus.WAITING_FOR_APPROVAL and not self.pending_approvals:
            raise ValueError("waiting sessions require at least one pending approval")

        return self

    @property
    def pending_approvals(self) -> list[ApprovalRequest]:
        """Return pending approval requests.

        Returns:
            Approval requests with status PENDING.
        """

        return [approval for approval in self.approvals if approval.is_pending]

    @property
    def verified_findings(self) -> list[Finding]:
        """Return verified findings linked to this session.

        Returns:
            Finding records with verification_status VERIFIED.
        """

        return [finding for finding in self.findings if finding.is_verified]

    def start(self, started_at: datetime | None = None) -> MissionSession:
        """Return a copy of this session marked running.

        Args:
            started_at: Optional UTC start timestamp. Defaults to current UTC time.

        Returns:
            A new MissionSession with status RUNNING.
        """

        return self.model_copy(
            update={"status": SessionStatus.RUNNING, "started_at": started_at or datetime.now(UTC)}
        )

    def pause(self) -> MissionSession:
        """Return a copy of this session marked paused.

        Returns:
            A new MissionSession with status PAUSED.
        """

        return self.model_copy(update={"status": SessionStatus.PAUSED})

    def wait_for_approval(self, approval: ApprovalRequest) -> MissionSession:
        """Return a copy of this session blocked on an approval request.

        Args:
            approval: Pending approval request to attach.

        Returns:
            A new MissionSession with status WAITING_FOR_APPROVAL.
        """

        return self.model_copy(
            update={
                "status": SessionStatus.WAITING_FOR_APPROVAL,
                "approvals": [*self.approvals, approval],
            }
        )

    def complete(self, finished_at: datetime | None = None) -> MissionSession:
        """Return a copy of this session marked completed.

        Args:
            finished_at: Optional UTC finish timestamp. Defaults to current UTC time.

        Returns:
            A new MissionSession with status COMPLETED.
        """

        return self.model_copy(
            update={"status": SessionStatus.COMPLETED, "finished_at": finished_at or datetime.now(UTC)}
        )

    def fail(self, error_message: str, finished_at: datetime | None = None) -> MissionSession:
        """Return a copy of this session marked failed.

        Args:
            error_message: Failure reason to store in metadata.
            finished_at: Optional UTC finish timestamp. Defaults to current UTC time.

        Returns:
            A new MissionSession with status FAILED.
        """

        metadata = {**self.metadata, "error_message": error_message.strip()}
        return self.model_copy(
            update={
                "status": SessionStatus.FAILED,
                "finished_at": finished_at or datetime.now(UTC),
                "metadata": metadata,
            }
        )

    def cancel(self, finished_at: datetime | None = None) -> MissionSession:
        """Return a copy of this session marked cancelled.

        Args:
            finished_at: Optional UTC finish timestamp. Defaults to current UTC time.

        Returns:
            A new MissionSession with status CANCELLED.
        """

        return self.model_copy(
            update={"status": SessionStatus.CANCELLED, "finished_at": finished_at or datetime.now(UTC)}
        )

    def add_phase(self, phase: PhaseExecution) -> MissionSession:
        """Return a copy of this session with one additional phase record.

        Args:
            phase: PhaseExecution to append.

        Returns:
            A new MissionSession containing the phase.
        """

        return self.model_copy(update={"phases": [*self.phases, phase]})

    def add_evidence(self, record: EvidenceRecord) -> MissionSession:
        """Return a copy of this session with one additional evidence record.

        Args:
            record: EvidenceRecord to append.

        Returns:
            A new MissionSession containing the evidence record.
        """

        return self.model_copy(update={"evidence": [*self.evidence, record]})

    def add_finding(self, finding: Finding) -> MissionSession:
        """Return a copy of this session with one additional finding.

        Args:
            finding: Finding to append.

        Returns:
            A new MissionSession containing the finding.
        """

        return self.model_copy(update={"findings": [*self.findings, finding]})

    def add_approval(self, approval: ApprovalRequest) -> MissionSession:
        """Return a copy of this session with one additional approval request.

        Args:
            approval: ApprovalRequest to append.

        Returns:
            A new MissionSession containing the approval request.
        """

        return self.model_copy(update={"approvals": [*self.approvals, approval]})

    def to_agent_context(self) -> dict[str, Any]:
        """Return compact session data for agent handoff.

        Returns:
            JSON-compatible session context suitable for planner and agent prompts.
        """

        return {
            "session_id": self.session_id,
            "mission_name": self.mission_name,
            "status": self.status.value,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "scope": self.scope.to_agent_context() if self.scope else None,
            "phases": [phase.to_summary_dict() for phase in self.phases],
            "finding_refs": [finding.finding_id for finding in self.findings],
            "evidence_refs": [record.evidence_id for record in self.evidence],
            "pending_approvals": [approval.to_summary_dict() for approval in self.pending_approvals],
        }

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a compact session summary.

        Returns:
            JSON-compatible session summary for CLI, storage, and reports.
        """

        return {
            "session_id": self.session_id,
            "mission_name": self.mission_name,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "current_phase": self.current_phase.value if self.current_phase else None,
            "phase_count": len(self.phases),
            "finding_count": len(self.findings),
            "verified_finding_count": len(self.verified_findings),
            "evidence_count": len(self.evidence),
            "pending_approval_count": len(self.pending_approvals),
            "output_dir": self.output_dir,
        }