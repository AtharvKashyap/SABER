

"""Approval workflow helpers for SABER.

This module defines ApprovalGate, the core state-management layer used when
ScopeGuard determines that a proposed action requires operator review. The gate
creates ApprovalRequest records, attaches them to MissionSession objects, and
returns updated session state after approve/deny decisions.

ApprovalGate is intentionally pure logic: it does not prompt on stdin, write to a
database, call an LLM, run tools, send notifications, or execute shell commands.
Those integrations belong in CLI, API, storage, and runner layers.

Inputs:
    - ScopeDecision objects from saber.models.scope.
    - ToolRequest objects from saber.core.scope_guard.
    - MissionSession objects from saber.models.session.

Outputs:
    - ApprovalRequest records.
    - Updated MissionSession objects.
    - ApprovalGateResult records describing whether execution may continue.

Used by:
    - saber.core.mission
    - saber.core.phase_graph
    - saber.core.scope_guard callers
    - saber.tools.* wrappers
    - saber.ui.cli approval prompts
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from saber.core.scope_guard import ToolRequest
from saber.models.scope import ScopeDecision
from saber.models.session import ApprovalRequest, ApprovalStatus, MissionSession, SessionStatus
from saber.models.target import Target


class ApprovalGateOutcome(StrEnum):
    """Outcome returned after ApprovalGate evaluates or updates approval state.

    Values:
        ALLOWED: The request can continue.
        DENIED: The request must not continue.
        WAITING_FOR_APPROVAL: The request is waiting for operator approval.
        NOT_FOUND: The requested approval record could not be found.
        INVALID_STATE: The operation was not valid for the current approval state.
    """

    ALLOWED = "allowed"
    DENIED = "denied"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    NOT_FOUND = "not_found"
    INVALID_STATE = "invalid_state"


@dataclass(frozen=True)
class ApprovalGateResult:
    """Result returned by ApprovalGate operations.

    Args:
        outcome: Approval gate outcome.
        allowed: Whether the guarded action may continue.
        session: Updated mission session.
        approval: Approval request related to the result, if any.
        reason: Human-readable result reason.
        metadata: Optional structured result metadata.

    Returns:
        Immutable result object describing approval state.
    """

    outcome: ApprovalGateOutcome
    allowed: bool
    session: MissionSession
    approval: ApprovalRequest | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_summary_dict(self) -> dict[str, Any]:
        """Return compact approval gate result data.

        Returns:
            JSON-compatible result summary.
        """

        return {
            "outcome": self.outcome.value,
            "allowed": self.allowed,
            "session_id": self.session.session_id,
            "approval_id": self.approval.approval_id if self.approval else None,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class ApprovalGate:
    """Manage approval request state for guarded SABER actions.

    ApprovalGate does not make policy decisions itself. ScopeGuard decides whether
    something is allowed, denied, or requires review. ApprovalGate handles the
    review lifecycle once a review is needed.
    """

    def require_approval_for_decision(
        self,
        session: MissionSession,
        decision: ScopeDecision,
        request: ToolRequest,
        requested_by: str,
    ) -> ApprovalGateResult:
        """Create an approval request when a ScopeDecision requires review.

        Args:
            session: Current mission session.
            decision: ScopeDecision returned by ScopeGuard.
            request: ToolRequest that triggered the decision.
            requested_by: Component, agent, or wrapper requesting approval.

        Returns:
            ApprovalGateResult with an updated session.
        """

        if decision.allowed:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.ALLOWED,
                allowed=True,
                session=session,
                reason="Scope decision already allows the request.",
                metadata={"tool_name": request.tool_name, "action": request.action},
            )

        if not decision.requires_review:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.DENIED,
                allowed=False,
                session=session,
                reason=decision.reason,
                metadata={"tool_name": request.tool_name, "action": request.action},
            )

        approval = self.create_approval_request(
            decision=decision,
            request=request,
            requested_by=requested_by,
        )
        updated_session = session.wait_for_approval(approval)

        return ApprovalGateResult(
            outcome=ApprovalGateOutcome.WAITING_FOR_APPROVAL,
            allowed=False,
            session=updated_session,
            approval=approval,
            reason="Approval request created and attached to session.",
            metadata={"tool_name": request.tool_name, "action": request.action},
        )

    def create_approval_request(
        self,
        decision: ScopeDecision,
        request: ToolRequest,
        requested_by: str,
    ) -> ApprovalRequest:
        """Create an ApprovalRequest from a review decision and tool request.

        Args:
            decision: Review decision returned by ScopeGuard.
            request: ToolRequest being reviewed.
            requested_by: Component, agent, or wrapper requesting approval.

        Returns:
            A pending ApprovalRequest.
        """

        target = request.target or decision.target
        return ApprovalRequest(
            approval_id=f"approval_{uuid4().hex}",
            action=request.action,
            reason=decision.reason,
            requested_by=requested_by,
            target=target,
            metadata={
                "tool_name": request.tool_name,
                "phase": request.phase.value,
                "category": request.category.value,
                "ttp": request.ttp,
                "scope_decision": decision.to_agent_dict(),
                "request_metadata": request.metadata,
            },
        )

    def approve(
        self,
        session: MissionSession,
        approval_id: str,
        decided_by: str,
        decision_reason: str | None = None,
        decided_at: datetime | None = None,
    ) -> ApprovalGateResult:
        """Approve a pending approval request.

        Args:
            session: Current mission session.
            approval_id: Approval request ID to approve.
            decided_by: Operator who approved the request.
            decision_reason: Optional approval reason.
            decided_at: Optional UTC decision timestamp.

        Returns:
            ApprovalGateResult with updated session and approval state.
        """

        return self._decide(
            session=session,
            approval_id=approval_id,
            status=ApprovalStatus.APPROVED,
            decided_by=decided_by,
            decision_reason=decision_reason,
            decided_at=decided_at,
        )

    def deny(
        self,
        session: MissionSession,
        approval_id: str,
        decided_by: str,
        decision_reason: str | None = None,
        decided_at: datetime | None = None,
    ) -> ApprovalGateResult:
        """Deny a pending approval request.

        Args:
            session: Current mission session.
            approval_id: Approval request ID to deny.
            decided_by: Operator who denied the request.
            decision_reason: Optional denial reason.
            decided_at: Optional UTC decision timestamp.

        Returns:
            ApprovalGateResult with updated session and approval state.
        """

        return self._decide(
            session=session,
            approval_id=approval_id,
            status=ApprovalStatus.DENIED,
            decided_by=decided_by,
            decision_reason=decision_reason,
            decided_at=decided_at,
        )

    def resolve_approval(self, session: MissionSession, approval_id: str) -> ApprovalGateResult:
        """Resolve whether an approval request allows execution.

        Args:
            session: Current mission session.
            approval_id: Approval request ID to resolve.

        Returns:
            ApprovalGateResult indicating allowed, denied, waiting, or not found.
        """

        approval = self.find_approval(session, approval_id)
        if approval is None:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.NOT_FOUND,
                allowed=False,
                session=session,
                reason=f"Approval request {approval_id} was not found.",
            )

        if approval.status == ApprovalStatus.APPROVED:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.ALLOWED,
                allowed=True,
                session=session,
                approval=approval,
                reason="Approval request was approved.",
            )

        if approval.status == ApprovalStatus.PENDING:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.WAITING_FOR_APPROVAL,
                allowed=False,
                session=session,
                approval=approval,
                reason="Approval request is still pending.",
            )

        return ApprovalGateResult(
            outcome=ApprovalGateOutcome.DENIED,
            allowed=False,
            session=session,
            approval=approval,
            reason=f"Approval request status is {approval.status.value}.",
        )

    @staticmethod
    def find_approval(session: MissionSession, approval_id: str) -> ApprovalRequest | None:
        """Find an approval request by ID.

        Args:
            session: Session containing approval requests.
            approval_id: Approval request ID to find.

        Returns:
            Matching ApprovalRequest, or None when not found.
        """

        for approval in session.approvals:
            if approval.approval_id == approval_id:
                return approval
        return None

    def _decide(
        self,
        session: MissionSession,
        approval_id: str,
        status: ApprovalStatus,
        decided_by: str,
        decision_reason: str | None,
        decided_at: datetime | None,
    ) -> ApprovalGateResult:
        """Apply an approval decision to a session.

        Args:
            session: Current mission session.
            approval_id: Approval request ID to update.
            status: Terminal approval status to apply.
            decided_by: Operator who made the decision.
            decision_reason: Optional decision reason.
            decided_at: Optional UTC decision timestamp.

        Returns:
            ApprovalGateResult with updated session state.
        """

        approval = self.find_approval(session, approval_id)
        if approval is None:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.NOT_FOUND,
                allowed=False,
                session=session,
                reason=f"Approval request {approval_id} was not found.",
            )

        if approval.status != ApprovalStatus.PENDING:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.INVALID_STATE,
                allowed=approval.status == ApprovalStatus.APPROVED,
                session=session,
                approval=approval,
                reason=f"Approval request {approval_id} is already {approval.status.value}.",
            )

        decision_time = decided_at or datetime.now(UTC)
        if status == ApprovalStatus.APPROVED:
            updated_approval = approval.approve(
                decided_by=decided_by,
                decision_reason=decision_reason,
                decided_at=decision_time,
            )
            outcome = ApprovalGateOutcome.ALLOWED
            allowed = True
            reason = "Approval request approved."
        elif status == ApprovalStatus.DENIED:
            updated_approval = approval.deny(
                decided_by=decided_by,
                decision_reason=decision_reason,
                decided_at=decision_time,
            )
            outcome = ApprovalGateOutcome.DENIED
            allowed = False
            reason = "Approval request denied."
        else:
            return ApprovalGateResult(
                outcome=ApprovalGateOutcome.INVALID_STATE,
                allowed=False,
                session=session,
                approval=approval,
                reason=f"Unsupported approval decision status: {status.value}.",
            )

        updated_approvals = [
            updated_approval if current.approval_id == approval_id else current
            for current in session.approvals
        ]
        updated_session = session.model_copy(update={"approvals": updated_approvals})

        if updated_session.status == SessionStatus.WAITING_FOR_APPROVAL:
            if updated_session.pending_approvals:
                session_status = SessionStatus.WAITING_FOR_APPROVAL
            else:
                session_status = SessionStatus.RUNNING if updated_session.started_at else SessionStatus.CREATED
            updated_session = updated_session.model_copy(update={"status": session_status})

        return ApprovalGateResult(
            outcome=outcome,
            allowed=allowed,
            session=updated_session,
            approval=updated_approval,
            reason=reason,
            metadata={"approval_id": approval_id},
        )