 
"""Tests for SABER ApprovalGate.

This file verifies that `saber.core.approval_gate` manages approval state for
review-required actions without prompting, executing tools, writing files, using a
database, or calling an LLM.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from saber.core.approval_gate import ApprovalGate, ApprovalGateOutcome, ApprovalGateResult
from saber.core.scope_guard import RequestedActionCategory, ToolRequest
from saber.models.scope import AssessmentPhase, ScopeDecision
from saber.models.session import ApprovalRequest, ApprovalStatus, MissionSession, SessionStatus
from saber.models.target import Target, TargetType


def make_target() -> Target:
    """Create a reusable target for approval gate tests.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.DOMAIN, value="example.com")


def make_request(target: Target | None = None) -> ToolRequest:
    """Create a reusable tool request.

    Args:
        target: Optional target for the request.

    Returns:
        A ToolRequest object.
    """

    return ToolRequest(
        tool_name="nuclei",
        action="run_nuclei_scan",
        phase=AssessmentPhase.WEB,
        target=target if target is not None else make_target(),
        category=RequestedActionCategory.WEB,
        ttp="T1190",
        requires_explicit_authorization=True,
        metadata={"template": "cves/2024/example.yaml"},
    )


def make_session(
    status: SessionStatus = SessionStatus.CREATED,
    approvals: list[ApprovalRequest] | None = None,
    started_at: datetime | None = None,
) -> MissionSession:
    """Create a reusable mission session.

    Args:
        status: Session status to assign.
        approvals: Optional approval list.
        started_at: Optional session start timestamp.

    Returns:
        A validated MissionSession object.
    """

    created_at = started_at - timedelta(seconds=1) if started_at else datetime.now(UTC)
    return MissionSession(
        session_id="session_1",
        mission_name="Approval Gate Test Mission",
        status=status,
        approvals=approvals if approvals is not None else [],
        created_at=created_at,
        started_at=started_at,
    )


def make_pending_approval(approval_id: str = "approval_1") -> ApprovalRequest:
    """Create a reusable pending approval request.

    Args:
        approval_id: Approval ID to assign.

    Returns:
        A pending ApprovalRequest object.
    """

    return ApprovalRequest(
        approval_id=approval_id,
        action="run_nuclei_scan",
        reason="Action requires approval.",
        requested_by="NucleiWrapper",
        target=make_target(),
    )


class TestApprovalGateResult:
    """Validate ApprovalGateResult behavior."""

    def test_to_summary_dict_without_approval(self) -> None:
        """Result summaries should serialize missing approvals as None."""

        session = make_session()
        result = ApprovalGateResult(
            outcome=ApprovalGateOutcome.ALLOWED,
            allowed=True,
            session=session,
            reason="Allowed.",
            metadata={"tool_name": "nuclei"},
        )

        assert result.to_summary_dict() == {
            "outcome": "allowed",
            "allowed": True,
            "session_id": "session_1",
            "approval_id": None,
            "reason": "Allowed.",
            "metadata": {"tool_name": "nuclei"},
        }

    def test_to_summary_dict_with_approval(self) -> None:
        """Result summaries should include approval IDs when present."""

        approval = make_pending_approval()
        session = make_session(approvals=[approval])
        result = ApprovalGateResult(
            outcome=ApprovalGateOutcome.WAITING_FOR_APPROVAL,
            allowed=False,
            session=session,
            approval=approval,
            reason="Waiting.",
        )

        assert result.to_summary_dict()["approval_id"] == "approval_1"
        assert result.to_summary_dict()["outcome"] == "waiting_for_approval"


class TestCreateApprovalRequest:
    """Validate approval request creation."""

    def test_create_approval_request_from_review_decision(self) -> None:
        """Approval requests should copy relevant request and decision context."""

        gate = ApprovalGate()
        target = make_target()
        request = make_request(target)
        decision = ScopeDecision.review(
            target=target,
            reason="Action run_nuclei_scan requires explicit authorization.",
            metadata={"reason_code": "action_requires_approval"},
        )

        approval = gate.create_approval_request(
            decision=decision,
            request=request,
            requested_by="NucleiWrapper",
        )

        assert approval.approval_id.startswith("approval_")
        assert approval.action == "run_nuclei_scan"
        assert approval.reason == "Action run_nuclei_scan requires explicit authorization."
        assert approval.requested_by == "NucleiWrapper"
        assert approval.status == ApprovalStatus.PENDING
        assert approval.target is not None
        assert approval.target.type == target.type
        assert approval.target.value == target.value
        assert approval.metadata["tool_name"] == "nuclei"
        assert approval.metadata["phase"] == "web"
        assert approval.metadata["category"] == "web"
        assert approval.metadata["ttp"] == "T1190"
        assert approval.metadata["request_metadata"] == {"template": "cves/2024/example.yaml"}
        assert approval.metadata["scope_decision"]["requires_review"] is True

    def test_create_approval_request_uses_decision_target_when_request_has_none(self) -> None:
        """Decision target should be used when request target is missing."""

        gate = ApprovalGate()
        target = make_target()
        request = ToolRequest(
            tool_name="reporter",
            action="publish_report",
            phase=AssessmentPhase.REPORTING,
            target=None,
            category=RequestedActionCategory.REPORTING,
        )
        decision = ScopeDecision.review(target=target, reason="Needs review.")

        approval = gate.create_approval_request(
            decision=decision,
            request=request,
            requested_by="Reporter",
        )

        assert approval.target is not None
        assert approval.target.type == target.type
        assert approval.target.value == target.value


class TestRequireApprovalForDecision:
    """Validate decision-to-approval behavior."""

    def test_allowed_decision_returns_allowed_result(self) -> None:
        """Already-allowed decisions should not create approval requests."""

        gate = ApprovalGate()
        session = make_session()
        request = make_request()
        decision = ScopeDecision.allow(reason="Allowed.")

        result = gate.require_approval_for_decision(
            session=session,
            decision=decision,
            request=request,
            requested_by="NucleiWrapper",
        )

        assert result.outcome == ApprovalGateOutcome.ALLOWED
        assert result.allowed is True
        assert result.session == session
        assert result.approval is None
        assert result.metadata == {"tool_name": "nuclei", "action": "run_nuclei_scan"}

    def test_denied_decision_returns_denied_result(self) -> None:
        """Denied decisions should not create approval requests."""

        gate = ApprovalGate()
        session = make_session()
        request = make_request()
        decision = ScopeDecision.deny(reason="Out of scope.")

        result = gate.require_approval_for_decision(
            session=session,
            decision=decision,
            request=request,
            requested_by="NucleiWrapper",
        )

        assert result.outcome == ApprovalGateOutcome.DENIED
        assert result.allowed is False
        assert result.session == session
        assert result.approval is None
        assert result.reason == "Out of scope."

    def test_review_decision_creates_approval_and_waiting_session(self) -> None:
        """Review decisions should create approval requests and update session state."""

        gate = ApprovalGate()
        session = make_session()
        request = make_request()
        decision = ScopeDecision.review(reason="Needs approval.")

        result = gate.require_approval_for_decision(
            session=session,
            decision=decision,
            request=request,
            requested_by="NucleiWrapper",
        )

        assert result.outcome == ApprovalGateOutcome.WAITING_FOR_APPROVAL
        assert result.allowed is False
        assert result.approval is not None
        assert result.approval.status == ApprovalStatus.PENDING
        assert result.session.status == SessionStatus.WAITING_FOR_APPROVAL
        assert result.session.approvals == [result.approval]
        assert session.status == SessionStatus.CREATED
        assert session.approvals == []


class TestApprovalDecisions:
    """Validate approve and deny behavior."""

    def test_approve_pending_request_updates_session(self) -> None:
        """Approving a pending request should update approval and unblock session."""

        gate = ApprovalGate()
        approval = make_pending_approval()
        session = make_session(status=SessionStatus.WAITING_FOR_APPROVAL, approvals=[approval])
        decided_at = datetime.now(UTC)

        result = gate.approve(
            session=session,
            approval_id="approval_1",
            decided_by="Atharv",
            decision_reason="Authorized for lab target.",
            decided_at=decided_at,
        )

        assert result.outcome == ApprovalGateOutcome.ALLOWED
        assert result.allowed is True
        assert result.approval is not None
        assert result.approval.status == ApprovalStatus.APPROVED
        assert result.approval.decided_by == "Atharv"
        assert result.approval.decision_reason == "Authorized for lab target."
        assert result.approval.decided_at == decided_at
        assert result.session.status == SessionStatus.CREATED
        assert result.session.approvals[0] == result.approval
        assert session.approvals[0].status == ApprovalStatus.PENDING

    def test_approve_waiting_running_session_returns_running_when_unblocked(self) -> None:
        """A started waiting session should return to running after final approval."""

        gate = ApprovalGate()
        approval = make_pending_approval()
        started_at = datetime.now(UTC) - timedelta(minutes=5)
        session = make_session(
            status=SessionStatus.WAITING_FOR_APPROVAL,
            approvals=[approval],
            started_at=started_at,
        )

        result = gate.approve(
            session=session,
            approval_id="approval_1",
            decided_by="Atharv",
        )

        assert result.session.status == SessionStatus.RUNNING
        assert result.session.started_at == started_at

    def test_approve_keeps_waiting_when_other_pending_approvals_remain(self) -> None:
        """Session should remain waiting when another approval is still pending."""

        gate = ApprovalGate()
        approval_1 = make_pending_approval("approval_1")
        approval_2 = make_pending_approval("approval_2")
        session = make_session(
            status=SessionStatus.WAITING_FOR_APPROVAL,
            approvals=[approval_1, approval_2],
        )

        result = gate.approve(
            session=session,
            approval_id="approval_1",
            decided_by="Atharv",
        )

        assert result.session.status == SessionStatus.WAITING_FOR_APPROVAL
        assert result.session.pending_approvals == [approval_2]

    def test_deny_pending_request_updates_session(self) -> None:
        """Denying a pending request should update approval and unblock session."""

        gate = ApprovalGate()
        approval = make_pending_approval()
        session = make_session(status=SessionStatus.WAITING_FOR_APPROVAL, approvals=[approval])
        decided_at = datetime.now(UTC)

        result = gate.deny(
            session=session,
            approval_id="approval_1",
            decided_by="Atharv",
            decision_reason="Out of scope.",
            decided_at=decided_at,
        )

        assert result.outcome == ApprovalGateOutcome.DENIED
        assert result.allowed is False
        assert result.approval is not None
        assert result.approval.status == ApprovalStatus.DENIED
        assert result.approval.decided_by == "Atharv"
        assert result.approval.decision_reason == "Out of scope."
        assert result.approval.decided_at == decided_at
        assert result.session.status == SessionStatus.CREATED

    def test_approval_not_found_returns_not_found(self) -> None:
        """Approving an unknown approval ID should return NOT_FOUND."""

        gate = ApprovalGate()
        session = make_session(approvals=[make_pending_approval()])

        result = gate.approve(
            session=session,
            approval_id="missing",
            decided_by="Atharv",
        )

        assert result.outcome == ApprovalGateOutcome.NOT_FOUND
        assert result.allowed is False
        assert result.approval is None
        assert result.session == session

    def test_already_decided_approval_returns_invalid_state(self) -> None:
        """Already decided approvals should not be changed again."""

        gate = ApprovalGate()
        approved = make_pending_approval().approve("Atharv")
        session = make_session(approvals=[approved])

        result = gate.deny(
            session=session,
            approval_id="approval_1",
            decided_by="Atharv",
        )

        assert result.outcome == ApprovalGateOutcome.INVALID_STATE
        assert result.allowed is True
        assert result.approval == approved
        assert result.session == session


class TestResolveApproval:
    """Validate approval resolution behavior."""

    def test_resolve_approved_request_allows_execution(self) -> None:
        """Approved requests should resolve to ALLOWED."""

        gate = ApprovalGate()
        approval = make_pending_approval().approve("Atharv")
        session = make_session(approvals=[approval])

        result = gate.resolve_approval(session, "approval_1")

        assert result.outcome == ApprovalGateOutcome.ALLOWED
        assert result.allowed is True
        assert result.approval == approval

    def test_resolve_pending_request_waits(self) -> None:
        """Pending requests should resolve to WAITING_FOR_APPROVAL."""

        gate = ApprovalGate()
        approval = make_pending_approval()
        session = make_session(approvals=[approval])

        result = gate.resolve_approval(session, "approval_1")

        assert result.outcome == ApprovalGateOutcome.WAITING_FOR_APPROVAL
        assert result.allowed is False
        assert result.approval == approval

    def test_resolve_denied_request_denies_execution(self) -> None:
        """Denied requests should resolve to DENIED."""

        gate = ApprovalGate()
        approval = make_pending_approval().deny("Atharv")
        session = make_session(approvals=[approval])

        result = gate.resolve_approval(session, "approval_1")

        assert result.outcome == ApprovalGateOutcome.DENIED
        assert result.allowed is False
        assert result.approval == approval

    def test_resolve_missing_request_returns_not_found(self) -> None:
        """Missing requests should resolve to NOT_FOUND."""

        gate = ApprovalGate()
        session = make_session()

        result = gate.resolve_approval(session, "missing")

        assert result.outcome == ApprovalGateOutcome.NOT_FOUND
        assert result.allowed is False
        assert result.approval is None

    def test_find_approval_returns_matching_request(self) -> None:
        """find_approval should return the matching approval object."""

        approval = make_pending_approval()
        session = make_session(approvals=[approval])

        assert ApprovalGate.find_approval(session, "approval_1") == approval
        assert ApprovalGate.find_approval(session, "missing") is None