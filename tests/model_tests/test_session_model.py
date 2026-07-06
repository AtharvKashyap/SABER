

"""Tests for SABER session models.

This file verifies that `saber.models.session` correctly models mission runtime
state, phase execution, approval decisions, linked evidence, linked findings, and
safe summary serialization without performing persistence or tool execution.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from saber.models.evidence import EvidenceRecord, EvidenceStatus, EvidenceType
from saber.models.finding import Finding, VerificationStatus
from saber.models.scope import AssessmentPhase, MissionScope
from saber.models.session import (
    ApprovalRequest,
    ApprovalStatus,
    MissionSession,
    PhaseExecution,
    PhaseStatus,
    SessionStatus,
)
from saber.models.target import Target, TargetType


def make_target() -> Target:
    """Create a reusable target for session tests.

    Returns:
        A validated Target object.
    """

    return Target(type=TargetType.DOMAIN, value="example.com")


def make_scope() -> MissionScope:
    """Create a reusable mission scope for session tests.

    Returns:
        A validated MissionScope object.
    """

    return MissionScope(
        mission_name="Internal Assessment",
        targets=[make_target()],
        allowed_phases=[AssessmentPhase.RECON, AssessmentPhase.REPORTING],
    )


def make_evidence(evidence_id: str = "ev_session") -> EvidenceRecord:
    """Create a reusable evidence record for session tests.

    Args:
        evidence_id: Evidence identifier to assign.

    Returns:
        A validated EvidenceRecord object.
    """

    return EvidenceRecord(
        evidence_id=evidence_id,
        type=EvidenceType.TOOL_TEXT,
        title="Nmap output",
        file_path="evidence/nmap.txt",
        status=EvidenceStatus.VERIFIED,
    )


def make_finding(finding_id: str = "finding_session") -> Finding:
    """Create a reusable verified finding for session tests.

    Args:
        finding_id: Finding identifier to assign.

    Returns:
        A validated Finding object.
    """

    return Finding(
        finding_id=finding_id,
        title="Open SSH",
        description="SSH is reachable.",
        verification_status=VerificationStatus.VERIFIED,
        affected_targets=[make_target()],
        evidence=[make_evidence()],
    )


def make_approval(approval_id: str = "approval_1") -> ApprovalRequest:
    """Create a reusable pending approval request.

    Args:
        approval_id: Approval identifier to assign.

    Returns:
        A validated ApprovalRequest object.
    """

    return ApprovalRequest(
        approval_id=approval_id,
        action="run_exploit_validation",
        reason="Exploit validation requires explicit approval.",
        requested_by="ExploitAgent",
        target=make_target(),
    )


class TestPhaseExecution:
    """Validate phase execution state behavior."""

    def test_valid_pending_phase(self) -> None:
        """A pending phase should be valid without timestamps."""

        phase = PhaseExecution(phase=AssessmentPhase.RECON)

        assert phase.phase == AssessmentPhase.RECON
        assert phase.status == PhaseStatus.PENDING
        assert phase.started_at is None
        assert phase.finished_at is None
        assert phase.error_message is None
        assert phase.findings_count == 0
        assert phase.evidence_count == 0

    def test_running_phase_requires_started_at(self) -> None:
        """Running phases should require a start timestamp."""

        with pytest.raises(ValueError):
            PhaseExecution(phase=AssessmentPhase.RECON, status=PhaseStatus.RUNNING)

    @pytest.mark.parametrize(
        "status",
        [
            PhaseStatus.COMPLETED,
            PhaseStatus.FAILED,
            PhaseStatus.SKIPPED,
            PhaseStatus.BLOCKED,
        ],
    )
    def test_terminal_phase_requires_finished_at(self, status: PhaseStatus) -> None:
        """Terminal phases should require a finish timestamp."""

        with pytest.raises(ValueError):
            PhaseExecution(phase=AssessmentPhase.RECON, status=status)

    def test_failed_phase_requires_error_message(self) -> None:
        """Failed phases should require an error message."""

        now = datetime.now(UTC)

        with pytest.raises(ValueError):
            PhaseExecution(
                phase=AssessmentPhase.RECON,
                status=PhaseStatus.FAILED,
                started_at=now,
                finished_at=now + timedelta(seconds=1),
            )

    def test_finished_before_started_raises_error(self) -> None:
        """Phase timestamps should be chronological."""

        started_at = datetime.now(UTC)
        finished_at = started_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            PhaseExecution(
                phase=AssessmentPhase.RECON,
                status=PhaseStatus.COMPLETED,
                started_at=started_at,
                finished_at=finished_at,
            )

    def test_phase_marker_methods_return_updated_copies(self) -> None:
        """Phase marker helpers should return copied phase records."""

        phase = PhaseExecution(phase=AssessmentPhase.RECON)
        started_at = datetime.now(UTC)
        finished_at = started_at + timedelta(seconds=5)

        running = phase.mark_running(started_at)
        completed = running.mark_completed(finished_at)
        failed = running.mark_failed(" tool error ", finished_at)

        assert phase.status == PhaseStatus.PENDING
        assert running.status == PhaseStatus.RUNNING
        assert running.started_at == started_at
        assert completed.status == PhaseStatus.COMPLETED
        assert completed.finished_at == finished_at
        assert failed.status == PhaseStatus.FAILED
        assert failed.error_message == "tool error"
        assert failed.finished_at == finished_at

    def test_to_summary_dict(self) -> None:
        """Phase summary should serialize compact phase state."""

        started_at = datetime.now(UTC)
        finished_at = started_at + timedelta(seconds=2)
        phase = PhaseExecution(
            phase=AssessmentPhase.RECON,
            status=PhaseStatus.COMPLETED,
            started_at=started_at,
            finished_at=finished_at,
            findings_count=1,
            evidence_count=2,
        )

        assert phase.to_summary_dict() == {
            "phase": "recon",
            "status": "completed",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "error_message": None,
            "findings_count": 1,
            "evidence_count": 2,
        }


class TestApprovalRequest:
    """Validate approval request behavior."""

    def test_valid_pending_approval(self) -> None:
        """A valid pending approval should normalize text fields."""

        approval = ApprovalRequest(
            approval_id=" approval_1 ",
            action=" run_exploit_validation ",
            reason=" Requires operator approval. ",
            requested_by=" PlannerAgent ",
            target=make_target(),
        )

        assert approval.approval_id == "approval_1"
        assert approval.action == "run_exploit_validation"
        assert approval.reason == "Requires operator approval."
        assert approval.requested_by == "PlannerAgent"
        assert approval.status == ApprovalStatus.PENDING
        assert approval.is_pending
        assert approval.target == make_target()
        assert approval.created_at.tzinfo == UTC

    def test_auto_generated_approval_id_has_expected_prefix(self) -> None:
        """Approval IDs should be generated when omitted."""

        approval = ApprovalRequest(
            action="run_scan",
            reason="Needs approval.",
            requested_by="PlannerAgent",
        )

        assert approval.approval_id.startswith("approval_")
        assert len(approval.approval_id) > len("approval_")

    @pytest.mark.parametrize("approval_id", ["", "   ", "approval 1"])
    def test_invalid_approval_id_raises_error(self, approval_id: str) -> None:
        """Empty or whitespace-containing approval IDs should be rejected."""

        with pytest.raises(ValueError):
            ApprovalRequest(
                approval_id=approval_id,
                action="run_scan",
                reason="Needs approval.",
                requested_by="PlannerAgent",
            )

    def test_pending_approval_cannot_have_decision_metadata(self) -> None:
        """Pending approvals should not include decision metadata."""

        with pytest.raises(ValueError):
            ApprovalRequest(
                action="run_scan",
                reason="Needs approval.",
                requested_by="PlannerAgent",
                decided_by="Atharv",
            )

    def test_terminal_approval_requires_decided_at(self) -> None:
        """Terminal approvals should require a decision timestamp."""

        with pytest.raises(ValueError):
            ApprovalRequest(
                action="run_scan",
                reason="Needs approval.",
                requested_by="PlannerAgent",
                status=ApprovalStatus.APPROVED,
                decided_by="Atharv",
            )

    def test_approved_or_denied_approval_requires_decided_by(self) -> None:
        """Approved or denied approvals should require a deciding operator."""

        with pytest.raises(ValueError):
            ApprovalRequest(
                action="run_scan",
                reason="Needs approval.",
                requested_by="PlannerAgent",
                status=ApprovalStatus.APPROVED,
                decided_at=datetime.now(UTC),
            )

    def test_decided_at_before_created_at_raises_error(self) -> None:
        """Approval decision timestamps should be chronological."""

        created_at = datetime.now(UTC)
        decided_at = created_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            ApprovalRequest(
                action="run_scan",
                reason="Needs approval.",
                requested_by="PlannerAgent",
                status=ApprovalStatus.APPROVED,
                created_at=created_at,
                decided_at=decided_at,
                decided_by="Atharv",
            )

    def test_approve_and_deny_return_updated_copies(self) -> None:
        """Approval decision helpers should return copied request objects."""

        approval = make_approval()
        decided_at = datetime.now(UTC)

        approved = approval.approve(" Atharv ", " Looks safe. ", decided_at)
        denied = approval.deny(" Atharv ", " Out of scope. ", decided_at)

        assert approval.status == ApprovalStatus.PENDING
        assert approved.status == ApprovalStatus.APPROVED
        assert approved.decided_by == "Atharv"
        assert approved.decision_reason == "Looks safe."
        assert approved.decided_at == decided_at
        assert denied.status == ApprovalStatus.DENIED
        assert denied.decided_by == "Atharv"
        assert denied.decision_reason == "Out of scope."
        assert denied.decided_at == decided_at

    def test_to_summary_dict(self) -> None:
        """Approval summary should serialize compact approval state."""

        approval = make_approval()
        summary = approval.to_summary_dict()

        assert summary["approval_id"] == "approval_1"
        assert summary["action"] == "run_exploit_validation"
        assert summary["reason"] == "Exploit validation requires explicit approval."
        assert summary["requested_by"] == "ExploitAgent"
        assert summary["target"] == {"type": "domain", "value": "example.com"}
        assert summary["status"] == "pending"
        assert summary["decided_at"] is None
        assert summary["decided_by"] is None
        assert summary["decision_reason"] is None
        assert "created_at" in summary


class TestMissionSessionCreation:
    """Validate MissionSession construction and basic validation."""

    def test_valid_created_session(self) -> None:
        """A created session should be valid without start or finish timestamps."""

        session = MissionSession(
            session_id=" session_1 ",
            mission_name=" Internal Assessment ",
            scope=make_scope(),
            output_dir=" output/demo ",
        )

        assert session.session_id == "session_1"
        assert session.mission_name == "Internal Assessment"
        assert session.scope == make_scope()
        assert session.status == SessionStatus.CREATED
        assert session.created_at.tzinfo == UTC
        assert session.started_at is None
        assert session.finished_at is None
        assert session.output_dir == "output/demo"

    def test_auto_generated_session_id_has_expected_prefix(self) -> None:
        """Session IDs should be generated when omitted."""

        session = MissionSession(mission_name="Assessment")

        assert session.session_id.startswith("session_")
        assert len(session.session_id) > len("session_")

    @pytest.mark.parametrize("session_id", ["", "   ", "session 1"])
    def test_invalid_session_id_raises_error(self, session_id: str) -> None:
        """Empty or whitespace-containing session IDs should be rejected."""

        with pytest.raises(ValueError):
            MissionSession(session_id=session_id, mission_name="Assessment")

    def test_running_session_requires_started_at(self) -> None:
        """Running sessions should require started_at."""

        with pytest.raises(ValueError):
            MissionSession(mission_name="Assessment", status=SessionStatus.RUNNING)

    @pytest.mark.parametrize(
        "status",
        [SessionStatus.COMPLETED, SessionStatus.FAILED, SessionStatus.CANCELLED],
    )
    def test_terminal_session_requires_finished_at(self, status: SessionStatus) -> None:
        """Terminal sessions should require finished_at."""

        with pytest.raises(ValueError):
            MissionSession(mission_name="Assessment", status=status)

    def test_started_at_before_created_at_raises_error(self) -> None:
        """Session start timestamp should not predate creation timestamp."""

        created_at = datetime.now(UTC)
        started_at = created_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            MissionSession(
                mission_name="Assessment",
                status=SessionStatus.RUNNING,
                created_at=created_at,
                started_at=started_at,
            )

    def test_finished_at_before_started_at_raises_error(self) -> None:
        """Session finish timestamp should not predate start timestamp."""

        started_at = datetime.now(UTC)
        finished_at = started_at - timedelta(seconds=1)

        with pytest.raises(ValueError):
            MissionSession(
                mission_name="Assessment",
                status=SessionStatus.COMPLETED,
                created_at=started_at - timedelta(seconds=2),
                started_at=started_at,
                finished_at=finished_at,
            )

    def test_waiting_for_approval_requires_pending_approval(self) -> None:
        """Waiting sessions should require at least one pending approval."""

        with pytest.raises(ValueError):
            MissionSession(
                mission_name="Assessment",
                status=SessionStatus.WAITING_FOR_APPROVAL,
            )


class TestMissionSessionHelpers:
    """Validate MissionSession helper properties and copy methods."""

    def test_pending_approvals_property(self) -> None:
        """pending_approvals should return only pending requests."""

        pending = make_approval("approval_pending")
        approved = make_approval("approval_approved").approve("Atharv")
        session = MissionSession(
            mission_name="Assessment",
            approvals=[pending, approved],
        )

        assert session.pending_approvals == [pending]

    def test_verified_findings_property(self) -> None:
        """verified_findings should return only verified findings."""

        verified = make_finding("finding_verified")
        candidate = Finding(
            finding_id="finding_candidate",
            title="Candidate",
            description="Candidate finding.",
            affected_targets=[make_target()],
            evidence=[make_evidence("ev_candidate")],
        )
        session = MissionSession(
            mission_name="Assessment",
            findings=[verified, candidate],
        )

        assert session.verified_findings == [verified]

    def test_status_transition_helpers_return_updated_copies(self) -> None:
        """Session status helpers should return copied session objects."""

        session = MissionSession(mission_name="Assessment")
        started_at = datetime.now(UTC)
        finished_at = started_at + timedelta(seconds=10)

        running = session.start(started_at)
        paused = running.pause()
        completed = running.complete(finished_at)
        failed = running.fail(" tool failed ", finished_at)
        cancelled = running.cancel(finished_at)

        assert session.status == SessionStatus.CREATED
        assert running.status == SessionStatus.RUNNING
        assert running.started_at == started_at
        assert paused.status == SessionStatus.PAUSED
        assert completed.status == SessionStatus.COMPLETED
        assert completed.finished_at == finished_at
        assert failed.status == SessionStatus.FAILED
        assert failed.finished_at == finished_at
        assert failed.metadata["error_message"] == "tool failed"
        assert cancelled.status == SessionStatus.CANCELLED
        assert cancelled.finished_at == finished_at

    def test_wait_for_approval_adds_pending_approval_and_sets_status(self) -> None:
        """wait_for_approval should attach approval and set waiting status."""

        session = MissionSession(mission_name="Assessment")
        approval = make_approval()

        updated = session.wait_for_approval(approval)

        assert session.status == SessionStatus.CREATED
        assert session.approvals == []
        assert updated.status == SessionStatus.WAITING_FOR_APPROVAL
        assert updated.approvals == [approval]
        assert updated.pending_approvals == [approval]

    def test_add_helpers_return_updated_copies(self) -> None:
        """Add helpers should append records without mutating original session."""

        session = MissionSession(mission_name="Assessment")
        phase = PhaseExecution(phase=AssessmentPhase.RECON)
        evidence = make_evidence()
        finding = make_finding()
        approval = make_approval()

        with_phase = session.add_phase(phase)
        with_evidence = session.add_evidence(evidence)
        with_finding = session.add_finding(finding)
        with_approval = session.add_approval(approval)

        assert session.phases == []
        assert session.evidence == []
        assert session.findings == []
        assert session.approvals == []
        assert with_phase.phases == [phase]
        assert with_evidence.evidence == [evidence]
        assert with_finding.findings == [finding]
        assert with_approval.approvals == [approval]


class TestMissionSessionSerialization:
    """Validate MissionSession summary and agent serialization."""

    def test_to_agent_context(self) -> None:
        """Agent context should include compact session state."""

        phase = PhaseExecution(phase=AssessmentPhase.RECON)
        evidence = make_evidence()
        finding = make_finding()
        approval = make_approval()
        session = MissionSession(
            session_id="session_1",
            mission_name="Assessment",
            scope=make_scope(),
            status=SessionStatus.WAITING_FOR_APPROVAL,
            current_phase=AssessmentPhase.RECON,
            phases=[phase],
            evidence=[evidence],
            findings=[finding],
            approvals=[approval],
        )

        context = session.to_agent_context()

        assert context["session_id"] == "session_1"
        assert context["mission_name"] == "Assessment"
        assert context["status"] == "waiting_for_approval"
        assert context["current_phase"] == "recon"
        assert context["scope"] is not None
        assert context["phases"] == [phase.to_summary_dict()]
        assert context["finding_refs"] == ["finding_session"]
        assert context["evidence_refs"] == ["ev_session"]
        assert len(context["pending_approvals"]) == 1
        assert context["pending_approvals"][0]["approval_id"] == "approval_1"

    def test_to_summary_dict(self) -> None:
        """Session summary should include counts and lifecycle timestamps."""

        created_at = datetime.now(UTC)
        started_at = created_at + timedelta(seconds=1)
        phase = PhaseExecution(phase=AssessmentPhase.RECON)
        evidence = make_evidence()
        finding = make_finding()
        approval = make_approval()
        session = MissionSession(
            session_id="session_1",
            mission_name="Assessment",
            status=SessionStatus.RUNNING,
            created_at=created_at,
            started_at=started_at,
            current_phase=AssessmentPhase.RECON,
            phases=[phase],
            evidence=[evidence],
            findings=[finding],
            approvals=[approval],
            output_dir="output/session_1",
        )

        summary = session.to_summary_dict()

        assert summary == {
            "session_id": "session_1",
            "mission_name": "Assessment",
            "status": "running",
            "created_at": created_at.isoformat(),
            "started_at": started_at.isoformat(),
            "finished_at": None,
            "current_phase": "recon",
            "phase_count": 1,
            "finding_count": 1,
            "verified_finding_count": 1,
            "evidence_count": 1,
            "pending_approval_count": 1,
            "output_dir": "output/session_1",
        }