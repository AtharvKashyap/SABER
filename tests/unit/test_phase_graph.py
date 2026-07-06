"""Tests for SABER PhaseGraph."""

from __future__ import annotations

import pytest
from datetime import UTC, datetime

from saber.core.phase_graph import PhaseGraph, PhaseTransitionOutcome, PhaseTransitionResult
from saber.models.scope import AssessmentPhase, ExecutionMode, MissionScope
from saber.models.session import MissionSession, PhaseExecution, PhaseStatus, SessionStatus
from saber.models.target import Target, TargetType


def make_target() -> Target:
    """Create a reusable in-scope target."""
    return Target(type=TargetType.DOMAIN, value="example.com")


def make_scope(
    allowed_phases: list[AssessmentPhase] | None = None,
    execution_mode: ExecutionMode = ExecutionMode.ASSESSMENT,
) -> MissionScope:
    """Create a reusable mission scope."""
    return MissionScope(
        mission_name="Phase Graph Test Mission",
        client_name="Test Client",
        operator_name="Atharv",
        execution_mode=execution_mode,
        targets=[make_target()],
        allowed_phases=allowed_phases
        if allowed_phases is not None
        else [
            AssessmentPhase.RECON,
            AssessmentPhase.WEB,
            AssessmentPhase.NETWORK,
            AssessmentPhase.ACTIVE_DIRECTORY,
            AssessmentPhase.EXPLOITATION,
            AssessmentPhase.POST_EXPLOITATION,
            AssessmentPhase.PASSWORD_CRACKING,
            AssessmentPhase.REPORTING,
        ],
    )


def make_session(
    current_phase: AssessmentPhase | None = None,
    phases: list[PhaseExecution] | None = None,
) -> MissionSession:
    """Create a reusable mission session."""
    return MissionSession(
        session_id="session_1",
        mission_name="Phase Graph Test Mission",
        status=SessionStatus.CREATED,
        current_phase=current_phase,
        phases=phases if phases is not None else [],
    )


class TestPhaseTransitionResult:
    """Validate PhaseTransitionResult behavior."""

    def test_to_summary_dict(self) -> None:
        """Transition results should serialize compactly."""
        session = make_session()
        result = PhaseTransitionResult(
            outcome=PhaseTransitionOutcome.ALLOWED,
            allowed=True,
            phase=AssessmentPhase.RECON,
            session=session,
            reason="Phase recon can start.",
            metadata={"current_phase": None},
        )

        assert result.to_summary_dict() == {
            "outcome": "allowed",
            "allowed": True,
            "phase": "recon",
            "session_id": "session_1",
            "reason": "Phase recon can start.",
            "metadata": {"current_phase": None},
        }


class TestPhaseGraphTransitions:
    """Validate default transition behavior."""

    def test_start_can_go_to_recon_or_reporting(self) -> None:
        """Mission start should allow recon and reporting."""
        graph = PhaseGraph(make_scope())

        assert graph.next_phases(None) == {AssessmentPhase.RECON, AssessmentPhase.REPORTING}

    def test_recon_can_transition_to_expected_phases(self) -> None:
        """Recon should lead into assessment branches or reporting."""
        graph = PhaseGraph(make_scope())

        assert graph.next_phases(AssessmentPhase.RECON) == {
            AssessmentPhase.WEB,
            AssessmentPhase.NETWORK,
            AssessmentPhase.ACTIVE_DIRECTORY,
            AssessmentPhase.REPORTING,
        }

    def test_reporting_has_no_next_phases(self) -> None:
        """Reporting should be terminal in the default graph."""
        graph = PhaseGraph(make_scope())

        assert graph.next_phases(AssessmentPhase.REPORTING) == set()

    def test_unknown_custom_transition_returns_empty_set(self) -> None:
        """Missing transition keys should return an empty set."""
        graph = PhaseGraph(make_scope(), transitions={})

        assert graph.next_phases(AssessmentPhase.RECON) == set()


class TestCanStartPhase:
    """Validate can_start_phase decisions."""

    def test_can_start_recon_from_new_session(self) -> None:
        """Recon should be allowed from mission start."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        result = graph.can_start_phase(session, AssessmentPhase.RECON)

        assert result.outcome == PhaseTransitionOutcome.ALLOWED
        assert result.allowed is True
        assert result.phase == AssessmentPhase.RECON
        assert result.metadata == {"current_phase": None}

    def test_can_start_reporting_from_new_session(self) -> None:
        """Reporting should be allowed from mission start."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        result = graph.can_start_phase(session, AssessmentPhase.REPORTING)

        assert result.outcome == PhaseTransitionOutcome.ALLOWED
        assert result.allowed is True

    def test_invalid_transition_is_denied(self) -> None:
        """A phase not reachable from the current phase should be denied."""
        graph = PhaseGraph(make_scope())
        session = make_session(current_phase=AssessmentPhase.REPORTING)

        result = graph.can_start_phase(session, AssessmentPhase.RECON)

        assert result.outcome == PhaseTransitionOutcome.DENIED
        assert result.allowed is False
        assert result.metadata["current_phase"] == "reporting"
        assert result.metadata["allowed_next"] == []

    def test_scope_disallowed_phase_is_blocked(self) -> None:
        """Scope-disallowed phases should be blocked before transition checks."""
        scope = make_scope(allowed_phases=[AssessmentPhase.RECON, AssessmentPhase.REPORTING])
        graph = PhaseGraph(scope)
        session = make_session(current_phase=AssessmentPhase.RECON)

        result = graph.can_start_phase(session, AssessmentPhase.EXPLOITATION)

        assert result.outcome == PhaseTransitionOutcome.BLOCKED
        assert result.allowed is False
        assert result.metadata == {"blocked_by": "mission_scope"}

    def test_running_phase_cannot_start_again(self) -> None:
        """Running phases should not be restarted."""
        graph = PhaseGraph(make_scope())
        phase = PhaseExecution(phase=AssessmentPhase.RECON).mark_running()
        session = make_session(phases=[phase])

        result = graph.can_start_phase(session, AssessmentPhase.RECON)

        assert result.outcome == PhaseTransitionOutcome.ALREADY_RUNNING
        assert result.allowed is False

    def test_completed_phase_cannot_start_again(self) -> None:
        """Completed phases should not be restarted."""
        graph = PhaseGraph(make_scope())
        phase = PhaseExecution(phase=AssessmentPhase.RECON).mark_running().mark_completed()
        session = make_session(phases=[phase])

        result = graph.can_start_phase(session, AssessmentPhase.RECON)

        assert result.outcome == PhaseTransitionOutcome.ALREADY_COMPLETED
        assert result.allowed is False

    def test_blocked_phase_cannot_start(self) -> None:
        """Blocked phases should not start."""
        graph = PhaseGraph(make_scope())
        phase = PhaseExecution(phase=AssessmentPhase.RECON).model_copy(
            update={
                "status": PhaseStatus.BLOCKED,
                "finished_at": datetime.now(UTC),
                "error_message": "Blocked by policy.",
            }
        )
        session = make_session(phases=[phase])

        result = graph.can_start_phase(session, AssessmentPhase.RECON)

        assert result.outcome == PhaseTransitionOutcome.BLOCKED
        assert result.allowed is False


class TestPhaseStateUpdates:
    """Validate phase state mutation helpers."""

    def test_start_phase_adds_running_phase_and_sets_current_phase(self) -> None:
        """start_phase should add a running phase and set current_phase."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        updated = graph.start_phase(session, AssessmentPhase.RECON)

        phase = graph.get_phase_execution(updated, AssessmentPhase.RECON)
        assert phase is not None
        assert phase.status == PhaseStatus.RUNNING
        assert updated.current_phase == AssessmentPhase.RECON
        assert session.current_phase is None
        assert session.phases == []

    def test_start_phase_raises_for_invalid_transition(self) -> None:
        """start_phase should raise when can_start_phase denies transition."""
        graph = PhaseGraph(make_scope())
        session = make_session(current_phase=AssessmentPhase.REPORTING)

        with pytest.raises(ValueError, match="Cannot transition"):
            graph.start_phase(session, AssessmentPhase.RECON)

    def test_complete_phase_marks_phase_completed(self) -> None:
        """complete_phase should mark phase completed with counts."""
        graph = PhaseGraph(make_scope())
        phase = PhaseExecution(phase=AssessmentPhase.RECON).mark_running()
        session = make_session(current_phase=AssessmentPhase.RECON, phases=[phase])

        updated = graph.complete_phase(
            session,
            AssessmentPhase.RECON,
            findings_count=2,
            evidence_count=5,
        )

        completed = graph.get_phase_execution(updated, AssessmentPhase.RECON)
        assert completed is not None
        assert completed.status == PhaseStatus.COMPLETED
        assert completed.findings_count == 2
        assert completed.evidence_count == 5
        assert completed.finished_at is not None

    def test_fail_phase_marks_phase_failed(self) -> None:
        """fail_phase should mark phase failed with an error."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        updated = graph.fail_phase(session, AssessmentPhase.WEB, "Tool failed.")

        failed = graph.get_phase_execution(updated, AssessmentPhase.WEB)
        assert failed is not None
        assert failed.status == PhaseStatus.FAILED
        assert failed.error_message == "Tool failed."
        assert failed.finished_at is not None

    def test_skip_phase_marks_phase_skipped(self) -> None:
        """skip_phase should mark phase skipped with a reason."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        updated = graph.skip_phase(session, AssessmentPhase.WEB, "No web targets.")

        skipped = graph.get_phase_execution(updated, AssessmentPhase.WEB)
        assert skipped is not None
        assert skipped.status == PhaseStatus.SKIPPED
        assert skipped.error_message == "No web targets."
        assert skipped.finished_at is not None

    def test_block_phase_marks_phase_blocked(self) -> None:
        """block_phase should mark phase blocked with a reason."""
        graph = PhaseGraph(make_scope())
        session = make_session()

        updated = graph.block_phase(session, AssessmentPhase.EXPLOITATION, "Approval required.")

        blocked = graph.get_phase_execution(updated, AssessmentPhase.EXPLOITATION)
        assert blocked is not None
        assert blocked.status == PhaseStatus.BLOCKED
        assert blocked.error_message == "Approval required."
        assert blocked.finished_at is not None

    def test_replace_phase_execution_replaces_existing_phase(self) -> None:
        """Updating a phase should replace existing phase execution records."""
        graph = PhaseGraph(make_scope())
        phase = PhaseExecution(phase=AssessmentPhase.RECON).mark_running()
        session = make_session(phases=[phase])

        updated = graph.complete_phase(session, AssessmentPhase.RECON)

        assert len(updated.phases) == 1
        assert updated.phases[0].status == PhaseStatus.COMPLETED


class TestPhaseQueries:
    """Validate helper query methods."""

    def test_available_next_phases_filters_by_scope(self) -> None:
        """available_next_phases should remove phases not allowed by scope."""
        scope = make_scope(
            allowed_phases=[
                AssessmentPhase.RECON,
                AssessmentPhase.WEB,
                AssessmentPhase.REPORTING,
            ]
        )
        graph = PhaseGraph(scope)
        session = make_session(current_phase=AssessmentPhase.RECON)

        assert graph.available_next_phases(session) == [
            AssessmentPhase.REPORTING,
            AssessmentPhase.WEB,
        ]

    def test_current_phase_returns_session_current_phase(self) -> None:
        """current_phase should return the session current phase."""
        session = make_session(current_phase=AssessmentPhase.RECON)

        assert PhaseGraph.current_phase(session) == AssessmentPhase.RECON

    def test_get_phase_execution_returns_matching_phase(self) -> None:
        """get_phase_execution should return matching phase execution."""
        phase = PhaseExecution(phase=AssessmentPhase.RECON)
        session = make_session(phases=[phase])

        assert PhaseGraph.get_phase_execution(session, AssessmentPhase.RECON) == phase
        assert PhaseGraph.get_phase_execution(session, AssessmentPhase.WEB) is None