"""Phase progression must be decided by state, not by the model's say-so."""

from saber.models.mission_state import (
    KnownAccount,
    KnownCredential,
    KnownFlag,
    KnownHost,
    KnownLoot,
    KnownService,
    KnownSession,
    KnownVuln,
    MissionState,
    PtesPhase,
)
from saber.models.target import Target, TargetType
from saber.orchestration.phase_gate import PhaseGoalChecker


def _state(**updates) -> MissionState:
    base = MissionState(
        session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5")
    )
    return base.model_copy(update=updates)


# --- ordering --------------------------------------------------------------------


def test_phases_are_in_methodology_order():
    assert PtesPhase.ordered() == (
        PtesPhase.PRE_ENGAGEMENT,
        PtesPhase.RECON,
        PtesPhase.VULN_ASSESSMENT,
        PtesPhase.EXPLOITATION,
        PtesPhase.POST_EXPLOITATION,
        PtesPhase.LATERAL_MOVEMENT,
        PtesPhase.PROOF_OF_CONCEPT,
        PtesPhase.POST_ENGAGEMENT,
    )
    assert PtesPhase.RECON.next_phase() is PtesPhase.VULN_ASSESSMENT
    assert PtesPhase.POST_ENGAGEMENT.next_phase() is None


def test_default_phase_is_recon_for_back_compat():
    assert _state().current_phase is PtesPhase.RECON


# --- recon -----------------------------------------------------------------------


def test_recon_not_met_with_no_hosts():
    decision = PhaseGoalChecker().evaluate(_state())
    assert decision.goal_met is False
    assert "no hosts" in decision.reason
    assert decision.next_phase is None


def test_recon_not_met_with_a_host_but_nothing_reachable_on_it():
    state = _state(hosts=[KnownHost(address="10.0.0.5")])
    decision = PhaseGoalChecker().evaluate(state)
    assert decision.goal_met is False
    assert "no services or technologies" in decision.reason


def test_recon_met_with_host_and_service():
    state = _state(
        hosts=[KnownHost(address="10.0.0.5")],
        services=[KnownService(host="10.0.0.5", port=80)],
    )
    decision = PhaseGoalChecker().evaluate(state)
    assert decision.goal_met is True
    assert decision.next_phase is PtesPhase.VULN_ASSESSMENT
    assert decision.should_advance is True


# --- vuln assessment -------------------------------------------------------------


def test_vuln_assessment_met_by_a_vuln():
    state = _state(current_phase=PtesPhase.VULN_ASSESSMENT, vulns=[KnownVuln(title="RCE")])
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_vuln_assessment_met_by_credentials_alone():
    """Credentials found while enumerating are themselves an attack path."""

    state = _state(
        current_phase=PtesPhase.VULN_ASSESSMENT,
        credentials=[KnownCredential(username="svc")],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_vuln_assessment_not_met_when_only_services_are_known():
    state = _state(
        current_phase=PtesPhase.VULN_ASSESSMENT,
        services=[KnownService(host="10.0.0.5", port=445)],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is False


# --- exploitation ----------------------------------------------------------------


def test_exploitation_requires_real_access_not_just_a_found_vuln():
    """An unconfirmed vuln is a hypothesis; it is not a foothold."""

    state = _state(
        current_phase=PtesPhase.EXPLOITATION,
        vulns=[KnownVuln(title="maybe RCE", confirmed=False)],
    )
    decision = PhaseGoalChecker().evaluate(state)
    assert decision.goal_met is False
    assert "no session" in decision.reason


def test_exploitation_met_by_a_session():
    state = _state(
        current_phase=PtesPhase.EXPLOITATION,
        sessions=[KnownSession(host="10.0.0.5", kind="shell")],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_exploitation_met_by_a_validated_credential():
    state = _state(
        current_phase=PtesPhase.EXPLOITATION,
        credentials=[KnownCredential(username="svc", validated=True)],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_exploitation_not_met_by_an_unvalidated_credential():
    """A cracked hash is not proof the account still works."""

    state = _state(
        current_phase=PtesPhase.EXPLOITATION,
        credentials=[KnownCredential(username="svc", validated=False)],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is False


# --- post-exploitation -----------------------------------------------------------


def test_post_exploitation_met_by_loot():
    state = _state(
        current_phase=PtesPhase.POST_EXPLOITATION,
        loot=[KnownLoot(description="id_rsa", kind="key")],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_post_exploitation_met_by_enumerated_accounts():
    state = _state(
        current_phase=PtesPhase.POST_EXPLOITATION,
        accounts=[KnownAccount(username="admin")],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


# --- lateral movement ------------------------------------------------------------


def test_lateral_movement_needs_reach_beyond_one_host():
    state = _state(
        current_phase=PtesPhase.LATERAL_MOVEMENT,
        sessions=[KnownSession(host="10.0.0.5", kind="shell")],
    )
    decision = PhaseGoalChecker().evaluate(state)
    assert decision.goal_met is False
    assert "limited to 1 host" in decision.reason


def test_lateral_movement_met_by_sessions_on_two_hosts():
    state = _state(
        current_phase=PtesPhase.LATERAL_MOVEMENT,
        sessions=[
            KnownSession(host="10.0.0.5", kind="shell"),
            KnownSession(host="10.0.0.9", kind="winrm"),
        ],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_lateral_movement_met_by_a_validated_credential_on_a_new_host():
    state = _state(
        current_phase=PtesPhase.LATERAL_MOVEMENT,
        sessions=[KnownSession(host="10.0.0.5", kind="shell")],
        credentials=[KnownCredential(username="admin", host="10.0.0.9", validated=True)],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_lateral_movement_not_met_by_a_credential_on_the_same_host():
    state = _state(
        current_phase=PtesPhase.LATERAL_MOVEMENT,
        sessions=[KnownSession(host="10.0.0.5", kind="shell")],
        credentials=[KnownCredential(username="admin", host="10.0.0.5", validated=True)],
    )
    assert PhaseGoalChecker().evaluate(state).goal_met is False


# --- proof of concept / terminal -------------------------------------------------


def test_proof_of_concept_met_by_a_flag():
    state = _state(current_phase=PtesPhase.PROOF_OF_CONCEPT, flags=[KnownFlag(value="flag{x}")])
    assert PhaseGoalChecker().evaluate(state).goal_met is True


def test_post_engagement_never_advances():
    state = _state(current_phase=PtesPhase.POST_ENGAGEMENT, flags=[KnownFlag(value="flag{x}")])
    decision = PhaseGoalChecker().evaluate(state)
    assert decision.goal_met is False
    assert decision.should_advance is False


# --- advance() -------------------------------------------------------------------


def test_advance_moves_exactly_one_phase_and_copies_state():
    state = _state(
        hosts=[KnownHost(address="10.0.0.5")],
        services=[KnownService(host="10.0.0.5", port=80)],
        flags=[KnownFlag(value="flag{x}")],
    )
    advanced = PhaseGoalChecker().advance(state)

    # One step only, even though later phases' evidence is already present.
    assert advanced.current_phase is PtesPhase.VULN_ASSESSMENT
    assert state.current_phase is PtesPhase.RECON, "original state must not be mutated"
    assert advanced is not state


def test_advance_is_a_no_op_when_the_goal_is_not_met():
    state = _state()
    assert PhaseGoalChecker().advance(state) is state


def test_every_phase_has_a_goal_defined():
    """An unrecognized phase must never silently advance."""

    checker = PhaseGoalChecker()
    for phase in PtesPhase.ordered():
        decision = checker.evaluate(_state(current_phase=phase))
        assert "no goal defined" not in decision.reason, phase
