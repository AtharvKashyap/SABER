from saber.models.mission_state import (
    AttemptedAction,
    AutonomyLevel,
    KnownService,
    MissionState,
)
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(
        session_id="session_abc",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="Enumerate and assess 10.0.0.5",
    )


def test_defaults_are_autonomous_and_empty():
    state = _state()
    assert state.autonomy_level == AutonomyLevel.AUTONOMOUS
    assert state.services == []
    assert state.step_count == 0
    assert state.objective_met is False


def test_known_service_key():
    svc = KnownService(host="10.0.0.5", port=80, protocol="tcp", service="http")
    assert svc.key == "10.0.0.5:80/tcp"


def test_record_attempt_is_immutable_and_appends():
    state = _state()
    attempt = AttemptedAction(tool_name="nmap", action="service_scan", success=True)
    updated = state.record_attempt(attempt)

    assert state.attempted_actions == []  # original unchanged
    assert len(updated.attempted_actions) == 1
    assert updated.failed_actions == []


def test_failed_actions_filters():
    state = _state().record_attempt(
        AttemptedAction(tool_name="nmap", action="service_scan", success=False, reason="timeout")
    )
    assert len(state.failed_actions) == 1
    assert state.failed_actions[0].reason == "timeout"


def test_attempt_signature_is_stable_and_order_independent():
    a = AttemptedAction(
        tool_name="whatweb", action="fingerprint", args={"url": "http://x", "depth": 1}
    )
    b = AttemptedAction(
        tool_name="whatweb", action="fingerprint", args={"depth": 1, "url": "http://x"}
    )
    assert a.signature == b.signature
