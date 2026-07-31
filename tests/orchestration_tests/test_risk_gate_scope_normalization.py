"""Scope normalization must accept the same host spelled differently — and nothing else.

Found live: scope held "http://dvwa" while the decider proposed the bare host "dvwa"
as a per-action target. The exact string compare refused it, so the mission executed
nothing and MissionState stayed empty. Scope is a hard wall, so these tests pin both
directions: equivalent spellings allowed, genuinely different hosts still refused.
"""

from saber.agents.deciders.base import ActionKind, ProposedAction
from saber.models.mission_state import MissionState
from saber.models.scope import MissionScope
from saber.models.target import Target, TargetType
from saber.orchestration.risk_gate import RiskGate


def _state(scope_value: str, scope_type: TargetType) -> MissionState:
    target = Target(type=scope_type, value=scope_value)
    return MissionState(
        session_id="s",
        target=target,
        scope=MissionScope(mission_name="m", targets=[target]),
    )


def _action(target_value: str | None, target_type: TargetType = TargetType.HOST):
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="whatweb",
        tool_action="fingerprint",
        args={},
        objective="fingerprint",
        target=Target(type=target_type, value=target_value) if target_value else None,
    )


def _allows(state, action) -> bool:
    return RiskGate()._scope_allows(state, action)


def test_bare_host_is_allowed_when_scope_holds_the_url():
    state = _state("http://dvwa", TargetType.URL)
    assert _allows(state, _action("dvwa")) is True


def test_url_is_allowed_when_scope_holds_the_bare_host():
    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action("http://dvwa", TargetType.URL)) is True


def test_port_and_path_do_not_change_scope_identity():
    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action("http://dvwa:80/vulnerabilities/xss", TargetType.URL)) is True


def test_a_different_host_is_still_refused():
    """The hard wall must hold — this is the whole point of the gate."""

    state = _state("http://dvwa", TargetType.URL)
    assert _allows(state, _action("evil.example.com")) is False
    assert _allows(state, _action("http://evil.example.com", TargetType.URL)) is False


def test_a_host_that_merely_contains_the_scoped_name_is_refused():
    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action("dvwa.evil.example.com")) is False
    assert _allows(state, _action("notdvwa")) is False


def test_credentials_in_a_url_cannot_smuggle_a_foreign_host():
    """"http://dvwa@evil.com" points at evil.com, not dvwa."""

    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action("http://dvwa@evil.example.com", TargetType.URL)) is False


def test_an_ip_inside_an_in_scope_cidr_is_still_refused():
    """Documented limitation: normalization does NOT expand network ranges.

    Widening a CIDR to its members is a real scope decision and must be explicit.
    """

    state = _state("192.168.56.0/24", TargetType.CIDR)
    assert _allows(state, _action("192.168.56.5", TargetType.IP)) is False


def test_no_action_target_falls_back_to_the_mission_target():
    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action(None)) is True
