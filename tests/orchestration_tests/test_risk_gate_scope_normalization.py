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


# --- scope must not be bypassable through tool args -------------------------------


def _action_with_args(args: dict, target_value: str | None = None):
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="whatweb",
        tool_action="fingerprint",
        args=args,
        objective="fingerprint",
        target=Target(type=TargetType.HOST, value=target_value) if target_value else None,
    )


def test_out_of_scope_url_arg_is_refused_even_with_an_in_scope_target():
    """The live hole: wrappers prefer kwargs["url"] over the Target.

    A decider could name an in-scope target to pass the gate and send
    url=http://evil.example.com in args, and whatweb would scan the foreign host.
    """

    state = _state("dvwa", TargetType.HOST)
    action = _action_with_args({"url": "http://evil.example.com"}, target_value="dvwa")
    assert _allows(state, action) is False


def test_in_scope_url_arg_is_allowed():
    state = _state("dvwa", TargetType.HOST)
    action = _action_with_args({"url": "http://dvwa/vulnerabilities/xss"}, target_value="dvwa")
    assert _allows(state, action) is True


def test_out_of_scope_domain_arg_is_refused():
    """dnsrecon/subfinder/amass/theharvester all take `domain`."""

    state = _state("lab.local", TargetType.DOMAIN)
    assert _allows(state, _action_with_args({"domain": "evil.example.com"})) is False
    assert _allows(state, _action_with_args({"domain": "lab.local"})) is True


def test_non_destination_args_are_not_treated_as_hosts():
    """A pattern or community string must not be misread as a target."""

    state = _state("dvwa", TargetType.HOST)
    action = _action_with_args({"pattern": "password", "community": "public"}, "dvwa")
    assert _allows(state, action) is True


def test_unparseable_host_bearing_arg_fails_closed():
    state = _state("dvwa", TargetType.HOST)
    assert _allows(state, _action_with_args({"url": "://"}, "dvwa")) is False


def test_every_host_bearing_arg_name_in_a_contract_is_covered():
    """A new destination arg must be added to _HOST_BEARING_ARGS or scope leaks.

    Catches the drift where a contract gains a host-bearing arg the gate does not know
    about, silently reopening the bypass this test file exists to close.
    """

    from saber.orchestration.risk_gate import _HOST_BEARING_ARGS
    from saber.tools.registry import build_default_registry

    registry = build_default_registry()
    suspicious = {"url", "domain", "destination", "host", "hostname", "rhosts", "cidr", "server"}
    seen: set[str] = set()
    for name in sorted({e.name for e in registry._entries.values()}):
        contract = registry.get(name).load_contract()
        if contract is None:
            continue
        for act in contract.actions:
            for spec in act.args:
                if spec.name in suspicious:
                    seen.add(spec.name)

    uncovered = seen - set(_HOST_BEARING_ARGS)
    assert not uncovered, (
        f"contracts declare destination arg(s) {sorted(uncovered)} that RiskGate does "
        f"not scope-check; add them to _HOST_BEARING_ARGS"
    )
