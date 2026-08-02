"""An in-scope hostname's own resolved address must stay in scope.

Found live against the bundled lab. Scope declared the hostnames
(``dvwa``, ``juiceshop``, ...). nmap resolved ``dvwa`` to 172.21.0.4 and recorded
the service under the ADDRESS, so the deterministic decider's next step built
``url=http://172.21.0.4:80`` — which the gate refused as out of scope. Recon
poisoned every action that followed it and the mission died after one step.

The address is admissible only because THIS mission's own recon tied it to an
in-scope name. These tests pin that narrowness: an unrelated address, or a host
with no in-scope hostname, is still refused. Scope stays a hard wall.
"""

from saber.agents.deciders.base import ActionKind, ProposedAction
from saber.models.mission_state import KnownHost, MissionState
from saber.models.scope import MissionScope
from saber.models.target import Target, TargetType
from saber.orchestration.risk_gate import RiskGate


def _state(hosts: list[KnownHost]) -> MissionState:
    target = Target(type=TargetType.HOST, value="dvwa")
    return MissionState(
        session_id="s",
        target=target,
        scope=MissionScope(mission_name="m", targets=[target]),
        hosts=hosts,
    )


def _action(url: str) -> ProposedAction:
    return ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="whatweb",
        tool_action="fingerprint",
        args={"url": url},
        objective="fingerprint",
    )


def _allows(state, action) -> bool:
    return RiskGate()._scope_allows(state, action)


def test_address_of_an_in_scope_hostname_is_allowed():
    state = _state([KnownHost(address="172.21.0.4", hostnames=["dvwa"])])
    assert _allows(state, _action("http://172.21.0.4:80")) is True


def test_address_is_allowed_as_a_per_action_target_too():
    state = _state([KnownHost(address="172.21.0.4", hostnames=["dvwa"])])
    action = ProposedAction(
        kind=ActionKind.TOOL,
        tool_name="nuclei",
        tool_action="scan",
        args={},
        objective="scan",
        target=Target(type=TargetType.IP, value="172.21.0.4"),
    )
    assert _allows(state, action) is True


def test_extra_hostnames_on_the_same_host_do_not_matter():
    """Docker gives the container several names; one in-scope name is enough."""

    state = _state(
        [KnownHost(address="172.21.0.4", hostnames=["saber-lab-dvwa.saber-lab", "dvwa"])]
    )
    assert _allows(state, _action("http://172.21.0.4")) is True


def test_address_of_a_host_with_no_in_scope_hostname_is_refused():
    state = _state([KnownHost(address="172.21.0.9", hostnames=["unrelated.internal"])])
    assert _allows(state, _action("http://172.21.0.9")) is False


def test_address_with_no_hostnames_at_all_is_refused():
    """A bare discovered address proves nothing about identity."""

    state = _state([KnownHost(address="172.21.0.9", hostnames=[])])
    assert _allows(state, _action("http://172.21.0.9")) is False


def test_an_address_never_seen_in_state_is_refused():
    state = _state([KnownHost(address="172.21.0.4", hostnames=["dvwa"])])
    assert _allows(state, _action("http://8.8.8.8")) is False


def test_a_neighbour_in_the_same_subnet_is_still_refused():
    """Resolving one host must not admit the network around it."""

    state = _state([KnownHost(address="172.21.0.4", hostnames=["dvwa"])])
    assert _allows(state, _action("http://172.21.0.5")) is False
