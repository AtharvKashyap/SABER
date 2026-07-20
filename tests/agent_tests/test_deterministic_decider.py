from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.deterministic import DeterministicDecider
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import KnownService, KnownTechnology, MissionState
from saber.models.target import Target, TargetType


def _decide(state: MissionState):
    return DeterministicDecider().decide(state, StateSummarizer().summarize(state))


def test_first_action_is_service_scan_when_no_services():
    state = MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))
    action = _decide(state)
    assert action.kind == ActionKind.TOOL
    assert (action.tool_name, action.tool_action) == ("nmap", "service_scan")


def test_web_service_without_fingerprint_triggers_whatweb():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
    )
    action = _decide(state)
    assert action.tool_name == "whatweb"


def test_report_when_nothing_left():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        technologies=[KnownTechnology(host="10.0.0.5", name="nginx")],
        vulns=[],
        metadata={"web_scanned": True, "exploit_intel_done": True},
    )
    # after web + intel exhausted, decider reports
    action = _decide(state)
    assert action.kind == ActionKind.REPORT
