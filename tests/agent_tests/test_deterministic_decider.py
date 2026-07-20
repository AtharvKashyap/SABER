from saber.agents.deciders.base import ActionKind, RiskLevel
from saber.agents.deciders.deterministic import DeterministicDecider
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import (
    AttemptedAction,
    KnownService,
    KnownTechnology,
    MissionState,
)
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


def test_rung3_fires_nuclei_when_fingerprinted_and_no_vulns():
    # Fingerprinted host + open web service + no vulns + nuclei not yet attempted
    # -> rung 3 proposes a nuclei template scan.
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        technologies=[KnownTechnology(host="10.0.0.5", name="nginx")],
        vulns=[],
    )
    action = _decide(state)
    assert (action.tool_name, action.tool_action) == ("nuclei", "template_scan")
    assert action.risk == RiskLevel.MEDIUM
    assert action.metadata["category"] == "web"


def test_rung3_does_not_refire_nuclei_after_attempt():
    # Regression: a clean (zero-vuln) nuclei scan is a success, not a failure, so
    # the loop's repeat-failure detector never trips. Rung 3 must consult the
    # attempted set itself or it re-proposes nuclei forever and never advances.
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[KnownService(host="10.0.0.5", port=80, service="http")],
        technologies=[KnownTechnology(host="10.0.0.5", name="nginx")],
        vulns=[],
        attempted_actions=[
            AttemptedAction(tool_name="nuclei", action="template_scan"),
        ],
    )
    action = _decide(state)
    assert (action.tool_name, action.tool_action) != ("nuclei", "template_scan")
    # No versioned service and no exploit intel left -> decider advances to REPORT.
    assert action.kind == ActionKind.REPORT


def test_rung4_fires_searchsploit_for_versioned_service():
    # Versioned service + exploit intel not done + nuclei already attempted
    # -> rung 3 is guarded out and rung 4 proposes a searchsploit lookup.
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        services=[
            KnownService(
                host="10.0.0.5",
                port=80,
                service="http",
                product="Apache",
                version="2.4.49",
            ),
        ],
        technologies=[KnownTechnology(host="10.0.0.5", name="Apache")],
        vulns=[],
        attempted_actions=[
            AttemptedAction(tool_name="nuclei", action="template_scan"),
        ],
    )
    action = _decide(state)
    assert (action.tool_name, action.tool_action) == ("searchsploit", "lookup")
    assert action.metadata["category"] == "exploitation"
