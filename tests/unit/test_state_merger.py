from saber.core.state_merger import StateMerger
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"))


def _attempt() -> AttemptedAction:
    return AttemptedAction(tool_name="nmap", action="service_scan", success=True)


def test_merge_adds_service_and_records_attempt():
    obs = [
        {
            "kind": "service",
            "data": {"host": "10.0.0.5", "port": 80, "service": "http", "state": "open"},
        }
    ]
    merged = StateMerger().merge(_state(), obs, _attempt())

    assert len(merged.services) == 1
    assert merged.services[0].key == "10.0.0.5:80/tcp"
    assert merged.step_count == 1
    assert merged.attempted_actions[0].tool_name == "nmap"


def test_merge_dedupes_services_by_key():
    state = _state()
    obs = [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "service": "http"}}]
    once = StateMerger().merge(state, obs, _attempt())
    twice = StateMerger().merge(once, obs, _attempt())
    assert len(twice.services) == 1  # no duplicate


def test_merge_updates_service_fields_on_rescan():
    state = _state()
    first = StateMerger().merge(
        state, [{"kind": "service", "data": {"host": "10.0.0.5", "port": 80}}], _attempt()
    )
    second = StateMerger().merge(
        first,
        [
            {
                "kind": "service",
                "data": {"host": "10.0.0.5", "port": 80, "product": "nginx", "version": "1.25"},
            }
        ],
        _attempt(),
    )
    assert len(second.services) == 1
    assert second.services[0].product == "nginx"
    assert second.services[0].version == "1.25"


def test_merge_promotes_vuln_and_evidence_refs():
    obs = [
        {
            "kind": "vuln",
            "data": {"title": "CVE-2021-41773", "host": "10.0.0.5", "severity": "high"},
        }
    ]
    merged = StateMerger().merge(
        _state(), obs, _attempt(), evidence_refs=["ev1"], finding_refs=["f1"]
    )
    assert merged.vulns[0].identifier is None or merged.vulns[0].title.startswith("CVE")
    assert "ev1" in merged.evidence_refs
    assert "f1" in merged.finding_refs


def test_merge_records_failed_attempt():
    attempt = AttemptedAction(
        tool_name="nmap", action="service_scan", success=False, reason="timeout"
    )
    merged = StateMerger().merge(_state(), [], attempt)
    assert merged.failed_actions[0].reason == "timeout"


def test_merge_is_immutable():
    state = _state()
    StateMerger().merge(
        state, [{"kind": "service", "data": {"host": "10.0.0.5", "port": 22}}], _attempt()
    )
    assert state.services == []  # original untouched
