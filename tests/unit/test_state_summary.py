from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import (
    AttemptedAction,
    Hypothesis,
    KnownService,
    KnownVuln,
    MissionState,
)
from saber.models.target import Target, TargetType


def _state() -> MissionState:
    return MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
        services=[KnownService(host="10.0.0.5", port=p) for p in range(1, 60)],
        vulns=[KnownVuln(title="v", severity="high")],
        hypotheses=[Hypothesis(statement="maybe RCE via CVE-2021-41773")],
        attempted_actions=[
            AttemptedAction(tool_name="nmap", action="x", success=False, reason="timeout")
        ],
    )


def test_summary_caps_services():
    summary = StateSummarizer(max_items=20).summarize(_state())
    assert len(summary.to_dict()["services"]) <= 20


def test_summary_includes_failed_actions_for_repeat_avoidance():
    summary = StateSummarizer().summarize(_state())
    failed = summary.to_dict()["recent_failures"]
    assert failed and failed[0]["reason"] == "timeout"


def test_summary_includes_objective_and_counts():
    d = StateSummarizer().summarize(_state()).to_dict()
    assert d["objective"] == "assess"
    assert d["counts"]["services"] == 59
