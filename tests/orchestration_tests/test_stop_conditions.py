# tests/orchestration_tests/test_stop_conditions.py
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.target import Target, TargetType
from saber.orchestration.stop_conditions import StopEvaluator


def _state(**kw) -> MissionState:
    return MissionState(session_id="s", target=Target(type=TargetType.IP, value="10.0.0.5"), **kw)


def test_stops_when_objective_met():
    result = StopEvaluator().evaluate(_state(objective_met=True), None)
    assert result.should_stop and "objective" in result.reason


def test_stops_when_decider_says_stop():
    action = ProposedAction(kind=ActionKind.STOP, objective="done", risk=RiskLevel.LOW)
    assert StopEvaluator().evaluate(_state(), action).should_stop


def test_stops_at_max_steps():
    assert StopEvaluator(max_steps=5).evaluate(_state(step_count=5), None).should_stop


def test_stops_on_repeated_failures():
    failing = [
        AttemptedAction(
            tool_name="nmap", action="scan", args={"x": 1}, success=False, reason="timeout"
        )
        for _ in range(3)
    ]
    state = _state(attempted_actions=failing)
    assert StopEvaluator(max_repeat_failures=3).evaluate(state, None).should_stop


def test_continues_by_default():
    assert StopEvaluator().evaluate(_state(step_count=1), None).should_stop is False
