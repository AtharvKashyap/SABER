from saber.agents.base_agent import AgentObservation
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.core.state_merger import StateMerger
from saber.models.mission_state import MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.risk_gate import GateDecision, GateResult
from saber.orchestration.stop_conditions import StopDecision
from saber.orchestration.strategies.ctf import CtfStrategy


class _Summarizer:
    def summarize(self, state):
        return type("S", (), {"to_dict": lambda self: {}})()


class _Decider:
    """One TOOL action, then STOP."""

    def __init__(self):
        self.calls = 0

    def decide(self, state, summary):
        self.calls += 1
        if self.calls == 1:
            return ProposedAction(
                kind=ActionKind.TOOL,
                tool_name="custom_cli",
                tool_action="run_command",
                args={},
                objective="grab flag",
                risk=RiskLevel.LOW,
            )
        return ProposedAction(kind=ActionKind.STOP, objective="done", rationale="done")


class _Gate:
    def evaluate(self, state, action):
        return GateResult(GateDecision.ALLOW, "ok")


class _Executor:
    def execute(self, state, session, action):
        obs = AgentObservation(
            summary="output was: flag{saber_vulnbin_pwned}",
            tool_name=action.tool_name,
            action=action.tool_action,
            success=True,
        )
        return ActionExecutionRecord(sandbox_result=None, observation=obs, error=None)


class _ResultProcessor:
    def process_tool_result(self, **kwargs):
        return type(
            "P", (), {"parsed_observations": [], "evidence_ids": [], "finding_ids": []}
        )()


class _Stop:
    def evaluate(self, state, action):
        return StopDecision(should_stop=state.objective_met, reason="objective met")


class _Store:
    def __init__(self):
        self.snapshots = []

    def snapshot(self, state):
        self.snapshots.append(state)


def _state(metadata=None):
    target = Target(type=TargetType.HOST, value="vulnbin")
    state = MissionState(session_id="s1", target=target, objective="capture the flag")
    if metadata:
        state = state.model_copy(update={"metadata": {**state.metadata, **metadata}})
    return state


def _build_loop(store):
    return MissionLoop(
        decider=_Decider(),
        summarizer=_Summarizer(),
        risk_gate=_Gate(),
        stop_evaluator=_Stop(),
        executor=_Executor(),
        merger=StateMerger(),
        state_store=store,
        result_processor=_ResultProcessor(),
        max_steps=5,
        strategy=CtfStrategy(),
    )


def test_flag_detected_sets_metadata_and_meets_objective():
    store = _Store()
    loop = _build_loop(store)
    session = MissionSession(session_id="s1", mission_name="ctf")
    loop.run(_state(), session, strategy=CtfStrategy())
    final = store.snapshots[-1]
    assert final.metadata.get("flag") == "flag{saber_vulnbin_pwned}"
    assert final.objective_met is True


def test_malformed_flag_regex_does_not_raise_or_set_flag():
    store = _Store()
    loop = _build_loop(store)
    session = MissionSession(session_id="s1", mission_name="ctf")
    state = _state(metadata={"flag_regex": "flag{[invalid"})
    # Must not raise even though the user-supplied regex is invalid.
    result = loop.run(state, session, strategy=CtfStrategy())
    final = store.snapshots[-1]
    assert final.metadata.get("flag") is None
    assert final.objective_met is False
    assert result is not None
