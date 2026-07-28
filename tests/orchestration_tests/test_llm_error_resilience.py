"""A transient/unrecoverable LLM error must fail the mission, not fake-complete it.

Regression: the LlmDecider returned ActionKind.STOP on any LLM exception, and the
loop maps STOP -> COMPLETED, so an intermittent TLS blip produced a "completed"
mission with an empty MissionState and empty reports (a false success).
"""

from __future__ import annotations

from saber.agents.deciders.base import ActionKind
from saber.agents.deciders.llm import LlmDecider
from saber.core.state_merger import StateMerger
from saber.core.tool_catalog import ToolCatalog
from saber.models.mission_state import MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.orchestration.risk_gate import GateDecision, GateResult
from saber.orchestration.stop_conditions import StopDecision


class _Summary:
    def to_dict(self):
        return {}


class _RaisingClient:
    enabled = True

    def complete_json(self, **kwargs):
        raise RuntimeError("boom: [SSL: SSLV3_ALERT_BAD_RECORD_MAC] sslv3 alert bad record mac")


class _DisabledClient:
    enabled = False


def _state():
    return MissionState(
        session_id="s1", target=Target(type=TargetType.HOST, value="dvwa"), objective="x"
    )


def test_decider_returns_error_kind_on_llm_exception():
    decider = LlmDecider(_RaisingClient(), ToolCatalog([]))
    action = decider.decide(_state(), _Summary())
    assert action.kind == ActionKind.ERROR


def test_decider_returns_error_kind_when_disabled():
    decider = LlmDecider(_DisabledClient(), ToolCatalog([]))
    action = decider.decide(_state(), _Summary())
    assert action.kind == ActionKind.ERROR


# --- loop maps ERROR -> FAILED ---


class _ErrorDecider:
    def decide(self, state, summary):
        from saber.agents.deciders.base import ProposedAction

        return ProposedAction(kind=ActionKind.ERROR, objective="stop", rationale="LLM error: boom")


class _Summarizer:
    def summarize(self, state):
        return _Summary()


class _Gate:
    def evaluate(self, state, action):
        return GateResult(GateDecision.ALLOW, "ok")


class _Executor:
    def execute(self, state, session, action):
        obs = type("O", (), {"summary": "", "success": True})()
        return ActionExecutionRecord(sandbox_result=None, observation=obs, error=None)


class _ResultProcessor:
    def process_tool_result(self, **kwargs):
        return type("P", (), {"parsed_observations": [], "evidence_ids": [], "finding_ids": []})()


class _Stop:
    def evaluate(self, state, action):
        return StopDecision(should_stop=False, reason="")


class _Store:
    def __init__(self):
        self.snapshots = []

    def snapshot(self, state):
        self.snapshots.append(state)


def test_loop_maps_error_action_to_failed_status():
    loop = MissionLoop(
        decider=_ErrorDecider(), summarizer=_Summarizer(), risk_gate=_Gate(),
        stop_evaluator=_Stop(), executor=_Executor(), merger=StateMerger(),
        state_store=_Store(), result_processor=_ResultProcessor(), max_steps=5,
    )
    session = MissionSession(session_id="s1", mission_name="m")
    result = loop.run(_state(), session)
    assert result.status == MissionRunStatus.FAILED
