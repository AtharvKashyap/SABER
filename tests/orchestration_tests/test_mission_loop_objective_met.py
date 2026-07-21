"""The mission loop consults an injected strategy for objective-met.

When a ``strategy`` is injected, the loop calls ``strategy.objective_met`` after
each merge and sets ``state.objective_met`` so the StopEvaluator can terminate
the run -- independent of whatever the decider proposes.
"""

from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.core.result_processor import ProcessedToolResult
from saber.core.state_merger import StateMerger
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import AutonomyLevel, MissionState
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.orchestration.risk_gate import RiskGate
from saber.orchestration.stop_conditions import StopEvaluator


class _AlwaysToolDecider:
    """Always proposes the same low-risk recon action; never STOP/REPORT.

    This isolates termination to the strategy: if the loop stops, it is because
    the injected strategy reported the objective met, not the decider.
    """

    def __init__(self):
        self.calls = 0

    def decide(self, state, summary):
        self.calls += 1
        return ProposedAction(
            kind=ActionKind.TOOL,
            tool_name="nmap",
            tool_action="service_scan",
            args={"target": "10.0.0.5"},
            agent_name="recon_agent",
            objective="scan",
            risk=RiskLevel.LOW,
            metadata={"category": "recon"},
        )


class _FakeExecutor:
    def execute(self, state, session, action):
        from saber.agents.base_agent import AgentObservation

        obs = AgentObservation(
            summary="ok", tool_name=action.tool_name, action=action.tool_action, success=True
        )
        return ActionExecutionRecord(sandbox_result=object(), observation=obs, error=None)


class _FakeProcessor:
    def process_tool_result(self, **kwargs):
        return ProcessedToolResult(
            session_id=kwargs["session_id"],
            step_id=None,
            tool_name="nmap",
            parsed_observations=[],
            evidence_ids=[],
            finding_ids=[],
        )


class _FakeStore:
    def snapshot(self, state):
        pass


class _FlipStrategy:
    """objective_met stays False on the first merge, then flips to True."""

    def __init__(self):
        self.calls = 0

    def objective_met(self, state):
        self.calls += 1
        return self.calls >= 2


def _loop(decider, strategy):
    return MissionLoop(
        decider=decider,
        summarizer=StateSummarizer(),
        risk_gate=RiskGate(),
        stop_evaluator=StopEvaluator(max_steps=10),
        executor=_FakeExecutor(),
        merger=StateMerger(),
        state_store=_FakeStore(),
        result_processor=_FakeProcessor(),
        strategy=strategy,
        max_steps=10,
    )


def _fixtures():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=AutonomyLevel.AUTONOMOUS,
        objective="capture the flag",
    )
    session = MissionSession(session_id="s", mission_name="m")
    return state, session


def test_loop_terminates_when_strategy_reports_objective_met():
    strategy = _FlipStrategy()
    decider = _AlwaysToolDecider()
    state, session = _fixtures()

    result = _loop(decider, strategy).run(state, session)

    # The decider never REPORTs and there are no failures, so the ONLY way to
    # stop before max_steps is the strategy flipping objective_met to True.
    assert result.status == MissionRunStatus.STOPPED
    assert result.reason == "objective met"
    assert result.state.objective_met is True
    # Proves the flip drove termination: two merges (False then True).
    assert strategy.calls == 2
    assert decider.calls == 2
