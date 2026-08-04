from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
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


class _ScriptedDecider:
    """Emits a low-risk tool action once, then reports."""

    def __init__(self):
        self.calls = 0

    def decide(self, state, summary):
        self.calls += 1
        if self.calls == 1:
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
        return ProposedAction(kind=ActionKind.REPORT, objective="done", risk=RiskLevel.LOW)


class _FakeExecutor:
    def execute(self, state, session, action):
        from saber.agents.base_agent import AgentObservation

        obs = AgentObservation(
            summary="ok", tool_name=action.tool_name, action=action.tool_action, success=True
        )
        return ActionExecutionRecord(sandbox_result=object(), observation=obs, error=None)


class _FakeProcessor:
    def process_tool_result(self, **kwargs):
        from saber.core.result_processor import ProcessedToolResult

        return ProcessedToolResult(
            session_id=kwargs["session_id"],
            step_id=None,
            tool_name="nmap",
            parsed_observations=[
                {"kind": "service", "data": {"host": "10.0.0.5", "port": 80, "service": "http"}}
            ],
            evidence_ids=["ev1"],
            finding_ids=["f1"],
        )


class _FakeStore:
    def __init__(self):
        self.snapshots = 0

    def snapshot(self, state):
        self.snapshots += 1


def _loop(decider):
    return MissionLoop(
        decider=decider,
        summarizer=StateSummarizer(),
        risk_gate=RiskGate(),
        stop_evaluator=StopEvaluator(max_steps=10),
        executor=_FakeExecutor(),
        merger=StateMerger(),
        state_store=_FakeStore(),
        result_processor=_FakeProcessor(),
        max_steps=10,
    )


def _fixtures():
    state = MissionState(
        session_id="s",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=AutonomyLevel.AUTONOMOUS,
        objective="assess",
    )
    session = MissionSession(session_id="s", mission_name="m")
    return state, session


def test_loop_runs_then_reports_and_completes():
    state, session = _fixtures()
    result = _loop(_ScriptedDecider()).run(state, session)
    assert result.status == MissionRunStatus.COMPLETED
    assert any(s.key == "10.0.0.5:80/tcp" for s in result.state.services)  # merged
    assert result.state.step_count >= 1


def test_loop_pauses_on_high_risk_confirmation():
    class _HighRisk:
        def decide(self, state, summary):
            return ProposedAction(
                kind=ActionKind.TOOL,
                tool_name="metasploit",
                tool_action="run_exploit",
                objective="pop",
                risk=RiskLevel.HIGH,
                agent_name="exploit_agent",
                metadata={"category": "exploitation"},
            )

    state, session = _fixtures()
    result = _loop(_HighRisk()).run(state, session)
    assert result.status == MissionRunStatus.PAUSED_FOR_APPROVAL


def test_loop_snapshots_state_each_iteration():
    state, session = _fixtures()
    loop = _loop(_ScriptedDecider())
    loop.run(state, session)
    assert loop.state_store.snapshots >= 1
