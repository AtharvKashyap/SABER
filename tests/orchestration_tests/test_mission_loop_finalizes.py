"""The mission loop finalizes reports on terminal COMPLETED/STOPPED returns.

When a ``report_finalizer`` is injected, a completed (or stopped) loop calls
``finalize_from_state`` and surfaces the produced artifacts on the result. With
no finalizer injected (the default), the loop behaves exactly as before and the
result carries no artifacts.
"""

from __future__ import annotations

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
from saber.reporting.finalizer import ReportFinalizer


class _ScriptedDecider:
    """Emits a low-risk tool action once, then reports (COMPLETED)."""

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


class _RaisingFinalizer:
    """A finalizer whose report generation always fails."""

    def __init__(self, output_dir):
        self.output_dir = output_dir

    def finalize_from_state(self, state, session, reports_dir):
        raise RuntimeError("boom: report generation failed")


def _loop(report_finalizer=None):
    return MissionLoop(
        decider=_ScriptedDecider(),
        summarizer=StateSummarizer(),
        risk_gate=RiskGate(),
        stop_evaluator=StopEvaluator(max_steps=10),
        executor=_FakeExecutor(),
        merger=StateMerger(),
        state_store=_FakeStore(),
        result_processor=_FakeProcessor(),
        max_steps=10,
        report_finalizer=report_finalizer,
    )


def _fixtures():
    state = MissionState(
        session_id="loopfin",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        autonomy_level=AutonomyLevel.AUTONOMOUS,
        objective="assess",
    )
    session = MissionSession(session_id="loopfin", mission_name="m")
    return state, session


def test_completed_loop_finalizes_and_surfaces_artifacts(tmp_path):
    finalizer = ReportFinalizer(
        finding_store=None,
        output_dir=tmp_path,
        export_pdf=False,
        export_markdown=False,
    )
    state, session = _fixtures()

    result = _loop(report_finalizer=finalizer).run(state, session)

    assert result.status == MissionRunStatus.COMPLETED
    assert result.artifacts, "completed loop should surface report artifacts"
    report_types = {artifact.report_type for artifact in result.artifacts}
    assert "json" in report_types
    assert (tmp_path / "loopfin" / "findings.json").exists()


def test_loop_without_finalizer_has_no_artifacts():
    state, session = _fixtures()

    result = _loop(report_finalizer=None).run(state, session)

    assert result.status == MissionRunStatus.COMPLETED
    assert result.artifacts == []


def test_finalizer_error_does_not_abort_completed_run(tmp_path):
    """A finalizer that raises must not fail an otherwise-complete mission."""

    state, session = _fixtures()

    result = _loop(report_finalizer=_RaisingFinalizer(tmp_path)).run(state, session)

    # The run still reaches a terminal COMPLETED outcome...
    assert result.status == MissionRunStatus.COMPLETED
    # ...but produces no artifacts, and the failure is recorded, not raised.
    assert result.artifacts == []
    assert "report_finalization_error" in result.state.metadata
