"""The loop must actually advance the PTES phase, not just own a checker.

PhaseGoalChecker has thorough unit tests, but its INTEGRATION had zero coverage:
`MissionLoop._advance_phase` could be replaced with `lambda self, state: state` and
all 1879 tests still passed. Since `_advance_phase` swallows exceptions by design
(phase bookkeeping must not kill a mission), any regression inside it degrades
silently to "mission permanently stuck in RECON" — with reports that narrate a
recon-only engagement — while the suite stays green.
"""

from saber.agents.base_agent import AgentObservation
from saber.agents.deciders.base import ActionKind, ProposedAction, RiskLevel
from saber.core.state_merger import StateMerger
from saber.models.mission_state import MissionState, PtesPhase
from saber.models.session import MissionSession
from saber.models.target import Target, TargetType
from saber.orchestration.action_executor import ActionExecutionRecord
from saber.orchestration.mission_loop import MissionLoop
from saber.orchestration.risk_gate import GateDecision, GateResult
from saber.orchestration.stop_conditions import StopDecision


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
                tool_name="nmap",
                tool_action="service_scan",
                args={},
                objective="scan",
                risk=RiskLevel.LOW,
            )
        return ProposedAction(kind=ActionKind.STOP, objective="done", rationale="done")


class _Gate:
    def evaluate(self, state, action):
        return GateResult(GateDecision.ALLOW, "ok")


class _Executor:
    def execute(self, state, session, action):
        return ActionExecutionRecord(
            sandbox_result=object(),
            observation=AgentObservation(
                summary="scan complete",
                tool_name=action.tool_name,
                action=action.tool_action,
                success=True,
            ),
            error=None,
        )


class _ResultProcessor:
    """Yields a host and a service — exactly the recon phase goal."""

    def process_tool_result(self, **kwargs):
        return type(
            "P",
            (),
            {
                "parsed_observations": [
                    {"kind": "host", "data": {"address": "10.0.0.5"}},
                    {"kind": "service", "data": {"host": "10.0.0.5", "port": 80}},
                ],
                "evidence_ids": [],
                "finding_ids": [],
            },
        )()


class _EmptyResultProcessor:
    def process_tool_result(self, **kwargs):
        return type(
            "P", (), {"parsed_observations": [], "evidence_ids": [], "finding_ids": []}
        )()


class _Stop:
    def evaluate(self, state, action):
        return StopDecision(False, "continue")


class _Store:
    def __init__(self):
        self.snapshots = []

    def snapshot(self, state):
        self.snapshots.append(state)


def _state():
    return MissionState(
        session_id="s1",
        target=Target(type=TargetType.IP, value="10.0.0.5"),
        objective="assess",
    )


def _loop(store, result_processor):
    return MissionLoop(
        decider=_Decider(),
        summarizer=_Summarizer(),
        risk_gate=_Gate(),
        stop_evaluator=_Stop(),
        executor=_Executor(),
        merger=StateMerger(),
        state_store=store,
        result_processor=result_processor,
        max_steps=3,
    )


def test_loop_advances_the_phase_when_the_goal_is_evidenced():
    store = _Store()
    loop = _loop(store, _ResultProcessor())

    loop.run(_state(), MissionSession(session_id="s1", mission_name="m"))
    final = store.snapshots[-1]

    assert final.current_phase is PtesPhase.VULN_ASSESSMENT, (
        "recon produced a host and a service, so the loop must leave RECON"
    )


def test_loop_records_exactly_one_transition_note():
    store = _Store()
    loop = _loop(store, _ResultProcessor())

    loop.run(_state(), MissionSession(session_id="s1", mission_name="m"))
    final = store.snapshots[-1]

    transitions = [n for n in final.notes if n.title.startswith("Phase complete:")]
    assert len(transitions) == 1
    note = transitions[0]
    assert note.title == "Phase complete: recon -> vuln_assessment"
    assert note.metadata["from_phase"] == "recon"
    assert note.metadata["to_phase"] == "vuln_assessment"
    # The evidence, not just "done" — this is what the report narrates.
    assert "host(s)" in note.detail


def test_loop_does_not_advance_without_evidence():
    """A mission that learns nothing must stay in RECON rather than drift forward."""

    store = _Store()
    loop = _loop(store, _EmptyResultProcessor())

    loop.run(_state(), MissionSession(session_id="s1", mission_name="m"))
    final = store.snapshots[-1]

    assert final.current_phase is PtesPhase.RECON
    assert not [n for n in final.notes if n.title.startswith("Phase complete:")]


def test_phase_advance_is_actually_wired_into_the_loop():
    """Guards the mutation that used to pass: stubbing _advance_phase to a no-op.

    Asserted structurally as well as behaviourally, so deleting the call site fails
    here rather than silently degrading every future mission to recon-only.
    """

    import inspect

    source = inspect.getsource(MissionLoop.run)
    assert "_advance_phase" in source, "_advance_phase is no longer called by run()"
