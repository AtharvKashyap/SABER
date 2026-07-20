"""The SABER agentic mission loop.

State-first closed loop: summarize -> decide -> gate -> execute -> normalize ->
snapshot -> stop-check, repeated until a stop condition. Replaces plan-first
driving. Reuses StepRunner-adjacent execution via ActionExecutor, plus parsers,
ResultProcessor, and the stores.
"""

from __future__ import annotations

from dataclasses import dataclass

from saber.agents.deciders.base import ActionKind
from saber.core.result_processor import ResultProcessor
from saber.core.state_merger import StateMerger
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.session import ApprovalRequest, MissionSession
from saber.orchestration.action_executor import ActionExecutor
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.orchestration.risk_gate import GateDecision, RiskGate
from saber.orchestration.stop_conditions import StopEvaluator
from saber.storage.mission_state_store import MissionStateStore


@dataclass(frozen=True)
class MissionLoopResult:
    """Result of a mission-loop run."""

    state: MissionState
    session: MissionSession
    status: MissionRunStatus
    reason: str


class MissionLoop:
    """Drive a mission from MissionState until a stop condition."""

    def __init__(
        self,
        decider,
        summarizer: StateSummarizer,
        risk_gate: RiskGate,
        stop_evaluator: StopEvaluator,
        executor: ActionExecutor,
        merger: StateMerger,
        state_store: MissionStateStore,
        result_processor: ResultProcessor,
        session_store=None,
        max_steps: int = 50,
    ) -> None:
        """Initialize the loop."""

        self.decider = decider
        self.summarizer = summarizer
        self.risk_gate = risk_gate
        self.stop_evaluator = stop_evaluator
        self.executor = executor
        self.merger = merger
        self.state_store = state_store
        self.result_processor = result_processor
        self.session_store = session_store
        self.max_steps = max_steps

    def run(self, state: MissionState, session: MissionSession) -> MissionLoopResult:
        """Run the closed loop until pause, completion, or a stop condition."""

        self.state_store.snapshot(state)

        for _ in range(self.max_steps):
            summary = self.summarizer.summarize(state)
            action = self.decider.decide(state, summary)

            if action.kind in {ActionKind.STOP, ActionKind.REPORT}:
                reason = action.rationale or action.kind.value
                state = state.model_copy(update={"stop_reason": reason})
                self.state_store.snapshot(state)
                return MissionLoopResult(state, session, MissionRunStatus.COMPLETED, reason)

            gate = self.risk_gate.evaluate(state, action)

            if gate.decision == GateDecision.REFUSE:
                state = self.merger.merge(
                    state,
                    [],
                    AttemptedAction(
                        tool_name=action.tool_name or "?",
                        action=action.tool_action or "?",
                        args=action.args,
                        success=False,
                        reason=f"refused: {gate.reason}",
                    ),
                )
                self.state_store.snapshot(state)
                stop = self.stop_evaluator.evaluate(state, action)
                if stop.should_stop:
                    state = state.model_copy(update={"stop_reason": stop.reason})
                    return MissionLoopResult(state, session, MissionRunStatus.STOPPED, stop.reason)
                continue

            if gate.decision == GateDecision.CONFIRM:
                approval = ApprovalRequest(
                    action=f"{action.tool_name}.{action.tool_action}",
                    reason=gate.reason,
                    requested_by="mission_loop",
                    target=action.target or state.target,
                    metadata={"proposed_action": action.to_dict()},
                )
                session = session.wait_for_approval(approval)
                if self.session_store is not None:
                    self.session_store.update_session_status(
                        session.session_id, "waiting_for_approval"
                    )
                state = state.model_copy(
                    update={"stop_reason": f"awaiting confirmation: {gate.reason}"}
                )
                self.state_store.snapshot(state)
                return MissionLoopResult(
                    state, session, MissionRunStatus.PAUSED_FOR_APPROVAL, gate.reason
                )

            # ALLOW: execute the action.
            record = self.executor.execute(state, session, action)
            attempt = AttemptedAction(
                tool_name=action.tool_name or "?",
                action=action.tool_action or "?",
                args=action.args,
                success=record.observation.success,
                reason=("" if record.error is None else record.error),
            )

            parsed_observations: list[dict] = []
            evidence_refs: list[str] = []
            finding_refs: list[str] = []
            if record.error is None and record.sandbox_result is not None:
                processed = self.result_processor.process_tool_result(
                    session_id=state.session_id,
                    tool_result=record.sandbox_result,
                    tool_name=action.tool_name,
                    action=action.tool_action,
                )
                parsed_observations = list(getattr(processed, "parsed_observations", []) or [])
                evidence_refs = list(getattr(processed, "evidence_ids", []) or [])
                finding_refs = list(getattr(processed, "finding_ids", []) or [])

            state = self.merger.merge(
                state,
                parsed_observations,
                attempt,
                evidence_refs=evidence_refs,
                finding_refs=finding_refs,
            )
            self.state_store.snapshot(state)

            stop = self.stop_evaluator.evaluate(state, action)
            if stop.should_stop:
                state = state.model_copy(update={"stop_reason": stop.reason})
                self.state_store.snapshot(state)
                return MissionLoopResult(state, session, MissionRunStatus.STOPPED, stop.reason)

        state = state.model_copy(update={"stop_reason": "max_steps exhausted"})
        self.state_store.snapshot(state)
        return MissionLoopResult(state, session, MissionRunStatus.STOPPED, "max_steps exhausted")
