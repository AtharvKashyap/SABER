"""The SABER agentic mission loop.

State-first closed loop: summarize -> decide -> gate -> execute -> normalize ->
snapshot -> stop-check, repeated until a stop condition. Replaces plan-first
driving. Reuses StepRunner-adjacent execution via ActionExecutor, plus parsers,
ResultProcessor, and the stores.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from saber.agents.deciders.base import ActionKind
from saber.core.flag_detector import detect_flag
from saber.core.result_processor import ResultProcessor
from saber.core.state_merger import StateMerger
from saber.core.state_summary import StateSummarizer
from saber.models.mission_state import AttemptedAction, MissionState
from saber.models.session import ApprovalRequest, MissionSession
from saber.orchestration.action_executor import ActionExecutionRecord, ActionExecutor
from saber.orchestration.mission_orchestrator import MissionRunStatus
from saber.orchestration.risk_gate import GateDecision, RiskGate
from saber.orchestration.stop_conditions import StopEvaluator
from saber.storage.mission_state_store import MissionStateStore

if TYPE_CHECKING:
    from saber.orchestration.strategies.base import TargetStrategy
    from saber.reporting.finalizer import ReportArtifact, ReportFinalizer

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MissionLoopResult:
    """Result of a mission-loop run."""

    state: MissionState
    session: MissionSession
    status: MissionRunStatus
    reason: str
    artifacts: list[ReportArtifact] = field(default_factory=list)


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
        strategy: TargetStrategy | None = None,
        report_finalizer: ReportFinalizer | None = None,
    ) -> None:
        """Initialize the loop.

        ``strategy`` is optional (default ``None``) for backward compatibility.
        When provided, the loop consults ``strategy.objective_met(state)`` after
        each merge and marks ``state.objective_met`` so the StopEvaluator can
        terminate the run. When ``None``, objective-met behavior is unchanged.

        ``report_finalizer`` is an optional singleton dependency (default
        ``None``). When provided, the loop calls
        ``report_finalizer.finalize_from_state(...)`` on every terminal
        COMPLETED/STOPPED return and surfaces the produced artifacts on the
        result. When ``None``, no report is generated and the result carries no
        artifacts.
        """

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
        self.strategy = strategy
        self.report_finalizer = report_finalizer

    def run(
        self,
        state: MissionState,
        session: MissionSession,
        strategy: TargetStrategy | None = None,
    ) -> MissionLoopResult:
        """Run the closed loop until pause, completion, or a stop condition.

        ``strategy`` is the per-mission strategy threaded from the caller. When
        provided it overrides the constructor ``strategy`` (production builds the
        loop as a target-agnostic singleton, so the per-mission strategy can only
        arrive here). When ``None``, the constructor ``strategy`` is used as a
        back-compat fallback; when both are ``None``, objective-met is a no-op.
        """

        active_strategy = strategy if strategy is not None else self.strategy

        self.state_store.snapshot(state)

        for _ in range(self.max_steps):
            summary = self.summarizer.summarize(state)
            action = self.decider.decide(state, summary)

            if action.kind == ActionKind.ERROR:
                # The decider could not decide (LLM unreachable/misconfigured).
                # Fail the mission rather than reporting an empty COMPLETED run.
                reason = action.rationale or "decision error"
                state = state.model_copy(update={"stop_reason": reason})
                self.state_store.snapshot(state)
                return self._terminal(state, session, MissionRunStatus.FAILED, reason)

            if action.kind in {ActionKind.STOP, ActionKind.REPORT}:
                reason = action.rationale or action.kind.value
                state = state.model_copy(update={"stop_reason": reason})
                self.state_store.snapshot(state)
                return self._terminal(state, session, MissionRunStatus.COMPLETED, reason)

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
                state = self._apply_strategy_objective(state, active_strategy)
                self.state_store.snapshot(state)
                stop = self.stop_evaluator.evaluate(state, action)
                if stop.should_stop:
                    state = state.model_copy(update={"stop_reason": stop.reason})
                    return self._terminal(state, session, MissionRunStatus.STOPPED, stop.reason)
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
            state = self._detect_and_record_flag(state, record, parsed_observations)
            state = self._apply_strategy_objective(state, active_strategy)
            self.state_store.snapshot(state)

            stop = self.stop_evaluator.evaluate(state, action)
            if stop.should_stop:
                state = state.model_copy(update={"stop_reason": stop.reason})
                self.state_store.snapshot(state)
                return self._terminal(state, session, MissionRunStatus.STOPPED, stop.reason)

        state = state.model_copy(update={"stop_reason": "max_steps exhausted"})
        self.state_store.snapshot(state)
        return self._terminal(state, session, MissionRunStatus.STOPPED, "max_steps exhausted")

    def _detect_and_record_flag(
        self,
        state: MissionState,
        record: ActionExecutionRecord,
        parsed_observations: list[dict],
    ) -> MissionState:
        """Record a captured flag on state.metadata['flag'] if one appears.

        A malformed ``state.metadata["flag_regex"]`` (user-supplied) must never
        crash the loop: any exception raised while detecting is caught and the
        state is returned unchanged.
        """

        if state.metadata.get("flag"):
            return state

        texts: list[str] = [record.observation.summary or ""]
        for obs in parsed_observations:
            texts.append(str(obs))
        result = getattr(record, "sandbox_result", None)
        for attr in ("stdout", "output", "reason"):
            value = getattr(result, attr, None)
            if isinstance(value, str):
                texts.append(value)

        extra = state.metadata.get("flag_regex")
        try:
            flag = detect_flag(texts, extra_patterns=[extra] if isinstance(extra, str) else None)
        except Exception:
            logger.exception(
                "Flag detection failed for session %s (likely an invalid "
                "flag_regex); leaving state unchanged.",
                state.session_id,
            )
            return state
        if not flag:
            return state
        return state.model_copy(update={"metadata": {**state.metadata, "flag": flag}})

    def _apply_strategy_objective(
        self, state: MissionState, strategy: TargetStrategy | None
    ) -> MissionState:
        """Mark ``objective_met`` when the active strategy reports success.

        No-op when no strategy is active. Only ever sets ``objective_met`` to
        True, so it never clears a flag set elsewhere; the StopEvaluator then
        terminates the run on the next stop check.
        """

        if strategy is not None and strategy.objective_met(state):
            return state.model_copy(update={"objective_met": True})
        return state

    def _terminal(
        self,
        state: MissionState,
        session: MissionSession,
        status: MissionRunStatus,
        reason: str,
    ) -> MissionLoopResult:
        """Build a terminal COMPLETED/STOPPED result, finalizing reports.

        Every terminal return funnels through here so report finalization
        happens exactly once, on the final state, for both COMPLETED and
        STOPPED outcomes. Non-terminal returns (e.g. PAUSED_FOR_APPROVAL) do
        not use this helper and carry no artifacts.
        """

        artifacts, state = self._finalize(state, session)
        return MissionLoopResult(
            state=state,
            session=session,
            status=status,
            reason=reason,
            artifacts=artifacts,
        )

    def _finalize(
        self, state: MissionState, session: MissionSession
    ) -> tuple[list[ReportArtifact], MissionState]:
        """Emit final report artifacts via the injected finalizer.

        Returns the artifacts alongside the (possibly updated) state. No-op
        returning no artifacts when no ``report_finalizer`` was injected (the
        default), so loops built without one behave exactly as before. The
        finalizer writes under its own ``output_dir`` (namespaced by
        ``session_id``) and best-effort skips any exporter that fails.

        Report finalization must never abort an otherwise-complete mission: a
        completed run that merely fails to *write its report* is still complete.
        A finalizer that raises is caught here, the failure is recorded on the
        returned state's metadata (and logged), and the run returns its terminal
        COMPLETED/STOPPED result with no artifacts rather than raising.
        """

        if self.report_finalizer is None:
            return [], state
        try:
            artifacts = self.report_finalizer.finalize_from_state(
                state, session, self.report_finalizer.output_dir
            )
        except Exception as exc:  # noqa: BLE001 - report failure must not abort the mission
            logger.exception(
                "Report finalization failed for session %s; returning the "
                "completed run without artifacts.",
                state.session_id,
            )
            recorded = state.model_copy(
                update={
                    "metadata": {
                        **state.metadata,
                        "report_finalization_error": f"{type(exc).__name__}: {exc}",
                    }
                }
            )
            return [], recorded
        return artifacts, state
