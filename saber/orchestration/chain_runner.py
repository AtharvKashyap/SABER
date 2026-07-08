"""Chain runner for SABER orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.models.scope import AssessmentPhase
from saber.orchestration.execution_plan import ExecutionPlan, ExecutionStep, ExecutionStepStatus, make_step_id
from saber.orchestration.step_runner import StepRunRecord


@dataclass
class ChainRunner:
    """Process step records and mutate execution plans immutably."""

    max_chain_depth: int = 20
    handoff_counts: dict[str, int] = field(default_factory=dict)

    def process_step_record(self, plan: ExecutionPlan, record: StepRunRecord) -> ExecutionPlan:
        """Process one step record and return updated plan."""

        current_step = plan.get_step(record.step_id)
        plan = self._mark_step_from_record(plan, current_step, record)

        if self.should_pause(record):
            return plan

        if record.handoff_agent:
            return self.add_handoff_step(
                plan=plan,
                from_step=current_step,
                handoff_agent=record.handoff_agent,
                objective=record.agent_result.decision.objective,
                metadata={
                    "source_step_id": record.step_id,
                    "source_agent": record.agent_name,
                    "handoff_message": record.agent_result.decision.message,
                },
            )

        return plan

    def add_handoff_step(
        self,
        plan: ExecutionPlan,
        from_step: ExecutionStep,
        handoff_agent: str,
        objective: str,
        metadata: dict[str, Any] | None = None,
    ) -> ExecutionStep | ExecutionPlan:
        """Add a dynamic handoff step unless an equivalent pending step exists."""

        self._record_handoff(handoff_agent)

        if self.handoff_counts[handoff_agent] > self.max_chain_depth:
            failed = from_step.mark_failed(
                {
                    "reason": "max_chain_depth_exceeded",
                    "handoff_agent": handoff_agent,
                    "handoff_count": self.handoff_counts[handoff_agent],
                }
            )
            return plan.update_step(failed)

        existing = self._find_existing_runnable_or_pending_agent_step(plan, handoff_agent)
        if existing is not None:
            return plan

        step = ExecutionStep(
            step_id=make_step_id(handoff_agent),
            agent_name=handoff_agent,
            objective=objective or f"Continue mission with {handoff_agent}.",
            phase=self._phase_for_agent(handoff_agent),
            target=from_step.target,
            depends_on=[from_step.step_id],
            metadata={"dynamic": True, "handoff": True, **(metadata or {})},
        )

        return plan.add_step(step)

    def should_pause(self, record: StepRunRecord) -> bool:
        """Return whether chain should pause."""

        return record.requires_approval or record.status == ExecutionStepStatus.NEEDS_APPROVAL

    def should_stop(self, plan: ExecutionPlan) -> bool:
        """Return whether chain should stop."""

        return plan.is_complete() or plan.has_blocking_approval() or plan.has_failed_step()

    def _mark_step_from_record(
        self,
        plan: ExecutionPlan,
        step: ExecutionStep,
        record: StepRunRecord,
    ) -> ExecutionPlan:
        """Update step status from record."""

        metadata = {
            "agent_name": record.agent_name,
            "agent_status": record.agent_result.status.value,
            "decision_type": record.agent_result.decision.action_type.value,
            "handoff_agent": record.handoff_agent,
            "requires_approval": record.requires_approval,
            **record.metadata,
        }

        if record.status == ExecutionStepStatus.COMPLETED:
            return plan.update_step(step.mark_completed(metadata))
        if record.status == ExecutionStepStatus.NEEDS_APPROVAL:
            return plan.update_step(step.mark_needs_approval(metadata))
        if record.status == ExecutionStepStatus.HANDOFF:
            return plan.update_step(step.mark_handoff(metadata))
        if record.status == ExecutionStepStatus.STOPPED:
            return plan.update_step(step.mark_stopped(metadata))
        if record.status == ExecutionStepStatus.FAILED:
            return plan.update_step(step.mark_failed(metadata))
        if record.status == ExecutionStepStatus.SKIPPED:
            return plan.update_step(step.mark_skipped(metadata))

        return plan.update_step(step.mark_failed({"reason": f"unsupported_record_status:{record.status.value}"}))

    def _record_handoff(self, handoff_agent: str) -> None:
        """Increment handoff count."""

        self.handoff_counts[handoff_agent] = self.handoff_counts.get(handoff_agent, 0) + 1

    @staticmethod
    def _find_existing_runnable_or_pending_agent_step(plan: ExecutionPlan, agent_name: str) -> ExecutionStep | None:
        """Find existing non-terminal step for same agent."""

        non_terminal = {
            ExecutionStepStatus.PENDING,
            ExecutionStepStatus.RUNNING,
            ExecutionStepStatus.NEEDS_APPROVAL,
        }
        for step in plan.steps:
            if step.agent_name == agent_name and step.status in non_terminal:
                return step
        return None

    @staticmethod
    def _phase_for_agent(agent_name: str) -> AssessmentPhase:
        """Infer phase for dynamic handoff agent."""

        mapping = {
            "planner_agent": AssessmentPhase.RECON,
            "recon_agent": AssessmentPhase.RECON,
            "network_agent": AssessmentPhase.NETWORK,
            "web_agent": AssessmentPhase.RECON,
            "exploit_agent": AssessmentPhase.EXPLOITATION,
            "post_exploit_agent": AssessmentPhase.EXPLOITATION,
            "lateral_movement_agent": AssessmentPhase.LATERAL_MOVEMENT,
            "reverse_engineer_agent": AssessmentPhase.RECON,
            "tool_selection_agent": AssessmentPhase.RECON,
            "reporter_agent": AssessmentPhase.REPORTING,
            "chain_agent": AssessmentPhase.EXPLOITATION,
        }
        return mapping.get(agent_name, AssessmentPhase.RECON)
