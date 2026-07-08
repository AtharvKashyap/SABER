"""Step runner for SABER orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from saber.agents.base_agent import AgentContext, AgentObservation, AgentRunResult, AgentRunStatus, BaseAgent
from saber.core.sandbox import Sandbox
from saber.models.session import MissionSession
from saber.models.target import Target
from saber.orchestration.execution_plan import ExecutionStep, ExecutionStepStatus
from saber.tools.registry import ToolRegistry


@dataclass(frozen=True)
class StepRunRecord:
    """Record produced by running one execution step."""

    step_id: str
    agent_name: str
    status: ExecutionStepStatus
    agent_result: AgentRunResult
    new_observations: list[AgentObservation] = field(default_factory=list)
    handoff_agent: str | None = None
    requires_approval: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible record."""

        return {
            "step_id": self.step_id,
            "agent_name": self.agent_name,
            "status": self.status.value,
            "agent_result": self.agent_result.to_dict(),
            "new_observations": [
                {
                    "summary": observation.summary,
                    "tool_name": observation.tool_name,
                    "action": observation.action,
                    "success": observation.success,
                    "metadata": observation.metadata,
                }
                for observation in self.new_observations
            ],
            "handoff_agent": self.handoff_agent,
            "requires_approval": self.requires_approval,
            "metadata": self.metadata,
        }


class StepRunner:
    """Run exactly one execution step."""

    def __init__(
        self,
        agents: dict[str, BaseAgent],
        tool_registry: ToolRegistry,
        sandbox: Sandbox,
    ) -> None:
        """Initialize step runner."""

        if not agents:
            raise ValueError("StepRunner requires at least one agent.")

        self.agents = agents
        self.tool_registry = tool_registry
        self.sandbox = sandbox

    def run_step(
        self,
        step: ExecutionStep,
        session: MissionSession,
        target: Target,
        observations: list[AgentObservation],
        constraints: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StepRunRecord:
        """Run one execution step once."""

        agent = self._get_agent(step.agent_name)
        step_target = step.target or target

        context = AgentContext(
            session=session,
            target=step_target,
            sandbox=self.sandbox,
            tool_registry=self.tool_registry,
            objective=step.objective,
            phase=agent.config.phase,
            observations=observations,
            constraints=constraints or {},
            metadata={
                "step_id": step.step_id,
                "step_metadata": step.metadata,
                **(metadata or {}),
            },
        )

        try:
            agent_result = agent.run(context)
        except Exception as exc:
            failed_decision = self._failure_result(agent=agent, step=step, exc=exc)
            return StepRunRecord(
                step_id=step.step_id,
                agent_name=step.agent_name,
                status=ExecutionStepStatus.FAILED,
                agent_result=failed_decision,
                new_observations=[],
                metadata={"error": str(exc), "error_type": type(exc).__name__},
            )

        return StepRunRecord(
            step_id=step.step_id,
            agent_name=step.agent_name,
            status=self._map_status(agent_result.status),
            agent_result=agent_result,
            new_observations=agent_result.observations,
            handoff_agent=agent_result.decision.handoff_agent,
            requires_approval=agent_result.status == AgentRunStatus.NEEDS_APPROVAL,
            metadata={
                "agent_status": agent_result.status.value,
                "decision_type": agent_result.decision.action_type.value,
                "agent_metadata": agent_result.metadata,
            },
        )

    def _get_agent(self, agent_name: str) -> BaseAgent:
        """Return agent by name."""

        try:
            return self.agents[agent_name]
        except KeyError as exc:
            raise KeyError(f"Agent not registered: {agent_name}") from exc

    @staticmethod
    def _map_status(status: AgentRunStatus) -> ExecutionStepStatus:
        """Map agent run status to execution step status."""

        mapping = {
            AgentRunStatus.COMPLETED: ExecutionStepStatus.COMPLETED,
            AgentRunStatus.NEEDS_APPROVAL: ExecutionStepStatus.NEEDS_APPROVAL,
            AgentRunStatus.HANDOFF: ExecutionStepStatus.HANDOFF,
            AgentRunStatus.STOPPED: ExecutionStepStatus.STOPPED,
            AgentRunStatus.FAILED: ExecutionStepStatus.FAILED,
        }
        return mapping[status]

    @staticmethod
    def _failure_result(agent: BaseAgent, step: ExecutionStep, exc: Exception) -> AgentRunResult:
        """Create AgentRunResult for runner exceptions."""

        from saber.agents.base_agent import AgentActionType, AgentDecision

        decision = AgentDecision(
            action_type=AgentActionType.STOP,
            objective=step.objective,
            message=f"Step failed before completion: {exc}",
            metadata={"error": str(exc), "error_type": type(exc).__name__},
        )

        return AgentRunResult(
            agent_name=agent.config.name,
            status=AgentRunStatus.FAILED,
            decision=decision,
            observations=[],
            metadata={"step_id": step.step_id, "error": str(exc), "error_type": type(exc).__name__},
        )
